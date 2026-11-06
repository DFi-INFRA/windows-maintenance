"""Construction du paquet de maintenance (script + outils figés), utilisé par la CI et en local.

    python build/build.py update                 # cherche la dernière version officielle de chaque outil,
                                                 # met à jour tools.json (url, version, sha256)
    python build/build.py package --version v3.3.2
                                                 # télécharge les outils de tools.json, vérifie leur empreinte,
                                                 # produit dist/mre-bundle.zip et dist/release-notes.md

Le paquet contient le script de maintenance et tools/ (scripts, modules, manifest.json). Le zip est
reproductible : mêmes entrées, même empreinte. Bibliothèque standard uniquement (Python 3.11+).
"""

import argparse
import hashlib
import io
import json
import os
import re
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "tools.json"
SCRIPT = ROOT / "Invoke-Maintenance.ps1"
DIST = ROOT / "dist"
FIXED_TIME = (2026, 1, 1, 0, 0, 0)
USER_AGENT = "dfi-maintenance-build"


def fetch(url, accept=None):
    """Retourne (contenu, url finale après redirections)."""
    headers = {"User-Agent": USER_AGENT}
    if accept:
        headers["Accept"] = accept
    token = os.environ.get("GITHUB_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        headers["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=120) as r:
        return r.read(), r.geturl()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


# ------------------------------------------------------------------ mise à jour des sources

def latest(entry):
    """Dernière version officielle d'un outil : (version, url figée, fichier, contenu)."""
    src = entry["source"]
    kind = src["type"]
    if kind == "github-release":
        rel = json.loads(fetch(f"https://api.github.com/repos/{src['repo']}/releases/latest",
                               "application/vnd.github+json")[0])
        assets = [a for a in rel["assets"] if re.search(src["asset"], a["name"])]
        if len(assets) != 1:
            raise SystemExit(f"{src['repo']} {rel['tag_name']} : {len(assets)} fichier(s) pour {src['asset']}")
        url = assets[0]["browser_download_url"]
        return rel["tag_name"], url, assets[0]["name"], fetch(url)[0]
    if kind == "psgallery":
        data, final = fetch(f"https://www.powershellgallery.com/api/v2/package/{src['package']}")
        m = re.search(r"\.(\d+(?:\.\d+)+)\.nupkg$", final, re.I)
        if not m:
            raise SystemExit(f"{src['package']} : version introuvable dans {final}")
        version = m.group(1)
        return (version, f"https://www.powershellgallery.com/api/v2/package/{src['package']}/{version}",
                f"{src['package']}.{version}.zip", data)
    if kind == "url":
        data = fetch(src["url"])[0]
        m = re.search(src["versionPattern"], data.decode("utf-8", "replace"), re.M)
        version = m.group(1) if m else "inconnue"
        return version, src["url"], entry["file"], data
    raise SystemExit(f"type de source inconnu : {kind}")


def update():
    sources = json.loads(SOURCES.read_text(encoding="utf-8"))
    entries = list(sources["scripts"].items()) + [(m["name"], m) for m in sources["modules"]]
    changes = []
    for name, entry in entries:
        version, url, file, data = latest(entry)
        digest = sha256(data)
        if digest != entry["sha256"]:
            changes.append(f"{name} : {entry['version']} -> {version}")
        entry.update(version=version, url=url, file=file, sha256=digest)
    SOURCES.write_text(json.dumps(sources, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("\n".join(changes) if changes else "outils déjà à jour")


# ------------------------------------------------------------------ paquet

def package(version, repo=None):
    sources = json.loads(SOURCES.read_text(encoding="utf-8"))
    files = {}
    manifest = {"bundleVersion": version, "scriptSha256": sha256(SCRIPT.read_bytes()), "scripts": {}, "modules": []}
    for name, entry in sources["scripts"].items():
        rel = f"scripts/{entry['file']}"
        files[rel] = download_checked(name, entry)
        manifest["scripts"][name] = {"path": rel, "version": entry["version"], "url": entry["url"], "sha256": entry["sha256"]}
    for entry in sources["modules"]:
        rel = f"modules/{entry['file']}"
        files[rel] = download_checked(entry["name"], entry)
        manifest["modules"].append({"name": entry["name"], "path": rel, "moduleRoot": entry["moduleRoot"],
                                    "version": entry["version"], "url": entry["url"], "sha256": entry["sha256"]})

    content = [(SCRIPT.name, SCRIPT.read_bytes())]
    content += [(f"tools/{rel}", data) for rel, data in sorted(files.items())]
    content.append(("tools/manifest.json", (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode()))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in content:
            info = zipfile.ZipInfo(name, FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, data)
    DIST.mkdir(exist_ok=True)
    bundle = DIST / "mre-bundle.zip"
    bundle.write_bytes(buf.getvalue())
    digest = sha256(buf.getvalue()).upper()

    lines = [f"Paquet de maintenance {version}", "",
             "À reporter dans le script NinjaOne MRE - Collecte :", "",
             "```", f"$BundleVersion = '{version}'", f"$BundleHash    = '{digest}'", "```", "",
             f"Paquet : {bundle_url(version, repo)}", "",
             "| Outil | Version | Source |", "|---|---|---|"]
    lines += [f"| {n} | {e['version']} | {e['url']} |" for n, e in sources["scripts"].items()]
    lines += [f"| {e['name']} | {e['version']} | {e['url']} |" for e in sources["modules"]]
    (DIST / "release-notes.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"paquet : {bundle} ({bundle.stat().st_size // 1024} Ko)")
    print(f"BundleHash : {digest}")


def bundle_url(version, repo):
    if not repo:
        return "<url de mre-bundle.zip dans cette release>"
    return f"https://github.com/{repo}/releases/download/{version}/mre-bundle.zip"


def download_checked(name, entry):
    data = fetch(entry["url"])[0]
    digest = sha256(data)
    if digest != entry["sha256"]:
        raise SystemExit(f"{name} : empreinte {digest} différente de tools.json ({entry['sha256']}). "
                         "Fichier modifié à la source : lancer 'update' et relire le changement.")
    return data


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("update")
    pk = sub.add_parser("package")
    pk.add_argument("--version", required=True)
    pk.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY"), help="organisation/dépôt GitHub")
    a = p.parse_args()
    update() if a.cmd == "update" else package(a.version, a.repo)


if __name__ == "__main__":
    sys.exit(main())
