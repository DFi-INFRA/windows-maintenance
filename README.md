# Script de maintenance Windows Server

Script PowerShell de contrôle mensuel des serveurs Windows (système, Windows Update, journaux d'événements,
Active Directory, Exchange, Veeam, RDS, impression...). Il produit un rapport HTML local et un JSON
(schéma `dfi-mre/1`) exploité pour générer le rapport de maintenance.

Le dépôt ne contient aucune donnée client : tout est collecté à l'exécution sur le serveur.

## Contenu

| Fichier | Rôle |
|---|---|
| `Invoke-Maintenance.ps1` | Script de maintenance (Windows PowerShell 5.1, droits administrateur) ; sa version est dans le JSON (`scriptVersion`) et le manifeste du paquet |
| `MRE-Collecte.ps1` | Lanceur NinjaOne : installe le paquet de la release si besoin, vérifie, exécute |
| `tools.json` | Outils externes : source officielle, version et empreinte SHA-256 figées |
| `build/build.py` | Mise à jour des outils et construction du paquet (utilisé par la CI) |
| `.github/workflows/package.yml` | CI manuelle : produit une release contenant `mre-bundle.zip` |

## Paquet

`mre-bundle.zip` contient le script et le dossier `tools` (scripts, modules, `manifest.json`). Les serveurs
le téléchargent en une seule fois depuis la release ; le script ne télécharge rien à l'exécution et refuse
tout outil dont l'empreinte diffère du manifeste.

| Outil | Source officielle |
|---|---|
| HealthChecker | [microsoft/CSS-Exchange](https://github.com/microsoft/CSS-Exchange) |
| Get-ADHealth | [alitajran.com](https://www.alitajran.com/active-directory-health-check-powershell-script/) |
| GPOZaurr, CleanupMonster | [EvotecIT](https://github.com/EvotecIT) |
| PSEventViewer | [PowerShell Gallery](https://www.powershellgallery.com/packages/PSEventViewer) |

Les versions figées sont dans `tools.json` et dans les notes de chaque release.

## Produire une nouvelle version

1. Actions > « Paquet de maintenance » > Run workflow : indiquer la version (ex. `v3.3.2`) et cocher
   « Mettre à jour les outils » pour passer chaque outil à sa dernière version officielle (le `tools.json`
   modifié est commité par la CI).
2. La CI vérifie la syntaxe PowerShell, télécharge les outils, contrôle leurs empreintes et publie la release
   avec `mre-bundle.zip`. Les notes de release donnent `$BundleVersion` et `$BundleHash`.
3. Tester le paquet sur un serveur (exécution manuelle du contenu du zip), surtout après une mise à jour d'outils.
4. Reporter `$BundleVersion` et `$BundleHash` dans le script NinjaOne : chaque serveur installe le nouveau paquet
   à sa prochaine exécution.

Publier une release ne déploie rien : tant que `$BundleHash` n'est pas modifié dans NinjaOne, les serveurs
gardent le paquet précédent.

En local : `python build/build.py package --version v3.3.2` (et `update` pour les outils).

## Exécution

Sous NinjaOne : contenu de `MRE-Collecte.ps1`, exécuté en System. Les serveurs doivent pouvoir joindre `github.com`
et `objects.githubusercontent.com` (le proxy WinHTTP de la machine est utilisé s'il est défini).

Manuellement : extraire `mre-bundle.zip` dans `C:\DFI-Maintenance`, puis

```powershell
.\Invoke-Maintenance.ps1 -ToolsPath C:\DFI-Maintenance\tools
```

Rapports dans `C:\DFI-Maintenance` ; les 10 plus récents de chaque type sont conservés.
`-NinjaField <champ>` écrit le JSON compressé (gzip + base64) dans un custom field NinjaOne.
