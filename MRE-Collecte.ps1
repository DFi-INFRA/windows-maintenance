# MRE - Collecte mensuelle (script NinjaOne, a executer en tant que System)
#
# 1. Si le paquet installe dans $Root n'est pas celui attendu, telecharge mre-bundle.zip depuis $BundleUrl
#    (release GitHub), verifie son SHA-256, puis remplace le script de maintenance et le dossier tools.
# 2. Verifie le script par l'empreinte inscrite dans tools\manifest.json, puis le lance : il ecrit son JSON
#    dans le custom field NinjaOne. Aucun autre telechargement n'a lieu.
#
# Mise a jour : lancer la CI "Paquet de maintenance", puis reporter $BundleVersion et $BundleHash donnes dans
# les notes de la release. Tant qu'ils ne sont pas modifies ici, une nouvelle release n'est jamais utilisee.
# L'empreinte reste obligatoire : elle garantit que le paquet installe est bien celui qui a ete teste.
# $BundleVersion vide = deploiement manuel (contenu du zip copie dans $Root).
# Texte volontairement en ASCII : l'encodage du script cote NinjaOne n'est pas garanti.

$Root          = 'C:\DFI-Maintenance'
$ScriptName    = 'Invoke-Maintenance.ps1'
$Repo          = 'DFi-INFRA/windows-maintenance'
$BundleVersion = ''   # ex. v3.3.1
$BundleHash    = ''   # empreinte donnee dans les notes de la release
$Field         = 'mreReport'
$MaxChars      = 10000

$BundleUrl = if ($BundleVersion) { "https://github.com/$Repo/releases/download/$BundleVersion/mre-bundle.zip" } else { '' }

function Set-Field([string]$Value) {
    if (Get-Command Ninja-Property-Set -ErrorAction SilentlyContinue) {
        Ninja-Property-Set -Name $Field -Value $Value | Out-Null
    } else {
        $cli = Join-Path $env:ProgramData 'NinjaRMMAgent\ninjarmm-cli.exe'
        if (Test-Path $cli) { & $cli set $Field $Value | Out-Null }
    }
}

function Stop-WithError([string]$Message) {
    Write-Output "ERREUR : $Message"
    Set-Field ("error:" + $Message + " (" + $env:COMPUTERNAME + ", " + (Get-Date).ToUniversalTime().ToString('o') + ")")
    exit 1
}

function Get-Sha256([string]$Path) { (Get-FileHash -Path $Path -Algorithm SHA256).Hash }

# Proxy WinHTTP (netsh, EN/FR) : sous System, le telechargement ne l'utilise pas forcement de lui-meme
function Get-WinHttpProxyUri {
    $out = (& netsh winhttp show proxy) -join "`n"
    if ($out -notmatch '(?im)^\s*(?:Proxy Server\(s\)|Serveur\(s\) proxy)\s*:\s*(\S.*)$') { return $null }
    $server = $matches[1].Trim()
    if ($server -match '(?i)(?:^|;)https=([^;\s]+)') { $server = $matches[1] }
    elseif ($server -match '(?i)(?:^|;)http=([^;\s]+)') { $server = $matches[1] }
    if ($server -notmatch '^[a-z]+://') { $server = "http://$server" }
    return $server
}

function Install-Bundle {
    $work = Join-Path $env:TEMP ("mre-bundle-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    try {
        $zip = Join-Path $work 'mre-bundle.zip'
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $client = New-Object System.Net.WebClient
        $proxy = Get-WinHttpProxyUri
        if ($proxy) {
            $client.Proxy = New-Object System.Net.WebProxy($proxy, $true)
            $client.Proxy.UseDefaultCredentials = $true
        }
        $client.DownloadFile($BundleUrl, $zip)
        $h = Get-Sha256 $zip
        if ($h -ne $BundleHash) { throw "empreinte du paquet inattendue : $h" }

        $x = Join-Path $work 'x'
        Expand-Archive -Path $zip -DestinationPath $x -Force
        if (-not (Test-Path (Join-Path $x $ScriptName)) -or -not (Test-Path (Join-Path $x 'tools\manifest.json'))) {
            throw "contenu du paquet incomplet"
        }
        # Seuls le script et tools sont remplaces : les rapports deja produits restent
        $tools = Join-Path $Root 'tools'
        if (Test-Path $tools) { Remove-Item -Path $tools -Recurse -Force -ErrorAction Stop }
        Copy-Item -Path (Join-Path $x 'tools') -Destination $tools -Recurse -Force -ErrorAction Stop
        Copy-Item -Path (Join-Path $x $ScriptName) -Destination (Join-Path $Root $ScriptName) -Force -ErrorAction Stop
        # Anciens noms versionnes (Script_Maintenancev3.3.ps1...) : remplaces par $ScriptName
        Get-ChildItem -Path $Root -Filter 'Script_Maintenance*.ps1' -File -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue
        Set-Content -Path (Join-Path $tools 'bundle.sha256') -Value $BundleHash -Encoding ASCII
    } finally {
        Remove-Item -Path $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if (-not (Test-Path $Root)) { New-Item -ItemType Directory -Path $Root -Force | Out-Null }
$scriptPath   = Join-Path $Root $ScriptName
$toolsPath    = Join-Path $Root 'tools'
$manifestPath = Join-Path $toolsPath 'manifest.json'
$markerPath   = Join-Path $toolsPath 'bundle.sha256'

# Installation conforme : paquet attendu, manifeste lisible et script identique a celui du manifeste
function Test-Installed {
    if (-not (Test-Path $scriptPath) -or -not (Test-Path $manifestPath)) { return 'script ou tools\manifest.json absent' }
    if ($BundleUrl) {
        $installed = if (Test-Path $markerPath) { (Get-Content $markerPath -Raw).Trim() } else { '' }
        if ($installed -ne $BundleHash) { return "paquet installe : $(if ($installed) { $installed } else { 'aucun' })" }
    }
    try { $m = Get-Content $manifestPath -Raw | ConvertFrom-Json } catch { return 'tools\manifest.json illisible' }
    $h = Get-Sha256 $scriptPath
    if ($h -ne ([string]$m.scriptSha256).ToUpperInvariant()) { return "script modifie (empreinte $h)" }
    return ''
}

if ($BundleUrl -and -not $BundleHash) { Stop-WithError "BundleHash manquant pour $BundleVersion" }
$problem = Test-Installed
if ($problem -and $BundleUrl) {
    Write-Output "Installation du paquet $BundleUrl ($problem)."
    try { Install-Bundle } catch { Stop-WithError ("installation du paquet impossible : " + $_.Exception.Message) }
    $problem = Test-Installed
}
if ($problem) { Stop-WithError "$problem dans $Root : copier le contenu de mre-bundle.zip" }
$manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json

Write-Output "Paquet $($manifest.bundleVersion) verifie, lancement."
$started = Get-Date
try {
    # Meme processus : Ninja-Property-Set reste disponible pour le script de maintenance
    & $scriptPath -ToolsPath $toolsPath -NinjaField $Field -NinjaMaxChars $MaxChars
} catch {
    Stop-WithError ("exception : " + $_.Exception.Message)
}
$minutes = [math]::Round(((Get-Date) - $started).TotalMinutes, 1)
Write-Output "Termine en $minutes min."
exit 0
