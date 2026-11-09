[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigPath = "",

    # Dossier des outils externes figes (scripts et modules verifies par SHA-256).
    # Par defaut : .\tools a cote du script, sinon C:\DFI-Maintenance\tools.
    [Parameter(Mandatory=$false)]
    [string]$ToolsPath = "",

    # Custom field NinjaOne qui recoit le JSON compresse (gzip + base64, prefixe "gz64:").
    # Vide = pas d'ecriture NinjaOne (execution manuelle).
    [Parameter(Mandatory=$false)]
    [string]$NinjaField = "",

    # Taille maximale acceptee par le custom field (caracteres). Au-dela, le JSON est allege puis, si
    # necessaire, remplace par un marqueur d'erreur pour que le moteur ne lise pas des donnees tronquees.
    [Parameter(Mandatory=$false)]
    [int]$NinjaMaxChars = 10000,

    # Partage Nextcloud en depot seul ("File drop", ex. https://cloud.exemple.ch/s/AbCdEf) qui recoit le zip
    # des rapports, et son mot de passe. Vide = le zip reste dans Export\.
    [Parameter(Mandatory=$false)]
    [string]$DropUrl = "",

    [Parameter(Mandatory=$false)]
    [string]$DropPassword = ""
)

Write-Host "# ============================="
Write-Host "# V3.4.1 : 09.11.2026"
Write-Host "# ============================="

# v3.4.1 : 09.11.2026
# - GPOZaurr et CleanupMonster uniquement sur l'emulateur PDC (rapports de domaine identiques sur chaque DC)
# - Plus d'erreur HKCU\...\Uninstall affichee sous le compte System

# v3.4 : 06.11.2026
# - Rapport complet a onglets (Export\<SERVEUR>_Maintenance_<AAAAMM>.html) regroupant les rapports des outils
#   (Maintenance, AD Health, GPOZaurr, CleanupMonster, HealthChecker, boites aux lettres, dcdiag, echecs de connexion)
#   et zip avec les fichiers d'origine ; empreinte du zip dans le JSON (reportArchive)
# - Depot du zip dans un partage Nextcloud en depot seul (-DropUrl, -DropPassword)

# v3.3 : 05.11.2026
# - Correction moyenne d'espace disque a 0% sur les serveurs a un seul disque (score de sante faussement degrade)
# - Correction faux positif "OS en fin de support" sur Windows Server 2025 ; 2016 (fin 12.01.2027) declenche desormais la recommandation
# - Correction de troncatures presentes dans le fichier v3.2 recu : -ErrorAction SilentlyConue (section WU toujours sautee),
#   $RWU au lieu de $ReportWU (historique WU absent), $normalizedRecommen (scores par domaine non calcules),
#   categories WindowsUpte/WindowUpdate (domaine Patching toujours a 100), titre "jor",
#   $Config.Services.kRDS (role RDS jamais detecte), libelle "Veeam Backup for Micros", $exchangeComponent (etat des
#   composants Exchange absent du rapport)
# - .Count sur un resultat filtre unique ($null sous PS 5.1) : cases vides et domaine a 100/100 malgre une alerte critique,
#   logiciels a entree unique (7-Zip, Chrome...) absents de la liste, evenement 2004 unique sans recommandation
# - Analyse dcdiag reecrite (ligne par ligne, FR/EN, noms de tests renvoyes a la ligne) : l'ancienne affichait
#   "Aucun probleme detecte" quand l'analyse echouait
# - Replication AD : 7 colonnes utiles au lieu de 29 ; recommandation en cas d'echec de replication
# - Outils externes figes (dossier tools, SHA-256) ; PSWindowsUpdate remplace par l'API Windows Update native
# - ADChecker lance avec -Report (aucun rapport n'etait produit), limite au DC local, delai maximal 5 min,
#   desactivable (CheckADHealthTool) ; CleanUpMonster : comptes ordinateurs inactifs repris dans le JSON ;
#   HealthChecker sans auto-mise a jour
# - Recommandations : la fonction ecrivait dans $global: alors que le script lit sa propre portee ; lance via
#   "& script.ps1" (wrapper, -Command, appel depuis un autre script) toutes les recommandations etaient perdues
# - Exchange : chargement du snap-in avant le test des cmdlets (hors Exchange Management Shell, le bloc etait toujours saute)
# - Exchange : edition/periode d'essai, certificats Auth et transport interne, constats HealthChecker dans le JSON
# - Test-ExchangeServerHealth desactive par defaut (incompatible Exchange SE, faux resultats)
# - Invoke-WebRequest -UseBasicParsing partout (sinon invite de securite bloquante sous NinjaOne)
# - Lignes alterees de la copie v3.2 recue (caracteres manquants : fa-microhip, .proress, thresholds.disk.goo, <divclass...)
#   restaurees depuis la v3.2 deployee sur les serveurs (19.06.2026)
# - Export JSON (schema dfi-mre/1) a cote du rapport HTML
# - Correction erreur de syntaxe "-g 0" (bloc Points a surveiller) et balise </dv> du KPI global
# - NinjaOne : execution en System validee ; domaine lu sur la machine (USERDNSDOMAIN vide sous System),
#   ecriture du custom field avec repli sur ninjarmm-cli.exe
# - Purge des anciens artefacts en fin d'execution (KeepLastReports par type, MaxLogFiles pour les journaux,
#   modules extraits dans TEMP par les executions precedentes) ; les sous-dossiers d'archives ne sont pas touches
# - Outils decrits par tools\manifest.json (chemin, version, source, SHA-256), produit avec le paquet de release ;
#   chaque fichier est verifie avant usage, aucun telechargement a l'execution

# v3.2 : 19.06.2026
# - Uniformisation du rendu AD: sous-sections Services AD, DCDIAG, DCDIAG-DNS, Kerberos, Replication AD Metadata et Backup AD rendues avec le meme gabarit visuel (report-subsection)
# - Harmonisation de la section Replication AD Metadata (titres/espacements/tableau) avec le reste du rapport
# - Encapsulation ADChecker dans une sous-section AD coherente tout en conservant le conteneur externe pour les tableaux larges
# - Correction critique Escape-Html: remplacement string-safe (suppression de l'erreur Replace [char] -> '&amp;' qui cassait le rendu en fin de bloc Windows Update)
# - Renforcement du Resume Executif: fallback explicite si aucun score de domaine n'est genere
# - Protection du KPI global: fallback "Indetermine" si le calcul de sante ne remonte pas un objet exploitable
# - Nettoyage Antivirus: suppression des faux positifs Registre (KB/Office/.NET/Hotfix/Cumulative Update)
# - Durcissement Antivirus en allowlist stricte: Bitdefender, CrowdStrike Falcon, Symantec Endpoint Protection, Windows Defender
# - Tableau Antivirus enrichi avec colonne Type (AV/EDR)
# - Exclusion des modules Veeam non cibles dans "Logiciels installes" (Proxmox, oVirt, Google Cloud/GCP, Kasten, AWS)
# - Amelioration section Logiciels: normalisation des libelles (FileZilla, Notepad++, PuTTY, WinRAR, WinSCP, etc.)
# - De-duplication des applications installees (DisplayName + DisplayVersion)
# - Epuration du rapport logiciels: suppression des longues listes "Non trouve" / "Non installe" et messages courts uniquement si aucune donnee

# v2.3 : 27.01.2026
# - Amélioration du système de scoring de santé du serveur avec détails explicites (CPU/RAM/Disque)
# - Ajout d'un bloc global "Actions Recommandées" avec génération automatique de recommandations
# - Recommandations automatiques pour : Uptime > 90 jours, Event Logs (>100 erreurs), Veeam (jobs/licences), Windows Update
# - Recommandations AD/GPO : dcdiag, krbtgt password age, services AD critiques
# - Recommandations sécurité : DNS publics, comptes Administrateurs locaux, Event ID 2004
# - Vérification Secure Boot (UEFI CA 2023) avec recommandations selon KB 5068202 (clés UEFICA2023Status, UEFICA2023Error, AvailableUpdates)
# - Ajout d'un résumé par rôles détectés en haut du rapport (tableau de statut)
# - Section dédiée "Serveur de fichiers" avec liste des partages SMB (exclusion des imprimantes)
# - Vérification Time Sync / NTP avec recommandations pour sources non fiables
# - Hygiène des applications : détection EOL (SQL Server, Exchange, Office), .NET Framework obsolète, outils d'accès distant
# - Amélioration du menu de navigation avec séparateurs visuels discrets entre groupes logiques
# - Nettoyage du code : suppression des variables inutilisées
# - Simplification : suppression des paramètres ClientName et ConfigPath (script générique)
# - Rollback : suppression de la gestion JSON (configuration intégrée au script)

# v2.2 : 23.12.2025
# (Version précédente)

# v2.1 : 31.10
# Ajout des dates de fin de support 
# Correction des erreurs
# Améliorations visuels

# v2.0 : 26.04
# Correction des erreurs remontes
# Ajout de la liste des applications installes
# Ajout des check Antivirus (a tester)
# Changements au niveau du code HTML/CSS 

# v1.1 : 26.02
# Correction d'un bug d'affichage AD Connect
# Correction d'un bug d'affichage de la version Windows
# Ajustement de certains parametres

Write-Host "# ============================="
Write-Host "# Block 0 : Initialisation"
Write-Host "# ============================="

try {
    # Limiter l'impact au processus courant uniquement.
    Set-ExecutionPolicy RemoteSigned -Scope Process -Force -ErrorAction Stop
} catch {
    Write-Warning "Impossible d'ajuster ExecutionPolicy pour ce processus : $($_.Exception.Message)"
}

# Configuration TLS 1.2 pour toutes les requêtes web sécurisées (compatible Windows PowerShell 5.1)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Verifier les privileges d'execution (élévation) et relancer si nécessaire
function Confirm-Elevation {
    try {
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        $isAdmin = $false
    }

    if (-not $isAdmin) {
        Write-Warning "Ce script nécessite des droits administrateur. Tentative d'élévation..."
        $scriptPath = $MyInvocation.MyCommand.Path
        if (-not $scriptPath -or $scriptPath -eq '') {
            Write-Warning "Impossible de déterminer le chemin du script; lancez manuellement en tant qu'administrateur.";
            exit 1
        }

        # Choisir l'exécutable PowerShell disponible
        $pwExe = 'powershell'
        if ($PSVersionTable.PSVersion.Major -ge 6) { $pwExe = 'pwsh' }

        try {
            Start-Process -FilePath $pwExe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs -WindowStyle Normal
        Write-HostSafe "Relancement du script en mode administrateur...";
            exit 0
        } catch {
            Write-Warning "Échec de l'élévation : $($_.Exception.Message)"
            exit 1
        }
    } else {
        Write-HostSafe "Execution avec privileges administrateur." -ForegroundColor Green
    }
}

# Fonction de logging
function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','VERBOSE')][string]$Level = 'INFO'
    )
    switch ($Level) {
        'ERROR'   { Write-Error $Message; break }
        'WARN'    { Write-Warning $Message; break }
        'VERBOSE' { Write-Verbose $Message; break }
        default   { Write-Output $Message; break }
    }
}

# Fonction pour "nettoyer" les accents pour l'affichage console (Write-Host)
function Convert-ToSafeConsoleText {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Text
    )
    if ($null -eq $Text) { return "" }

    # Évite les accents littéraux (problèmes d'encodage possibles si le fichier est lu en ANSI)
    $out = $Text

    # e / E
    $out = $out.Replace([string][char]0x00E9,'e') # é
    $out = $out.Replace([string][char]0x00E8,'e') # è
    $out = $out.Replace([string][char]0x00EA,'e') # ê
    $out = $out.Replace([string][char]0x00EB,'e') # ë
    $out = $out.Replace([string][char]0x00C9,'E') # É
    $out = $out.Replace([string][char]0x00C8,'E') # È
    $out = $out.Replace([string][char]0x00CA,'E') # Ê
    $out = $out.Replace([string][char]0x00CB,'E') # Ë

    # a / A
    $out = $out.Replace([string][char]0x00E0,'a') # à
    $out = $out.Replace([string][char]0x00E2,'a') # â
    $out = $out.Replace([string][char]0x00C0,'A') # À
    $out = $out.Replace([string][char]0x00C2,'A') # Â

    # i / I
    $out = $out.Replace([string][char]0x00EE,'i') # î
    $out = $out.Replace([string][char]0x00EF,'i') # ï
    $out = $out.Replace([string][char]0x00CE,'I') # Î
    $out = $out.Replace([string][char]0x00CF,'I') # Ï

    # o / O
    $out = $out.Replace([string][char]0x00F4,'o') # ô
    $out = $out.Replace([string][char]0x00F6,'o') # ö
    $out = $out.Replace([string][char]0x00D4,'O') # Ô
    $out = $out.Replace([string][char]0x00D6,'O') # Ö

    # u / U
    $out = $out.Replace([string][char]0x00F9,'u') # ù
    $out = $out.Replace([string][char]0x00FB,'u') # û
    $out = $out.Replace([string][char]0x00D9,'U') # Ù
    $out = $out.Replace([string][char]0x00DB,'U') # Û

    return $out
}

function Write-HostSafe {
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Message,
        [ConsoleColor]$ForegroundColor,
        [ConsoleColor]$BackgroundColor
    )

    $safe = Convert-ToSafeConsoleText -Text $Message

    if ($PSBoundParameters.ContainsKey('ForegroundColor') -and $PSBoundParameters.ContainsKey('BackgroundColor')) {
        Write-Host -Object $safe -ForegroundColor $ForegroundColor -BackgroundColor $BackgroundColor
    } elseif ($PSBoundParameters.ContainsKey('ForegroundColor')) {
        Write-Host -Object $safe -ForegroundColor $ForegroundColor
    } elseif ($PSBoundParameters.ContainsKey('BackgroundColor')) {
        Write-Host -Object $safe -BackgroundColor $BackgroundColor
    } else {
        Write-Host -Object $safe
    }
}

# Test de connectivite Internet plus fiable en contexte entreprise (HTTPS plutot que ping ICMP)
function Test-InternetAccess {
    [CmdletBinding()]
    param(
        [string[]]$Urls = @(
            'https://www.msftconnecttest.com/connecttest.txt',
            'https://www.microsoft.com'
        ),
        [int]$TimeoutSec = 8
    )

    foreach ($url in $Urls) {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $url -Method Head -TimeoutSec $TimeoutSec -ErrorAction Stop | Out-Null
            return $true
        } catch {
            # On tente l'URL suivante
        }
    }

    return $false
}

# Outils externes figes (v3.3) : remplace le telechargement a l'execution.
# Retourne le chemin d'un fichier du dossier tools uniquement si son SHA-256 correspond a l'empreinte attendue.
function Resolve-ToolsPath {
    param([string]$Requested)
    $candidates = @()
    if ($Requested) { $candidates += $Requested }
    if ($PSScriptRoot) { $candidates += (Join-Path $PSScriptRoot 'tools') }
    $candidates += 'C:\DFI-Maintenance\tools'
    foreach ($c in $candidates) {
        if ($c -and (Test-Path -LiteralPath $c -PathType Container)) { return (Resolve-Path -LiteralPath $c).Path }
    }
    return $null
}

function Test-PinnedFile {
    param(
        [Parameter(Mandatory=$true)][string]$RelativePath,
        [Parameter(Mandatory=$true)][string]$Sha256
    )
    if (-not $script:ToolsRoot) {
        Write-HostSafe "# Dossier tools introuvable : outil $RelativePath ignore."
        return $null
    }
    $full = Join-Path $script:ToolsRoot $RelativePath
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        Write-HostSafe "# Outil absent : $full (ignore)."
        return $null
    }
    $actual = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash
    if ($actual -ne $Sha256.ToUpperInvariant()) {
        Write-HostSafe "# EMPREINTE INVALIDE pour $full : attendu $Sha256, obtenu $actual. Outil NON execute."
        $script:ToolIntegrityErrors += $RelativePath
        return $null
    }
    return $full
}

# Charge tools\manifest.json (produit avec le paquet de release) dans $Config.Tools / $Config.ToolModules.
# Les empreintes y sont figees ; Test-PinnedFile refuse tout fichier qui ne correspond pas.
function Import-ToolManifest {
    param([string]$Root)
    $Config.Tools = @{}
    $Config.ToolModules = @()
    if (-not $Root) { return $null }
    $path = Join-Path $Root 'manifest.json'
    if (-not (Test-Path -LiteralPath $path)) {
        Write-HostSafe "# Manifeste des outils absent ($path) : outils externes ignores."
        Add-MreError -Section 'tools' -Message "manifest.json absent dans $Root"
        return $null
    }
    try {
        $m = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        Add-MreError -Section 'tools' -Message "manifest.json illisible : $($_.Exception.Message)"
        return $null
    }
    foreach ($p in @($m.scripts.PSObject.Properties)) {
        $Config.Tools[$p.Name] = @{ Path = $p.Value.path; Sha256 = $p.Value.sha256; Version = $p.Value.version }
    }
    $Config.ToolModules = @($m.modules | ForEach-Object {
        @{ Name = $_.name; Path = $_.path; Sha256 = $_.sha256; ModuleRoot = [bool]$_.moduleRoot; Version = $_.version } })
    return $m
}

# Export JSON (v3.3) : chaque section depose ici ses donnees brutes, a cote du HTML.
# Le JSON est la source du moteur auto-mre (page XWiki) ; le HTML reste le rapport local.
$script:Mre = [ordered]@{
    schema        = 'dfi-mre/1'
    scriptVersion = '3.4.1'
    generatedAt   = (Get-Date).ToUniversalTime().ToString('o')
    host          = $env:COMPUTERNAME
    # USERDNSDOMAIN est vide sous le compte System (NinjaOne) : domaine lu sur la machine
    domain        = $(try { (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).Domain } catch { $env:USERDNSDOMAIN })
    sections      = [ordered]@{}
    errors        = @()
}

function Set-MreSection {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        $Value
    )
    $script:Mre.sections[$Name] = $Value
}

function Add-MreError {
    param([string]$Section, [string]$Message)
    $script:Mre.errors += [ordered]@{ section = $Section; message = $Message }
}

# Convertit une date en ISO 8601 UTC (le JSON de ConvertTo-Json 5.1 donne sinon "\/Date(...)\/").
function ConvertTo-IsoDate {
    param($Value)
    if ($null -eq $Value) { return $null }
    try { return ([datetime]$Value).ToUniversalTime().ToString('o') } catch { return [string]$Value }
}

# Copie un script fige verifie vers sa destination de travail. Retourne $true si la copie est faite.
function Copy-PinnedTool {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Destination
    )
    $entry = $Config.Tools[$Name]
    if (-not $entry) { Write-HostSafe "# Outil $Name non declare dans la configuration."; return $false }
    $src = Test-PinnedFile -RelativePath $entry.Path -Sha256 $entry.Sha256
    if (-not $src) { return $false }
    Copy-Item -LiteralPath $src -Destination $Destination -Force -ErrorAction Stop
    # Re-verifier la copie : la destination est le fichier reellement execute.
    if ((Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash -ne $entry.Sha256.ToUpperInvariant()) {
        Write-HostSafe "# Copie alteree pour $Name, outil NON execute."
        return $false
    }
    return $true
}

# Fonction pour échapper les caractères HTML
function Escape-Html {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    try {
        return [System.Web.HttpUtility]::HtmlEncode($Text)
    } catch {
        # Fallback si System.Web n'est pas disponible
        $t = $Text
        $t = $t.Replace('&', '&amp;')       # &
        $t = $t.Replace('<', '&lt;')        # <
        $t = $t.Replace('>', '&gt;')        # >
        $t = $t.Replace('"', '&quot;')      # "
        $t = $t.Replace("'", '&#39;')      # '
        return $t
    }
}

# Fonction pour obtenir la configuration (simple, sans client)
function Get-Configuration {
    param(
        [string]$ConfigPath = ""
    )
    
    # Configuration par défaut (intégrée au script)
    $config = @{
        OutputPath   = 'C:\DFI-Maintenance'
        ReportPrefix = "Maintenance"
        Thresholds   = @{
            CPU = @{
                Good     = 40
                Warning  = 75
                Critical = 85
            }
            RAM = @{
                Good     = 40
                Warning  = 75
                Critical = 85
            }
            Disk = @{
                Good     = 60
                Warning  = 30
                Critical = 15
            }
        }
        Services = @{
            CheckAD             = $true
            CheckPrintServer    = $true
            CheckRDS            = $true
            CheckVeeam          = $true
            CheckVeeam365       = $true
            CheckExchange       = $true
            CheckWindowsUpdate  = $true
            # Test-ExchangeServerHealth (2015) est incompatible avec Exchange SE : faux "Fail" (Test-MAPIConnectivity
            # -Database, Test-Mailflow absent) et lecture de variables du script ($versions). HealthChecker le remplace.
            CheckExchangeLegacyHealth = $false
            # ADChecker (Get-ADHealth) : controles complementaires (tombstone, corbeille AD, LDAP, NTLMv1...).
            # Passe par WinRM/CIM meme en local ; borne a 5 min. Mettre a $false si WinRM est indisponible.
            CheckADHealthTool   = $true
            # GPOZaurr et CleanupMonster couvrent tout le domaine : uniquement sur l'emulateur PDC
            DomainWideToolsOnPdcOnly = $true
        }
        Export = @{
            GeneratePDF       = $false
            KeepLastReports   = 10
            ArchiveOldReports = $true
        }
        Logging = @{
            Enabled     = $true
            LogPath     = 'C:\DFI-Maintenance\logs'
            LogLevel    = "INFO"
            MaxLogFiles = 30
        }
        # Outils externes : charges depuis tools\manifest.json (voir Import-ToolManifest)
        Tools = @{}
        ToolModules = @()
        Security = @{}
    }
    
    return $config
}

# Fonction robuste pour vérifier si une application est installée
function Test-ApplicationInstalled {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ApplicationName,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("Exact", "Contains", "Match")]
        [string]$MatchType = "Contains"
    )
    
    try {
        $registryPaths = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        )
        
        foreach ($regPath in $registryPaths) {
            if (-not (Test-Path $regPath)) { continue }
            
            $apps = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue | 
                    Get-ItemProperty -ErrorAction SilentlyContinue | 
                    Where-Object { $_.DisplayName }
            
            if ($apps) {
                $found = switch ($MatchType) {
                    "Exact" {
                        $apps | Where-Object { $_.DisplayName -eq $ApplicationName } | Select-Object -First 1
                    }
                    "Contains" {
                        $apps | Where-Object { $_.DisplayName -like "*$ApplicationName*" } | Select-Object -First 1
                    }
                    "Match" {
                        $apps | Where-Object { $_.DisplayName -match $ApplicationName } | Select-Object -First 1
                    }
                }
                
                if ($found) { return $true }
            }
        }
        
        return $false
    } catch {
        Write-Log -Message "Erreur lors de la vérification de l'application $ApplicationName : $($_.Exception.Message)" -Level 'WARN'
        return $false
    }
}

# Fonction robuste pour vérifier si un module PowerShell existe
function Test-PowerShellModuleAvailable {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ModuleName,
        
        [Parameter(Mandatory=$false)]
        [string]$ModulePath = $null
    )
    
    try {
        if ($ModulePath) {
            if (Test-Path $ModulePath) {
                return $true
            }
        } else {
            $module = Get-Module -ListAvailable -Name $ModuleName -ErrorAction SilentlyContinue
            if ($module) {
                return $true
            }
        }
        return $false
    } catch {
        return $false
    }
}

# Fonction robuste pour vérifier si Exchange est installé
function Test-ExchangeInstalled {
    try {
        # Vérifier via le service
        $exchangeService = Get-Service -Name MSExchange* -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($exchangeService) {
            return $true
        }
        
        # Vérifier via les cmdlets Exchange
        $exchangeCmdlet = Get-Command -Name Get-ExchangeServer -ErrorAction SilentlyContinue
        if ($exchangeCmdlet) {
            return $true
        }
        
        # Vérifier via le registre
        $exchangePath = "HKLM:\SOFTWARE\Microsoft\ExchangeServer"
        if (Test-Path $exchangePath) {
            return $true
        }
        
        return $false
    } catch {
        return $false
    }
}

# Fonction pour obtenir les informations d'une application installée
function Get-InstalledApplication {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ApplicationName,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("Exact", "Contains", "Match")]
        [string]$MatchType = "Contains"
    )
    
    try {
        $registryPaths = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        )
        
        foreach ($regPath in $registryPaths) {
            if (-not (Test-Path $regPath)) { continue }
            
            $apps = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue | 
                    Get-ItemProperty -ErrorAction SilentlyContinue | 
                    Where-Object { $_.DisplayName }
            
            if ($apps) {
                $result = switch ($MatchType) {
                    "Exact" {
                        $apps | Where-Object { $_.DisplayName -eq $ApplicationName } | Select-Object -First 1
                    }
                    "Contains" {
                        $apps | Where-Object { $_.DisplayName -like "*$ApplicationName*" } | Select-Object -First 1
                    }
                    "Match" {
                        $apps | Where-Object { $_.DisplayName -match $ApplicationName } | Select-Object -First 1
                    }
                }
                
                if ($result) { return $result }
            }
        }
        
        return $null
    } catch {
        Write-Log -Message "Erreur lors de la récupération de l'application $ApplicationName : $($_.Exception.Message)" -Level 'WARN'
        return $null
    }
}

function Get-RecommendationContext {
    param(
        [hashtable]$Capabilities
    )

    $computerSystem = $null
    try {
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    } catch {}

    $domainRole = if ($computerSystem) { [int]$computerSystem.DomainRole } else { -1 }
    $platformSignature = if ($computerSystem) { "$($computerSystem.Manufacturer) $($computerSystem.Model)" } else { "" }

    return [pscustomobject]@{
        IsDomainJoined      = if ($computerSystem) { [bool]$computerSystem.PartOfDomain } else { $false }
        IsDomainController  = $domainRole -in @(4, 5)
        IsMemberServer      = $domainRole -eq 3
        IsStandaloneServer  = $domainRole -eq 2
        IsVirtualMachine    = $platformSignature -match 'vmware|virtual|hyper-v|kvm|xen|virtualbox'
        HasRemoteAdminRole  = [bool]($Capabilities.Contains('HasPrintServer') -and $Capabilities.HasPrintServer)
    }
}

# Fonction centralisée pour ajouter une action recommandée structurée
function Add-ActionRecommendation {
    param(
        [Parameter(Mandatory=$true)][string]$Category,
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet(1,2,3)][int]$Priority = 2
    )

    if ($null -eq $script:ActionRecommendations) {
        # Normaliser en tableau vide si null
        $script:ActionRecommendations = @()
    }
    elseif ($script:ActionRecommendations -isnot [System.Collections.IList]) {
        # Normaliser en tableau si objet unique
        $script:ActionRecommendations = @($script:ActionRecommendations)
    }

    $rec = [pscustomobject]@{
        Category = $Category
        Message  = $Message
        Priority = $Priority
    }

    $script:ActionRecommendations += $rec
}

# Fonction pour calculer le score de sante global du serveur
function Get-HealthScore {
    param(
        [double]$CPUUsage,
        [double]$UsedRAMPercent,
        [double]$AvgDiskFreePercent,
        [hashtable]$Thresholds
    )

    $score     = 100
    $findings  = @()

    # Impact CPU
    if ($CPUUsage -ge $Thresholds.CPU.Critical) {
        $score -= 30
        $findings += "Utilisation CPU &gt;= $($Thresholds.CPU.Critical)% (critique)"
    } elseif ($CPUUsage -ge $Thresholds.CPU.Warning) {
        $score -= 15
        $findings += "Utilisation CPU &gt;= $($Thresholds.CPU.Warning)% (elevee)"
    }

    # Impact RAM
    if ($UsedRAMPercent -ge $Thresholds.RAM.Critical) {
        $score -= 30
        $findings += "Utilisation RAM &gt;= $($Thresholds.RAM.Critical)% (critique)"
    } elseif ($UsedRAMPercent -ge $Thresholds.RAM.Warning) {
        $score -= 15
        $findings += "Utilisation RAM &gt;= $($Thresholds.RAM.Warning)% (elevee)"
    }

    # Impact Disques (moyenne espace libre)
    if ($AvgDiskFreePercent -le $Thresholds.Disk.Critical) {
        $score -= 30
        $findings += "Espace disque moyen &lt;= $($Thresholds.Disk.Critical)% (tres faible)"
    } elseif ($AvgDiskFreePercent -le $Thresholds.Disk.Warning) {
        $score -= 15
        $findings += "Espace disque moyen &lt;= $($Thresholds.Disk.Warning)% (faible)"
    }

    if ($score -lt 0) { $score = 0 }
    if ($score -gt 100) { $score = 100 }

    if ($score -ge 80) {
        $label = "Bon"
        $badge = "badge-success"
    } elseif ($score -ge 50) {
        $label = "A surveiller"
        $badge = "badge-warning"
    } else {
        $label = "Critique"
        $badge = "badge-error"
    }

    return [pscustomobject]@{
        Score        = $score
        Label        = $label
        BadgeClass   = $badge
        Findings     = $findings
    }
}

# Score de sante par domaine base sur les recommandations (priorites/categories)
function Get-DomainHealthScore {
    param(
        [Parameter(Mandatory=$true)][string]$DomainName,
        [Parameter(Mandatory=$true)][string[]]$Categories,
        [Parameter(Mandatory=$true)][object[]]$Recommendations
    )

    $domainRecs = $Recommendations | Where-Object { $_.Category -in $Categories }
    $highCount = @($domainRecs | Where-Object { $_.Priority -eq 1 }).Count
    $mediumCount = @($domainRecs | Where-Object { $_.Priority -eq 2 }).Count
    $infoCount = @($domainRecs | Where-Object { $_.Priority -eq 3 }).Count

    # Penalite simple et lisible: plus la priorite est haute, plus elle pese.
    $penalty = ($highCount * 35) + ($mediumCount * 15) + ($infoCount * 5)
    $score = 100 - $penalty
    if ($score -lt 0) { $score = 0 }
    if ($score -gt 100) { $score = 100 }

    if ($score -ge 80) {
        $label = "Bon"
        $badge = "badge-success"
    } elseif ($score -ge 50) {
        $label = "A surveiller"
        $badge = "badge-warning"
    } else {
        $label = "Critique"
        $badge = "badge-error"
    }

    return [pscustomobject]@{
        Domain    = $DomainName
        Score     = $score
        Label     = $label
        BadgeClass = $badge
        High      = $highCount
        Medium    = $mediumCount
        Info      = $infoCount
    }
}

# Resume executif base sur les indicateurs et recommandations deja collectes
function New-ExecutiveSummaryHtml {
    param(
        [Parameter(Mandatory=$true)][int]$GlobalScore,
        [Parameter(Mandatory=$true)][string]$GlobalLabel,
        [Parameter(Mandatory=$true)][object[]]$Recommendations,
        [Parameter(Mandatory=$true)][object[]]$DomainScores
    )

    $highCount = @($Recommendations | Where-Object { $_.Priority -eq 1 }).Count
    $mediumCount = @($Recommendations | Where-Object { $_.Priority -eq 2 }).Count
    $infoCount = @($Recommendations | Where-Object { $_.Priority -eq 3 }).Count

    $calloutClass = "info"
    $summaryTitle = "Etat global satisfaisant"
    if ($highCount -gt 0) {
        $calloutClass = "danger"
        $summaryTitle = "Points critiques a traiter"
    } elseif ($mediumCount -gt 0 -or $GlobalScore -lt 80) {
        $calloutClass = "warn"
        $summaryTitle = "Points de vigilance"
    }

    $domainRows = ($DomainScores | ForEach-Object {
        "<tr><td>" + (Escape-Html $_.Domain) + "</td><td><span class='" + $_.BadgeClass + "'>" + $_.Score + "/100 - " + (Escape-Html $_.Label) + "</span></td><td>" + $_.High + "</td><td>" + $_.Medium + "</td><td>" + $_.Info + "</td></tr>"
    }) -join ""

    if ([string]::IsNullOrWhiteSpace($domainRows)) {
        $domainRows = "<tr><td colspan='5'>Aucun score de domaine disponible.</td></tr>"
    }

    return @"
<div class='section' id='executif'>
    <h2>Resume Executif</h2>
    <div class='callout $calloutClass'>
        <div class='title'>$summaryTitle</div>
        <p><strong>Score global:</strong> $GlobalScore/100 ($GlobalLabel)</p>
        <p><strong>Alertes:</strong> $highCount critique(s), $mediumCount vigilance(s), $infoCount information(s).</p>
    </div>
    <h3>Scores par domaine</h3>
    <table>
        <tr><th>Domaine</th><th>Score</th><th>Critiques</th><th>Vigilances</th><th>Infos</th></tr>
        $domainRows
    </table>
</div>
"@
}

# Appel de la verification d'élévation
Confirm-Elevation

# Initialisation des variables de rapport (à $null pour tests conditionnels corrects)
$ReportAD = $null
$ReportRDS = $null
$ReportVBR = $null
$ReportVBO = $null
$ExchangeReport = $null
$WindowsUpdateReport = $null
$htmlapps = $null
$htmlreport = $null
$Printers = $null
$adCheckerBodyContent = $null
$ADConnectVersion = $null
$IsFileServer = $false
$FileSharesInfo = @()

# Indicateur global d'erreurs critiques survenues pendant l'execution
$GlobalError = $false

# Liste globale des actions recommandées (alimentée tout au long du script)
$ActionRecommendations = @()

# Charger la configuration
Write-HostSafe "# ============================="
Write-HostSafe "# Chargement de la configuration"
Write-HostSafe "# ============================="
$Config = Get-Configuration -ConfigPath $ConfigPath
Write-HostSafe "# Chemin de sortie : $($Config.OutputPath)" -ForegroundColor Cyan
Write-HostSafe "# Services actives : AD=$($Config.Services.CheckAD), Print=$($Config.Services.CheckPrintServer), RDS=$($Config.Services.CheckRDS), Veeam=$($Config.Services.CheckVeeam), Exchange=$($Config.Services.CheckExchange), WU=$($Config.Services.CheckWindowsUpdate)" -ForegroundColor Cyan

# Detecter la connectivite Internet (pour eviter les telechargements lents si pas de reseau)
$HasInternet = $false
try {
    $HasInternet = Test-InternetAccess
} catch {
    $HasInternet = $false
}

# Conteneurs JSON des sections Veeam et Exchange (remplis seulement si le role est present)
$script:MreVeeam = [ordered]@{ jobs = @(); repositories = @(); license = $null; m365Jobs = @() }
$script:MreExchange = [ordered]@{ componentStates = @(); certificates = @() }

# Outils figes (v3.3)
$script:ToolIntegrityErrors = @()
$script:ToolsRoot = Resolve-ToolsPath -Requested $ToolsPath
$toolManifest = Import-ToolManifest -Root $script:ToolsRoot
if ($toolManifest) {
    Write-HostSafe "# Outils figes : $($script:ToolsRoot) (paquet $($toolManifest.bundleVersion))" -ForegroundColor Cyan
    $script:Mre.bundleVersion = $toolManifest.bundleVersion
    $script:Mre.tools = @(@($Config.Tools.Keys | ForEach-Object { "$_ $($Config.Tools[$_].Version)" }) +
                          @($Config.ToolModules | ForEach-Object { "$($_.Name) $($_.Version)" }))
} elseif ($script:ToolsRoot) {
    Write-HostSafe "# Outils figes : $($script:ToolsRoot) (sans manifeste)" -ForegroundColor Yellow
} else {
    Write-HostSafe "# Dossier tools introuvable : ADChecker, GPOZaurr, CleanUpMonster et les checks Exchange externes seront ignores." -ForegroundColor Yellow
}

# Détection centralisée des rôles / produits installés
$EnvCapabilities = [ordered]@{
    HasAD          = $false
    HasPrintServer = $false
    HasVBR         = $false
    HasVBO         = $false
    HasExchange    = $false
}

try {
    if ($Config.Services.CheckAD) {
        $feature = Get-WindowsFeature -Name AD-Domain-Services -ErrorAction SilentlyContinue
        if ($feature -and $feature.Installed) { $EnvCapabilities.HasAD = $true }
    }
} catch {}

try {
    if ($Config.Services.CheckPrintServer) {
        $feature = Get-WindowsFeature -Name Print-Server -ErrorAction SilentlyContinue
        if ($feature -and $feature.Installed) { $EnvCapabilities.HasPrintServer = $true }
    }
} catch {}

try {
    if ($Config.Services.CheckVeeam) {
        $EnvCapabilities.HasVBR = Test-ApplicationInstalled -ApplicationName "Veeam Backup & Replication" -MatchType "Contains"
    }
} catch {}

try {
    if ($Config.Services.CheckVeeam365) {
        $EnvCapabilities.HasVBO = Test-ApplicationInstalled -ApplicationName "Veeam Backup for Microsoft 365" -MatchType "Exact"
    }
} catch {}

try {
    if ($Config.Services.CheckExchange) {
        $EnvCapabilities.HasExchange = Test-ExchangeInstalled
    }
} catch {}

$RecommendationContext = Get-RecommendationContext -Capabilities $EnvCapabilities

# Definir le chemin de sortie
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$folderPath = $Config.OutputPath

# S'assurer que le prefixe du rapport contient toujours 'Maintenance'
if (-not $Config.ReportPrefix -or $Config.ReportPrefix.Trim() -eq "") {
    $reportPrefix = "Maintenance"
} else {
    $reportPrefix = $Config.ReportPrefix
    if ($reportPrefix -notmatch 'Maintenance') {
        $reportPrefix = "Maintenance_$reportPrefix"
    }
}

$outputPath = Join-Path $folderPath "${reportPrefix}_${Hostname}_$timestamp.html"

# Creer le dossier s'il n'existe pas
if (-not (Test-Path -Path $folderPath)) {
    New-Item -ItemType Directory -Path $folderPath -Force | Out-Null
    Write-Log -Message "Le dossier $folderPath a ete cree." -Level 'INFO'
}

# Creer le dossier de logs si le logging est activé
if ($Config.Logging.Enabled) {
    if (-not (Test-Path -Path $Config.Logging.LogPath)) {
        New-Item -ItemType Directory -Path $Config.Logging.LogPath -Force | Out-Null
    }
}

# Variable a definir
$CurrentDate = Get-Date
$reportPath = $Config.OutputPath
if (-not $reportPath.EndsWith("\")) { $reportPath += "\" }

Write-HostSafe "# ============================="
Write-HostSafe "# Block 1 : Informations systeme de base"
Write-HostSafe "# ============================="

# Informations sur le système d'exploitation
# Initialiser OSInstance si pas déjà fait (sera réutilisé pour RAM et Uptime)
if (-not $OSInstance) {
    $OSInstance = Get-CimInstance -Class Win32_OperatingSystem
}
$OS = $OSInstance | Select-Object Version, Caption, BuildNumber
$OSInfo = $OS | ConvertTo-Html -Fragment

$cap = $OS.Caption

$WarningOS = if ($cap -like "*Windows Server 2003*") {
    @"
<div class='callout danger'>
  <div class='title'>Fin de support</div>
  <p>Windows Server 2003 et 2003 R2 ne sont plus supportés depuis le 14 juillet 2015.</p>
</div>
"@
} elseif ($cap -like "*Windows Server 2008 R2*") {
    @"
<div class='callout danger'>
  <div class='title'>Fin de support</div>
  <p>Windows Server 2008 R2 n’est plus supporté depuis le 14 janvier 2020 (ESU jusqu’au 10 janvier 2023).</p>
</div>
"@
} elseif ($cap -like "*Windows Server 2008*" -and $cap -notlike "*R2*") {
    @"
<div class='callout danger'>
  <div class='title'>Fin de support</div>
  <p>Windows Server 2008 n’est plus supporté depuis le 14 janvier 2020 (ESU jusqu’au 10 janvier 2023).</p>
</div>
"@
} elseif ($cap -like "*Windows Server 2012 R2*") {
    @"
<div class='callout danger'>
  <div class='title'>Fin de support</div>
  <p>Windows Server 2012 / 2012 R2 : plus de mises à jour depuis le 10 octobre 2023 (ESU via Azure Arc jusqu’au 13 octobre 2026).</p>
</div>
"@
} elseif ($cap -like "*Windows Server 2012*") {
    @"
<div class='callout danger'>
  <div class='title'>Fin de support</div>
  <p>Windows Server 2012 / 2012 R2 : plus de mises à jour depuis le 10 octobre 2023 (ESU via Azure Arc jusqu’au 13 octobre 2026).</p>
</div>
"@
} elseif ($cap -like "*Windows Server 2016*") {
    @"
<div class='callout warn'>
  <div class='title'>Attention</div>
  <p>Windows Server 2016 reste supporté jusqu’au 12 janvier 2027.</p>
</div>
"@
} elseif ($cap -like "*Windows Server 2019*") {
    @"
<div class='callout'>
  <div class='title'>Information</div>
  <p>Windows Server 2019 est supporté jusqu’au 9 janvier 2029.</p>
</div>
"@
} elseif ($cap -like "*Windows Server 2022*") {
    @"
<div class='callout'>
  <div class='title'>Information</div>
  <p>Windows Server 2022 est supporté jusqu’au 14 octobre 2031.</p>
</div>
"@
} elseif ($cap -like "*Windows Server 2025*") {
    @"
<div class='callout'>
  <div class='title'>Information</div>
  <p>Windows Server 2025 est supporté jusqu’au 10 octobre 2034.</p>
</div>
"@
} else {
    ""
}

# On teste le titre du callout et non tout le texte : -like ignore la casse, et la phrase
# "Vérifier la date de fin de support" declenchait la recommandation sur tous les serveurs (v3.3).
# "Attention" couvre les versions dont la fin de support est proche (2016 : 12.01.2027).
if ($WarningOS -and $WarningOS -match "<div class='title'>(Fin de support|Attention)</div>") {
    Add-ActionRecommendation -Category "OS" -Message "Systeme d'exploitation : version en fin de support ou bientot en fin de support - planifier une migration vers une version supportee." -Priority 1
}

# Informations sur l'uptime (utilise l'instance OS déjà chargée si disponible)
if (-not $OSInstance) {
    $OSInstance = Get-CimInstance Win32_OperatingSystem
}
$Uptime = (Get-Date) - $OSInstance.LastBootUpTime

# Action recommandée sur l'uptime (serveur jamais redémarré depuis longtemps)
if ($Uptime.Days -ge 90) {
    Add-ActionRecommendation -Category "Uptime" -Message "Uptime : le serveur n'a pas ete redemarre depuis $($Uptime.Days) jours - planifier un redemarrage controle (apres verification des mises a jour et sauvegardes)." -Priority 2
}

# Informations CPU et RAM
$CPUInfo = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1 Name
$CPUName = $CPUInfo.Name
$TotalCores = (Get-CimInstance -ClassName Win32_Processor | Measure-Object -Property NumberOfCores -Sum).Sum
$TotalThreads = (Get-CimInstance -ClassName Win32_Processor | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
$RAM = Get-CimInstance -ClassName Win32_ComputerSystem

# Informations sur les disques locaux
$Disks = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object DriveType -eq 3

# Informations reseau
$nic = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.IPv4Address } | Select-Object -First 1

if ($nic) {
    $IP         = $nic.IPv4Address.IPAddress
    $SubnetMask = $nic.IPv4Address.PrefixLength
    $Gateway    = $nic.IPv4DefaultGateway.NextHop
    $DnsServers = (Get-DnsClientServerAddress -InterfaceIndex $nic.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
} else {
    $IP = $SubnetMask = $Gateway = "Non détecté"
    $DnsServers = @("Non configuré")
}

# Mise en forme
$DnsServersHtml = ($DnsServers -join '<br>')

# Recommandation DNS basique (DNS publics connus)
if (($RecommendationContext.IsDomainJoined -or $RecommendationContext.IsDomainController -or $RecommendationContext.IsMemberServer) -and $DnsServers -and ($DnsServers -contains "8.8.8.8" -or $DnsServers -contains "1.1.1.1" -or $DnsServers -contains "8.8.4.4")) {
    Add-ActionRecommendation -Category "DNS" -Message "DNS : serveur configure avec des DNS publics (ex. 8.8.8.8 / 1.1.1.1) - sur un serveur membre/AD, privilegier des DNS internes pour l'authentification et la resolution AD." -Priority 2
}

# Détection simple d'un rôle "serveur de fichiers" (partages non administratifs)
try {
    $SmbShares = Get-SmbShare -ErrorAction Stop
    if ($SmbShares) {
        $dataShares = $SmbShares | Where-Object {
            $_.ShareType -eq 'FileSystem' -and                      # exclut les partages d'imprimantes
            $_.Name -notin @('ADMIN$', 'C$', 'D$', 'E$', 'IPC$') -and
            ($_.Path -and $_.Path -notlike '*\System32\spool*')     # sécurité supplémentaire pour print$
        }
        if ($dataShares.Count -gt 0) {
            $IsFileServer = $true
            $FileSharesInfo = $dataShares | Select-Object Name, Path, Description
        }
    }
} catch {
    # Get-SmbShare peut ne pas être disponible (anciennes versions / rôles non installés) ; on ignore
}
Set-MreSection -Name 'fileShares' -Value @($FileSharesInfo | Where-Object { $_ } | ForEach-Object { [ordered]@{ name = $_.Name; path = $_.Path; description = $_.Description } })

# Vérification de la synchro horaire / NTP
$mreTime = [ordered]@{ serviceStatus = $null; source = $null; lastSync = $null; stratum = $null; isPdcEmulator = $null }
try {
    if (-not ($RecommendationContext.IsDomainJoined -or $RecommendationContext.IsDomainController -or $RecommendationContext.IsMemberServer)) {
        throw 'Contexte standalone: recommandations Time Sync detaillees ignorees.'
    }

    $timeService = Get-Service -Name w32time -ErrorAction SilentlyContinue
    if ($timeService) { $mreTime.serviceStatus = [string]$timeService.Status }
    if ($timeService -and $timeService.Status -ne 'Running') {
        Add-ActionRecommendation -Category "TimeSync" -Message "Time Sync : le service de temps Windows (w32time) n'est pas demarre - le demarrer et verifier la configuration de synchronisation temporelle." -Priority 2
    }

    $w32tmOutput = & w32tm /query /status 2>$null
    if ($LASTEXITCODE -eq 0 -and $w32tmOutput) {
        $lines = $w32tmOutput -split "`r?`n"
        $sourceLine = $lines | Where-Object { $_ -match '^\s*Source' } | Select-Object -First 1
        if ($sourceLine) {
            $timeSource = ($sourceLine -split ':',2)[1].Trim()
            $mreTime.source = $timeSource
            if ($timeSource -match 'Local CMOS Clock|Free-running System Clock') {
                Add-ActionRecommendation -Category "TimeSync" -Message "Time Sync : aucune source NTP externe fiable detectee (source actuelle : '$timeSource') - configurer une source NTP appropriee (DC/serveur NTP)." -Priority 2
            }
        }
    }
    # Champs complementaires pour le JSON (libelles w32tm en anglais ou en francais)
    if ($w32tmOutput) {
        $stratumLine = $w32tmOutput | Where-Object { $_ -match '^\s*(Stratum|Strate)\s*:' } | Select-Object -First 1
        if ($stratumLine -and $stratumLine -match ':\s*(\d+)') { $mreTime.stratum = [int]$matches[1] }
        $syncLine = $w32tmOutput | Where-Object { $_ -match '^\s*(Last Successful Sync Time|Heure de la derni.re synchronisation)' } | Select-Object -First 1
        if ($syncLine) { $mreTime.lastSync = ($syncLine -split ':',2)[1].Trim() }
    }
    if ($RecommendationContext.IsDomainController) {
        try {
            $pdc = (Get-ADDomain -ErrorAction Stop).PDCEmulator
            $mreTime.isPdcEmulator = ($pdc -split '\.')[0] -ieq $env:COMPUTERNAME
        } catch { }
    }
} catch {
    # w32tm peut ne pas être disponible dans certains contextes, on ignore silencieusement
}
Set-MreSection -Name 'timeSync' -Value $mreTime

# Vérification Secure Boot (KB 5068202 - mises à jour certificats UEFI CA 2023)
# Réf. : https://support.microsoft.com/en-au/topic/registry-key-updates-for-secure-boot-windows-devices-with-it-managed-updates-a7be69c9-4634-42e1-9ca1-df06f827cf0
try {
    $secureBootBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
    $secureBootServicing = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"
    $secureBootEnabled = $null
    try {
        # Retourne True/False sur plateforme UEFI; peut lever une exception sinon.
        $secureBootEnabled = Confirm-SecureBootUEFI -ErrorAction Stop
    } catch {
        $secureBootEnabled = $null
    }

    if (Test-Path $secureBootServicing) {
        $uefiStatus = Get-ItemProperty -Path $secureBootServicing -Name "UEFICA2023Status" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty UEFICA2023Status
        $uefiError = Get-ItemProperty -Path $secureBootServicing -Name "UEFICA2023Error" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty UEFICA2023Error
        $availableUpdates = Get-ItemProperty -Path $secureBootBase -Name "AvailableUpdates" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AvailableUpdates

        if ($null -eq $uefiError) { $uefiError = 0 }
        if ($uefiError -ne 0) {
            Add-ActionRecommendation -Category "SecureBoot" -Message "Secure Boot (UEFI CA 2023) : erreur de deploiement (UEFICA2023Error = $uefiError) - consulter les journaux d'evenements Windows (Secure Boot DB/DBX) et la KB 5068202 pour diagnostiquer et corriger." -Priority 1
        }
        elseif ($uefiStatus -eq "NotStarted") {
            if ($RecommendationContext.IsVirtualMachine) {
                # Sur VM, le workflow UEFI CA 2023 genere souvent des faux positifs operationnels.
            }
            elseif ($secureBootEnabled -eq $true) {
                Add-ActionRecommendation -Category "SecureBoot" -Message "Secure Boot (UEFI CA 2023) : Secure Boot actif, mais mise a jour des certificats non demarree - sur ce poste gere IT, executer en admin : reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x5944 /f puis Start-ScheduledTask -TaskName '\\Microsoft\\Windows\\PI\\Secure-Boot-Update'. Redemarrer si necessaire (AvailableUpdates passe a 0x4000). Ref. KB 5068202." -Priority 2
            } elseif ($secureBootEnabled -eq $false) {
                Add-ActionRecommendation -Category "SecureBoot" -Message "Secure Boot (UEFI CA 2023) : Secure Boot desactive - activer Secure Boot dans le BIOS/UEFI avant d'appliquer la procedure de mise a jour des certificats (KB 5068202)." -Priority 1
            } else {
                Add-ActionRecommendation -Category "SecureBoot" -Message "Secure Boot (UEFI CA 2023) : mise a jour des certificats non demarree et etat Secure Boot indetermine - verifier si Secure Boot est actif (Confirm-SecureBootUEFI / BIOS-UEFI), puis appliquer la procedure KB 5068202." -Priority 2
            }
        }
        elseif ($uefiStatus -eq "InProgress") {
            $avHex = if ($null -ne $availableUpdates) { ('0x{0:X4}' -f [uint32]$availableUpdates) } else { 'N/A' }
            Add-ActionRecommendation -Category "SecureBoot" -Message "Secure Boot (UEFI CA 2023) : deploiement en cours (UEFICA2023Status = InProgress, AvailableUpdates = $avHex) - attendre la fin du traitement ou redemarrer puis relancer la tache planifiee Secure-Boot-Update si besoin. Ref. KB 5068202." -Priority 3
        }
        # Si "Updated" et erreur 0 : rien à recommander
    } else {
        # Clés absentes : soit la mise à jour Windows qui les apporte n'est pas installée, soit l'appareil n'est pas éligible
        # KB 5068202 : éligible = Windows 10 22H2+ (build 19045+), Windows 11 (build 22000+), Server 2022+ (build 20348+)
        $build = [int]($OSInstance.BuildNumber)
        $caption = $OSInstance.Caption
        $isEligible = ($build -ge 19045 -and $caption -like "*Windows 10*") -or
                      ($build -ge 22000 -and $caption -like "*Windows 11*") -or
                      ($build -ge 20348 -and $caption -like "*Windows Server*")
        if ($isEligible -and -not $RecommendationContext.IsVirtualMachine) {
            Add-ActionRecommendation -Category "SecureBoot" -Message "Secure Boot (UEFI CA 2023) : cles de registre absentes sur cet appareil eligible (Windows 10 22H2+ / 11 / Server 2022+) - installer les dernieres mises a jour cumulatives pour obtenir les cles et la tache planifiee, puis appliquer la procedure KB 5068202 si vous souhaitez deployer les certificats UEFI CA 2023 (recommande pour les postes geres IT)." -Priority 2
        }
    }
} catch {
    # Lecture impossible ; on n'ajoute pas de recommandation générique
}
Set-MreSection -Name 'secureBoot' -Value ([ordered]@{
    enabled          = $secureBootEnabled
    uefiCa2023Status = $uefiStatus
    uefiCa2023Error  = $uefiError
    availableUpdates = $availableUpdates
})

Write-HostSafe "# ============================="
Write-HostSafe "# Block 2 : Collecte des donnees CPU, RAM, Disques"
Write-HostSafe "# ============================="

# Utilisation moyenne globale du CPU
$CPUUsage = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average


# Informations RAM
# Cacher l'instance OS pour éviter les requêtes redondantes
$OSInstance = Get-CimInstance -Class Win32_OperatingSystem
$TotalRAM = [math]::Round($RAM.TotalPhysicalMemory / 1GB, 2)
# FreePhysicalMemory est en KB, donc conversion: KB -> GB
$FreeRAM = [math]::Round(($OSInstance.FreePhysicalMemory * 1KB) / 1GB, 2)
$UsedRAM = $TotalRAM - $FreeRAM
$UsedRAMPercent = [math]::Round(($UsedRAM / $TotalRAM) * 100, 2)

# Informations disques
# @() force un tableau : sous PowerShell 5.1, un seul [PSCustomObject] n'a pas de .Count,
# ce qui faisait tomber la moyenne a 0% sur les serveurs a un seul disque (v3.3).
$DiskInfo = @($Disks | ForEach-Object {
    $DiskLetter = $_.DeviceID
    $VolumeName = $_.VolumeName
    $TotalSpace = $_.Size
    $FreeSpace = $_.FreeSpace
    $UsedSpace = $TotalSpace - $FreeSpace
    $FreePercent = if ($TotalSpace -ne 0) { ($FreeSpace / $TotalSpace) * 100 } else { 0 }
    $FreePercentRounded = [math]::Round($FreePercent, 2)
    
    [PSCustomObject]@{
        DiskName        = if ($VolumeName) { $VolumeName } else { $DiskLetter }
        UsedSpaceGB     = "{0:N2}" -f ($UsedSpace / 1GB)
        FreeSpaceGB     = "{0:N2}" -f ($FreeSpace / 1GB)
        TotalSpaceGB    = "{0:N2}" -f ($TotalSpace / 1GB)
        FreePercent     = $FreePercentRounded
        FreePercentStr  = "{0:N2}" -f $FreePercentRounded
    }
})

# Calcul de la moyenne d'espace libre disque (pour KPI)
$AvgDiskFreePercent = if ($DiskInfo -and $DiskInfo.Count -gt 0) { 
    [math]::Round((($DiskInfo | ForEach-Object { [double]$_.FreePercent }) | Measure-Object -Average).Average, 2)
} else { 0 }

# Calcul d'un score de sante global (0-100) + explications
$healthSummary = Get-HealthScore -CPUUsage $CPUUsage -UsedRAMPercent $UsedRAMPercent -AvgDiskFreePercent $AvgDiskFreePercent -Thresholds $Config.Thresholds
if ($null -eq $healthSummary -or $null -eq $healthSummary.Score) {
    $HealthScore      = 0
    $HealthLabel      = "Indetermine"
    $HealthBadgeClass = "badge-warning"
    $HealthFindings   = @("Impossible de calculer le score global avec les metriques collectees.")
} else {
    $HealthScore      = $healthSummary.Score
    $HealthLabel      = $healthSummary.Label
    $HealthBadgeClass = $healthSummary.BadgeClass
    $HealthFindings   = $healthSummary.Findings
}

# Proxy WinHTTP (v3.3) : utilise par Windows Update ET par le client WinRM. Sans liste d'exclusion, les
# connexions WinRM/CIM internes partent vers le proxy (HTTP 403) : ADChecker et l'administration a distance cassent.
$mreWinHttpProxy = $null
try {
    $whp = (& netsh winhttp show proxy) -join "`n"
    if ($whp -match '(?im)^\s*(?:Proxy Server\(s\)|Serveur\(s\) proxy)\s*:\s*(\S.*)$') {
        $proxyServer = $matches[1].Trim()
        $bypass = if ($whp -match '(?im)^\s*(?:Bypass List|Liste de contournement)\s*:\s*(\S.*)$') { $matches[1].Trim() } else { '' }
        if ($bypass -match '^\((none|aucun)\)$') { $bypass = '' }
        $mreWinHttpProxy = [ordered]@{ server = $proxyServer; bypass = $bypass }
    } else {
        $mreWinHttpProxy = [ordered]@{ server = ''; bypass = '' }   # acces direct
    }
} catch { }

Set-MreSection -Name 'system' -Value ([ordered]@{
    os          = [ordered]@{ caption = $OS.Caption; version = $OS.Version; build = $OS.BuildNumber }
    lastBoot    = (ConvertTo-IsoDate $OSInstance.LastBootUpTime)
    uptimeDays  = [math]::Round($Uptime.TotalDays, 1)
    cpu         = [ordered]@{ name = $CPUName; cores = $TotalCores; threads = $TotalThreads; loadPercent = $CPUUsage }
    ram         = [ordered]@{ totalGB = $TotalRAM; usedGB = $UsedRAM; usedPercent = $UsedRAMPercent }
    disks       = @($Disks | ForEach-Object {
                      $size = [double]$_.Size; $free = [double]$_.FreeSpace
                      [ordered]@{
                          letter      = $_.DeviceID
                          label       = $_.VolumeName
                          totalGB     = [math]::Round($size / 1GB, 2)
                          freeGB      = [math]::Round($free / 1GB, 2)
                          freePercent = if ($size -gt 0) { [math]::Round(($free / $size) * 100, 2) } else { $null }
                      } })
    network     = [ordered]@{ ip = $IP; prefixLength = $SubnetMask; gateway = $Gateway; dns = @($DnsServers); winhttpProxy = $mreWinHttpProxy }
    health      = [ordered]@{ score = $HealthScore; label = $HealthLabel; findings = @($HealthFindings | ForEach-Object { [System.Net.WebUtility]::HtmlDecode($_) }) }
    # Note : loadPercent est un instantane (LoadPercentage au moment de l'execution), pas une moyenne sur la periode.
})

# Actions recommandées basées sur les KPI globaux
if ($CPUUsage -ge $Config.Thresholds.CPU.Critical) {
    Add-ActionRecommendation -Category "CPU" -Message "CPU : utilisation tres elevee (&gt;= $($Config.Thresholds.CPU.Critical)%) - analyser les processus gourmands et planifier une optimisation." -Priority 1
} elseif ($CPUUsage -ge $Config.Thresholds.CPU.Warning) {
    Add-ActionRecommendation -Category "CPU" -Message "CPU : utilisation elevee (&gt;= $($Config.Thresholds.CPU.Warning)%) - surveiller la charge et verifier les services applicatifs." -Priority 2
}

if ($UsedRAMPercent -ge $Config.Thresholds.RAM.Critical) {
    Add-ActionRecommendation -Category "RAM" -Message "RAM : utilisation critique (&gt;= $($Config.Thresholds.RAM.Critical)%) - envisager d'ajouter de la memoire ou de reduire les services." -Priority 1
} elseif ($UsedRAMPercent -ge $Config.Thresholds.RAM.Warning) {
    Add-ActionRecommendation -Category "RAM" -Message "RAM : utilisation elevee (&gt;= $($Config.Thresholds.RAM.Warning)%) - surveiller et optimiser l'usage memoire." -Priority 2
}

foreach ($disk in $DiskInfo) {
    if ($disk.FreePercent -le $Config.Thresholds.Disk.Critical) {
        Add-ActionRecommendation -Category "Disque" -Message "Disque $($disk.DiskName) : espace libre tres faible (&lt;= $($Config.Thresholds.Disk.Critical)%) - prevoir un nettoyage ou une extension de volume en priorite." -Priority 1
    } elseif ($disk.FreePercent -le $Config.Thresholds.Disk.Warning) {
        Add-ActionRecommendation -Category "Disque" -Message "Disque $($disk.DiskName) : espace libre faible (&lt;= $($Config.Thresholds.Disk.Warning)%) - planifier un nettoyage ou une extension de volume." -Priority 2
    }
}

Write-HostSafe "# ============================="
Write-HostSafe "# Block 3 : Collecte et formatage des journaux d'evenements"
Write-HostSafe "# ============================="

# Fonction pour recuperer et formater les journaux d'evenements
function Get-FormattedEventLogs {
    param (
        [string]$LogName,
        [string]$FilterXPath,
        [string]$Title,
        [string]$PostContent
    )

    $events = Get-WinEvent -LogName $LogName -FilterXPath $FilterXPath -ErrorAction SilentlyContinue

    if ($events) {
        # Actions recommandées basées sur le volume d'erreurs
        $errCount = $events.Count
        if ($LogName -eq "System" -and $errCount -gt 100) {
            Add-ActionRecommendation -Category "EventLog" -Message "Journaux Systeme : plus de $errCount evenements (Error/Warning/Critical) sur 30 jours - analyser en priorite les erreurs systeme." -Priority 2
        } elseif ($LogName -eq "Application" -and $errCount -gt 100) {
            Add-ActionRecommendation -Category "EventLog" -Message "Journaux Application : plus de $errCount evenements (Error/Warning/Critical) sur 30 jours - verifier les applications concernees." -Priority 2
        }

        $grouped = @($events | Group-Object Id, ProviderName |
               Select-Object @{Name='ProviderName';Expression={$_.Group[0].ProviderName}},
                             @{Name='Id';Expression={$_.Group[0].Id}},
                             @{Name='Level';Expression={$_.Group[0].LevelDisplayName}},
                             @{Name='Count';Expression={$_.Count}},
                             @{Name='Last';Expression={($_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated}},
                             @{Name='Sample';Expression={
                                 $m = ($_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).Message
                                 if ($m) { $m = ($m -split "`r?`n")[0]; if ($m.Length -gt 200) { $m = $m.Substring(0,200) } }
                                 $m
                             }} |
               Sort-Object Count -Descending)

        # 15 groupes au plus par journal : le JSON doit tenir dans un custom field NinjaOne
        $script:MreEventLogs[$LogName] = [ordered]@{
            total       = @($events).Count
            groupsTotal = @($grouped).Count
            groups = @($grouped | Select-Object -First 15 | ForEach-Object {
                [ordered]@{ provider = $_.ProviderName; id = $_.Id; level = $_.Level; count = $_.Count; last = (ConvertTo-IsoDate $_.Last); sample = $_.Sample }
            })
        }

        return $grouped | Select-Object ProviderName, Id, Count |
               ConvertTo-HTML -Fragment -PreContent "<h3>$Title</h3>" -PostContent $PostContent
    } else {
        $script:MreEventLogs[$LogName] = [ordered]@{ total = 0; groups = @() }
        return "<h3>$Title</h3><p>Aucun evenement trouve dans les 30 derniers jours</p>"
    }
}

# Verification des journaux d'evenements
$script:MreEventLogs = [ordered]@{}
$ApplicationEvent = Get-FormattedEventLogs -LogName "Application" `
                                            -FilterXPath "*[System[(Level=1 or Level=2 or Level=3) and TimeCreated[timediff(@SystemTime) <= 2592000000]]]" `
                                            -Title "Evenements Application" `
                                            -PostContent "<p>Evenements sur les 30 derniers jours</p>"

$SystemEvent = Get-FormattedEventLogs -LogName "System" `
                                        -FilterXPath "*[System[(Level=1 or Level=2 or Level=3) and TimeCreated[timediff(@SystemTime) <= 2592000000]]]" `
                                        -Title "Evenements Systeme" `
                                        -PostContent "<p>Evenements sur les 30 derniers jours</p>"
Set-MreSection -Name 'eventLogs' -Value ([ordered]@{ periodDays = 30; levels = 'Critical,Error,Warning'; logs = $script:MreEventLogs })

# Verification de l'evenement ID 4625
$start = (Get-Date).AddDays(-30)
$events4625 = Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4625; StartTime=$start} -ErrorAction SilentlyContinue

$resultArray = @()

if ($events4625) {
    foreach ($evt in $events4625) {
        $eventXml = [xml]$evt.ToXml()
        $eventArray = @{}
        $eventXml.Event.EventData.Data | 
            Where-Object {$_.name -in @("TargetUserName", "Status", "WorkstationName", "IpAddress", "LogonType")} | 
            ForEach-Object { $eventArray[$_.name] = $_.'#text' }

        $systemObject = $eventXml.Event.System | Select-Object EventID, @{N="TimeCreated";E={($_.TimeCreated).SystemTime}}

        $combinedObject = New-Object -TypeName PSObject
        foreach ($property in $eventArray.Keys) {
            $combinedObject | Add-Member -MemberType NoteProperty -Name $property -Value $eventArray[$property]
        }
        foreach ($property in $systemObject.psobject.Properties) {
            $combinedObject | Add-Member -MemberType NoteProperty -Name $property.Name -Value $property.Value
        }
        $resultArray += $combinedObject
    }

    $groupedResults = $resultArray | Group-Object TargetUserName
    $event4625count = $groupedResults | Select-Object Name, Count
    $mre4625 = @($groupedResults | Sort-Object Count -Descending | ForEach-Object {
        [ordered]@{
            account      = $_.Name
            count        = $_.Count
            last         = (ConvertTo-IsoDate (($_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated))
            sources      = @($_.Group | Group-Object IpAddress, WorkstationName | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
                               [ordered]@{ ip = $_.Group[0].IpAddress; workstation = $_.Group[0].WorkstationName; count = $_.Count } })
            logonTypes   = @($_.Group | Group-Object LogonType | ForEach-Object { [ordered]@{ type = $_.Name; count = $_.Count } })
        }
    })
    $eventsDirPath = Join-Path $Config.OutputPath "events"
    $events4625HTML = $event4625count | ConvertTo-HTML -Fragment -PreContent "<h3>Evenement 4625</h3>" -PostContent "<p>Les details de l'evenement peuvent etre trouves dans $eventsDirPath</p>"

    # Action recommandée si beaucoup d'échecs de connexion
    $total4625 = ($event4625count | Measure-Object -Property Count -Sum).Sum
    if ($total4625 -gt 0) {
        Add-ActionRecommendation -Category "Securite" -Message "Securite : $total4625 tentatives de connexion echouees (event 4625) sur les 30 derniers jours - verifier les comptes concernes et les origines des connexions." -Priority 1
    }
} else {
    $events4625HTML = "<h3>Evenement 4625</h3><p>Aucun evenement n'est present pendant la periode demandee (30 jours)</p>"
    $mre4625 = @()
}
Set-MreSection -Name 'failedLogons' -Value ([ordered]@{ periodDays = 30; total = @($resultArray).Count; accounts = $mre4625 })

# Création du répertoire + export CSV maintenant que $resultArray est rempli
$eventsDir = Join-Path $reportPath 'events'
try {
    if (-not (Test-Path $eventsDir)) { 
        New-Item -ItemType Directory -Path $eventsDir -ErrorAction Stop | Out-Null 
    }
    if ($resultArray -and $resultArray.Count -gt 0) {
        $resultArray | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $eventsDir "logonfail_$(Get-Date -Format yyyyMMdd).csv") -ErrorAction Stop
        Write-HostSafe "# Export CSV des evenements 4625 termine."
    }
} catch {
    Write-Warning "Erreur lors de l'export CSV des evenements 4625 : $($_.Exception.Message)"
}

# Verification de l'evenement ID 2004 (Ressources du serveur)
$event2004 = Get-WinEvent -FilterHashtable @{logname="System"; id=2004} -ErrorAction SilentlyContinue | 
              Select-Object -Unique | 
              Select-Object TimeCreated, ID, LevelDisplayName, Message
Set-MreSection -Name 'resourceExhaustion' -Value ([ordered]@{
    count  = @($event2004).Count
    events = @($event2004 | Sort-Object TimeCreated -Descending | Select-Object -First 10 | ForEach-Object {
        [ordered]@{ time = (ConvertTo-IsoDate $_.TimeCreated); message = (($_.Message -split "`r?`n")[0]) } })
})

if ($event2004) {
    $events2004 = $event2004 | ConvertTo-HTML -Fragment -PreContent "<h3>Evenement 2004</h3>"

    # Action recommandée en cas d'épuisement de ressources (ID 2004)
    $count2004 = @($event2004).Count
    if ($count2004 -gt 0) {
        Add-ActionRecommendation -Category "Ressources" -Message "Ressources : $count2004 evenement(s) 2004 (Resource Exhaustion) dans le journal Systeme - analyser les processus gourmands et la configuration memoire/disque." -Priority 1
    }
} else {
    $events2004 = "<h3>Evenement 2004</h3><p>Aucun evenement n'est present concernant les ressources du serveur</p>"
}

Write-HostSafe "# ============================="
Write-HostSafe "# Block 4 : Verification des applications installes"
Write-HostSafe "# ============================="

# Recommandation sur les membres du groupe Administrateurs local
try {
    if ($RecommendationContext.IsDomainController) {
        throw 'Controleur de domaine: recommandation groupe Administrators local ignoree.'
    }

    $localAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
    # On ignore les comptes/groupe système classiques
    $knownAdminPatterns = @(
        '^BUILTIN\\Administrators$',
        '^NT AUTHORITY\\SYSTEM$',
        '^NT AUTHORITY\\Local Service$',
        '^NT AUTHORITY\\Network Service$',
        'Domain Admins',
        'Enterprise Admins'
    )
    $suspiciousAdmins = $localAdmins | Where-Object {
        $name = $_.Name
        -not ($knownAdminPatterns | ForEach-Object { $name -match $_ })
    }
    if ($suspiciousAdmins.Count -gt 5) {
        $ActionRecommendations += "Sécurité locale : plus de 5 comptes/groupes non standards dans le groupe Administrators local - revoir les membres du groupe Administrators et limiter les accès."
    }
} catch {
    # Sur certains systèmes, Get-LocalGroupMember peut ne pas être disponible ; on ignore silencieusement
}

#Check des logiciels
#Derniere versions des softs 
$software = "7-Zip", "Adobe", "Chrome", "Edge", "FileZilla", "Firefox", "Greenshot", "Java", "Lansweeper", "Microsoft 365 Apps", "Microsoft Azure AD Connect", "Microsoft Entra Connect Sync", "Notepad++", "PuTTY", "Veeam Backup & Replication", "Veeam Backup for Microsoft 365", "VMware Tools", "WinRAR", "WinSCP"

if ($HasInternet) {
    # TLS deja configure en haut du script
    $Web = Invoke-WebRequest -UseBasicParsing -Uri "https://ninite.com/news" -TimeoutSec 30
} else {
    Write-HostSafe "# Pas d'acces Internet detecte, verification Ninite/versions des logiciels ignoree."
    $Web = $null
}
$versionsPath = Join-Path $Config.OutputPath "versions.txt"
if ($Web) {
    $Web.content > $versionsPath
    $versions = Get-Content $versionsPath -raw
} else {
    $versions = ""
}

$versions = $versions -replace '<[^>]+>',''
$versions = $versions -replace 'bout|press|updates|security|terms|privacy|jobs|&copy; Secure by Design Inc',''
$versions = $versions -replace '<[^>]+>',''
$versions = $versions -split "`r?`n" | Where-Object { $_.Trim() -ne '' } | Select-Object -Skip 7
$versions = $versions -replace 'updated to','%'
# Separation des lignes en utilisant le caractere de saut de ligne
$lines = $versions -split "`r?`n"
# Filtrage des lignes contenant le caractere '%'
$filteredLines = $lines | Where-Object { $_ -match '%' }
# Reconstitution de la variable avec les lignes filtrees
$versions = $filteredLines -join "`r`n"

foreach ($version in $versions){
$versions = $version -split '%'
}

# Separation des valeurs en utilisant le caractere de saut de ligne
$values = $versions -split "`r?`n"

# Tableau pour stocker les valeurs en deux colonnes
$tableau = @()

# Parcourir les valeurs et les ajouter au tableau en deux colonnes
for ($i = 0; $i -lt $values.Count; $i += 2) {
    $colonne1 = $values[$i]
    $colonne2 = $values[$i + 1]
    $tableau += [PsCustomObject]@{
        Soft = $colonne1
        Version = $colonne2
    }
}

$filteredVersions = @()

foreach ($logiciel in $software) {
    $filteredVersion = $tableau | Where-Object { $_.Soft -like "*$logiciel*" } | Sort-Object -Property Version -Descending | Select-Object -First 1
    if ($filteredVersion) {
        $filteredVersions += $filteredVersion
    }
}

if ($filteredVersions.Count -gt 0) {
    $LastVersions = $filteredVersions | ConvertTo-Html -Fragment -PreContent "<h2>Check Logiciels</h2><h3>Derniere versions des logiciels</h3>"
} else {
    $LastVersions = "<h2>Check Logiciels</h2><h3>Derniere versions des logiciels</h3><p>Aucune version en ligne detectee.</p>"
}


#Soft installes sur le serveur
# HKCU n'a pas de cle Uninstall sous le compte System (NinjaOne) : erreur affichee sans incidence, on la tait (v3.4.1)
$Appslist = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall","HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall","HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue | Get-ItemProperty -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion

$filteredApps = @()  # Tableau vide
$veeamExcludedModulesPattern = '(?i)(proxmox|ovirt|google\s*cloud|gcp|kasten|aws|amazon\s+web\s+services)'

foreach ($soft in $software) {
    $filtered = $Appslist | Where-Object { $_.DisplayName -like "*$soft*" }
    if ($soft -like "Veeam*") {
        $filtered = $filtered | Where-Object { $_.DisplayName -notmatch $veeamExcludedModulesPattern }
    }
    $filtered = @($filtered | Sort-Object DisplayName, DisplayVersion -Unique)

    if ($filtered.Count -gt 0) {
        $filteredApps += $filtered
    }
}

if ($filteredApps.Count -gt 0) {
    $CommunSoft = $filteredApps | Sort-Object DisplayName | Select-Object DisplayName, DisplayVersion | ConvertTo-Html -Fragment -PreContent "<h3>Logiciels installes</h3>"
} else {
    $CommunSoft = "<h3>Logiciels installes</h3><p>Aucune application cible detectee sur ce serveur.</p>"
}

Set-MreSection -Name 'software' -Value ([ordered]@{
    tracked = @($filteredApps | Sort-Object DisplayName | ForEach-Object {
        [ordered]@{ name = $_.DisplayName; version = $_.DisplayVersion; publisher = $_.Publisher } })
    latestKnown = @($filteredVersions | ForEach-Object { $_ })
})

#Report commun check
$htmlapps = ConvertTo-HTML -Body "$LastVersions $CommunSoft" -Title "Computer Information Report"

# Vérification des applications EOL et outils d'accès distant
if ($Appslist) {
    # Versions EOL connues
    $eolPatterns = @{
        "SQL Server 2008" = "SQL Server 2008"
        "SQL Server 2012" = "SQL Server 2012"
        "Microsoft SQL Server 2008" = "SQL Server 2008"
        "Microsoft SQL Server 2012" = "SQL Server 2012"
        "Microsoft Exchange Server 2010" = "Exchange 2010"
        "Microsoft Exchange Server 2013" = "Exchange 2013"
        "Microsoft Office 2010" = "Office 2010"
        "Microsoft Office Professional 2010" = "Office 2010"
    }
    
    $eolFound = @()
    foreach ($app in $Appslist) {
        if ($app.DisplayName) {
            foreach ($pattern in $eolPatterns.Keys) {
                if ($app.DisplayName -like "*$pattern*") {
                    $eolFound += $eolPatterns[$pattern]
                    break
                }
            }
        }
    }
    
    if ($eolFound.Count -gt 0) {
        $uniqueEol = ($eolFound | Select-Object -Unique) -join ', '
        $ActionRecommendations += "Applications : versions en fin de support détectées ($uniqueEol) - planifier une migration/upgrade vers des versions supportées."
    }
    
    # Détection .NET Framework très anciens (v2.0, v3.0, v3.5 sans SP)
    $dotNetOld = $Appslist | Where-Object {
        $_.DisplayName -match "Microsoft \.NET Framework (2\.0|3\.0|3\.5)" -and
        $_.DisplayName -notmatch "Service Pack|SP"
    }
    if ($dotNetOld.Count -gt 0) {
        $ActionRecommendations += "Applications : versions anciennes de .NET Framework détectées (v2.0/3.0/3.5 sans SP) - envisager une mise à jour vers des versions supportées."
    }
    
    # Outils d'accès distant
    $remoteTools = @("TeamViewer", "AnyDesk", "VNC", "UltraVNC", "TightVNC", "RealVNC", "LogMeIn", "GoToMyPC")
    $remoteFound = @()
    foreach ($app in $Appslist) {
        if ($app.DisplayName) {
            foreach ($tool in $remoteTools) {
                if ($app.DisplayName -like "*$tool*") {
                    $remoteFound += $tool
                    break
                }
            }
        }
    }
    
    if ($remoteFound.Count -gt 0 -and -not $RecommendationContext.IsDomainController) {
        $uniqueRemote = ($remoteFound | Select-Object -Unique) -join ', '
        Add-ActionRecommendation -Category "Securite" -Message "Outils d'acces distant detectes ($uniqueRemote) - verifier que leur presence est justifiee pour le role de ce serveur (bastion / support / administration) et que les acces sont controles." -Priority 3
    }
}

Write-HostSafe "# ============================="
Write-HostSafe "# Block 5 : Verification de l'antivirus"
Write-HostSafe "# ============================="

function Get-NormalizedAntivirusProductName {
    param(
        [string]$ProductName
    )

    if ([string]::IsNullOrWhiteSpace($ProductName)) {
        return $null
    }

    $name = $ProductName.Trim()
    switch -Regex ($name) {
        'bitdefender' { return 'Bitdefender' }
        'crowdstrike|csfalcon' { return 'CrowdStrike Falcon' }
        'windows defender|microsoft defender antivirus|windefend|msmpeng' { return 'Windows Defender' }
        'defender for endpoint|microsoft defender for endpoint|\bsense\b' { return 'Microsoft Defender for Endpoint' }
        'symantec|sep' { return 'Symantec Endpoint Protection' }
        default { return $name }
    }
}

function Get-AntivirusSignals {
    $results = @()

    $avIncludePattern = '(?i)(bitdefender|crowdstrike|csfalcon|symantec|sep|windows defender|microsoft defender antivirus|endpoint protection|endpoint security|antivirus)'
    $avExcludePattern = '(?i)^(security update|update for)|\(KB\d{6,8}\)|microsoft\s+(office|access|excel|word|powerpoint|publisher|visio|project)|asp\.net|\.net\s+framework|cumulative update|hotfix'

    try {
        $scProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction Stop
        foreach ($p in $scProducts) {
            $results += [PSCustomObject]@{
                Methode = "CIM SecurityCenter2"
                Produit = $p.displayName
                ProduitNormalise = Get-NormalizedAntivirusProductName -ProductName $p.displayName
                Version = "N/A"
                Statut  = "Declare"
            }
        }
    } catch {
        # Normal sur de nombreux serveurs: namespace absent
    }

    $regPaths = @(
        "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    foreach ($path in $regPaths) {
        $hive = $null
        $key = $null
        try {
            $hive = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
            $key = $hive.OpenSubKey($path)
            if ($key) {
                $key.GetSubKeyNames() | ForEach-Object {
                    $subKey = $key.OpenSubKey($_)
                    if ($subKey) {
                        $productName = $subKey.GetValue("DisplayName")
                        if (
                            $productName -and
                            ($productName -match $avIncludePattern) -and
                            -not ($productName -match $avExcludePattern)
                        ) {
                            $results += [PSCustomObject]@{
                                Methode = "Registre (Uninstall)"
                                Produit = $productName
                                ProduitNormalise = Get-NormalizedAntivirusProductName -ProductName $productName
                                Version = if ($subKey.GetValue("DisplayVersion")) { $subKey.GetValue("DisplayVersion") } else { "N/A" }
                                Statut  = "Installe"
                            }
                        }
                    }
                }
            }
        } catch {
            Write-Log -Message "Erreur detection antivirus via registre ($path): $($_.Exception.Message)" -Level 'WARN'
        } finally {
            if ($key) { $key.Close() }
            if ($hive) { $hive.Close() }
        }
    }

    $avServices = @{
        "WinDefend"          = "Windows Defender"
        "Sense"              = "Microsoft Defender for Endpoint"
        "BDEService"         = "Bitdefender"
        "EPProtectedService" = "Bitdefender"
        "EPSecurityService"  = "Bitdefender"
        "SepMasterService"   = "Symantec Endpoint Protection"
        "CSFalconService"    = "CrowdStrike Falcon"
    }

    foreach ($service in $avServices.Keys) {
        try {
            $s = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($s) {
                $results += [PSCustomObject]@{
                    Methode = "Service"
                    Produit = $avServices[$service]
                    ProduitNormalise = Get-NormalizedAntivirusProductName -ProductName $avServices[$service]
                    Version = "N/A"
                    Statut  = [string]$s.Status
                }
            }
        } catch {
            Write-Log -Message "Erreur verification service AV $service : $($_.Exception.Message)" -Level 'WARN'
        }
    }

    $avProcesses = @{
        "MsMpEng"            = "Windows Defender"
        "NisSrv"             = "Windows Defender"
        "bdagent"            = "Bitdefender"
        "bdservicehost"      = "Bitdefender"
        "EPConsole"          = "Bitdefender"
        "EPProtectedService" = "Bitdefender"
        "ccSvcHst"           = "Symantec"
        "CSFalconContainer"  = "CrowdStrike Falcon"
    }

    try {
        Get-Process -ErrorAction Stop | ForEach-Object {
            if ($avProcesses.ContainsKey($_.ProcessName)) {
                $version = "N/A"
                if ($_.Path -and (Test-Path $_.Path -ErrorAction SilentlyContinue)) {
                    try {
                        $version = (Get-Item $_.Path -ErrorAction Stop).VersionInfo.FileVersion
                    } catch {
                        $version = "Acces refuse"
                    }
                }
                $results += [PSCustomObject]@{
                    Methode = "Processus"
                    Produit = $avProcesses[$_.ProcessName]
                    ProduitNormalise = Get-NormalizedAntivirusProductName -ProductName $avProcesses[$_.ProcessName]
                    Version = $version
                    Statut  = "En cours"
                }
            }
        }
    } catch {
        Write-Log -Message "Erreur detection antivirus via processus: $($_.Exception.Message)" -Level 'WARN'
    }

    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
        $results += [PSCustomObject]@{
            Methode = "PowerShell (Defender)"
            Produit = "Windows Defender"
            ProduitNormalise = "Windows Defender"
            Version = $defenderStatus.AMProductVersion
            Statut  = if ($defenderStatus.AntivirusEnabled) { "Actif" } else { "Inactif" }
        }
    } catch {
        try {
            $service = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
            if ($service) {
                $results += [PSCustomObject]@{
                    Methode = "Service (Defender)"
                    Produit = "Windows Defender"
                    ProduitNormalise = "Windows Defender"
                    Version = "N/A"
                    Statut  = [string]$service.Status
                }
            }
        } catch {
            Write-Log -Message "Erreur detection Defender: $($_.Exception.Message)" -Level 'WARN'
        }
    }

    try {
        $csService = Get-Service -Name "CSFalconService" -ErrorAction SilentlyContinue
        if ($csService) {
            $csVersion = "N/A"
            try {
                $csVersion = (Get-ItemProperty "HKLM:\SOFTWARE\CrowdStrike\" -ErrorAction SilentlyContinue).Version
            } catch {}

            $results += [PSCustomObject]@{
                Methode = "Service (CrowdStrike)"
                Produit = "CrowdStrike Falcon"
                ProduitNormalise = "CrowdStrike Falcon"
                Version = if ($csVersion) { $csVersion } else { "N/A" }
                Statut  = [string]$csService.Status
            }
        }
    } catch {
        Write-Log -Message "Erreur detection CrowdStrike: $($_.Exception.Message)" -Level 'WARN'
    }

    return $results
}

function ConvertTo-AntivirusSummary {
    param(
        [object[]]$Signals
    )

    $antivirusSummary = @()
    if (-not $Signals -or $Signals.Count -eq 0) {
        return $antivirusSummary
    }

    $allowedProducts = @(
        'Bitdefender',
        'CrowdStrike Falcon',
        'Symantec Endpoint Protection',
        'Windows Defender'
    )

    $signals = $Signals | Where-Object {
        $_.ProduitNormalise -in $allowedProducts -or $_.ProduitNormalise -eq 'Microsoft Defender for Endpoint'
    }
    $signals = $signals | Where-Object { $_.ProduitNormalise -ne 'Microsoft Defender for Endpoint' }

    $groups = $signals |
        Where-Object { $_.ProduitNormalise } |
        Group-Object -Property ProduitNormalise

    $thirdPartyInstalledProducts = @()
    foreach ($previewGroup in $groups) {
        if ($previewGroup.Name -ne 'Windows Defender') {
            $previewRows = $previewGroup.Group
            $previewInstalled = @($previewRows | Where-Object { $_.Methode -match '^Registre \(Uninstall\)$' }).Count -gt 0
            if (-not $previewInstalled) {
                $previewInstalled = @($previewRows | Where-Object { $_.Statut -match 'Running|En cours|Actif' }).Count -gt 0
            }
            if ($previewInstalled) {
                $thirdPartyInstalledProducts += $previewGroup.Name
            }
        }
    }

    foreach ($g in $groups) {
        $productRows = $g.Group
        $versionInstalled = $null
        $versionSource = $null

        $registryVersion = $productRows |
            Where-Object { $_.Methode -match '^Registre \(Uninstall\)$' -and $_.Version -and $_.Version -ne 'N/A' } |
            Select-Object -First 1
        if ($registryVersion) {
            $versionInstalled = $registryVersion.Version
            $versionSource = 'Registre'
        }

        if (-not $versionInstalled -and $g.Name -eq 'Windows Defender') {
            $defVersion = $productRows |
                Where-Object { $_.Methode -match 'PowerShell \(Defender\)' -and $_.Version -and $_.Version -ne 'N/A' } |
                Select-Object -First 1
            if ($defVersion) {
                $versionInstalled = $defVersion.Version
                $versionSource = 'PowerShell Defender'
            }
        }

        if (-not $versionInstalled -and $g.Name -eq 'CrowdStrike Falcon') {
            $csVersion = $productRows |
                Where-Object { $_.Methode -match 'CrowdStrike' -and $_.Version -and $_.Version -ne 'N/A' } |
                Select-Object -First 1
            if ($csVersion) {
                $versionInstalled = $csVersion.Version
                $versionSource = 'Registre/Service CrowdStrike'
            }
        }

        $hasRegistryInstall = @($productRows | Where-Object { $_.Methode -match '^Registre \(Uninstall\)$' }).Count -gt 0
        $hasDefenderInstall = $g.Name -eq 'Windows Defender' -and @($productRows | Where-Object { $_.Methode -match 'Defender|WinDefend' }).Count -gt 0
        $hasCrowdStrikeInstall = $g.Name -eq 'CrowdStrike Falcon' -and @($productRows | Where-Object { $_.Methode -match 'CrowdStrike|CSFalconService' }).Count -gt 0
        $hasRuntimeEvidence = @($productRows | Where-Object { $_.Statut -match 'Running|En cours|Actif' }).Count -gt 0

        $isInstalled = $false
        if ($hasRegistryInstall -or $hasDefenderInstall -or $hasCrowdStrikeInstall) {
            $isInstalled = $true
        } elseif ($g.Name -ne 'Windows Defender' -and $versionInstalled -and $versionInstalled -ne 'N/A') {
            $isInstalled = $true
        } elseif ($g.Name -ne 'Windows Defender' -and $hasRuntimeEvidence) {
            $isInstalled = $true
        }

        $protectionState = 'Inconnu'
        if (@($productRows | Where-Object { $_.Statut -match 'Actif|Running|En cours' }).Count -gt 0) {
            $protectionState = 'Actif'
        } elseif (@($productRows | Where-Object { $_.Statut -match 'Inactif|Stopped|StopPending' }).Count -gt 0) {
            $protectionState = 'Inactif'
        }

        if ($g.Name -eq 'Windows Defender' -and $thirdPartyInstalledProducts.Count -gt 0) {
            $protectionState = 'Dormant'
        } elseif ($g.Name -ne 'Windows Defender' -and $isInstalled -and $protectionState -eq 'Inconnu' -and $thirdPartyInstalledProducts.Count -gt 0) {
            $protectionState = 'Actif'
        }

        $antivirusSummary += [PSCustomObject]@{
            Produit          = $g.Name
            Type             = if ($g.Name -eq 'CrowdStrike Falcon') { 'EDR' } else { 'AV' }
            Installe         = if ($isInstalled) { 'Oui' } else { 'Non' }
            VersionInstallee = if ($versionInstalled) { $versionInstalled } else { 'N/A' }
            EtatProtection   = $protectionState
            SourceVersion    = if ($versionSource) { $versionSource } else { 'N/A' }
        }
    }

    return $antivirusSummary
}

function New-AntivirusHtml {
    param(
        [object[]]$AntivirusSummary
    )

    if ($AntivirusSummary -and $AntivirusSummary.Count -gt 0) {
        return ($AntivirusSummary | Sort-Object Produit | ConvertTo-Html -Fragment -PreContent "<h2>Antivirus</h2>")
    }

    return "<h2>Antivirus</h2><p>Aucun antivirus detecte sur ce serveur.</p>"
}

$antivirusSignals = Get-AntivirusSignals
$antivirusSummary = ConvertTo-AntivirusSummary -Signals $antivirusSignals
Set-MreSection -Name 'antivirus' -Value @($antivirusSummary | ForEach-Object {
    [ordered]@{ product = $_.Produit; type = $_.Type; installed = $_.Installe; version = $_.VersionInstallee; protection = $_.EtatProtection; versionSource = $_.SourceVersion } })
$htmlreport = New-AntivirusHtml -AntivirusSummary $antivirusSummary

Write-HostSafe "# ============================="
Write-HostSafe "# Block 6 : Verification si l'AD Connect est installe"
Write-HostSafe "# ============================="

# Verifier si Azure AD Connect est installe
$ADConnectInstalled = $Appslist | Where-Object { $_.DisplayName -like "Microsoft Azure AD Connect" -or $_.DisplayName -like "Microsoft Entra Connect Sync"}

if ($ADConnectInstalled) {
    Write-HostSafe "# Azure AD Connect est installe sur ce serveur."

    # Recuperer la version d'Azure AD Connect
    $ADConnectVersion = $ADConnectInstalled.DisplayVersion
    Write-HostSafe "# Version d'Azure AD Connect : $ADConnectVersion"
} else {
    Write-HostSafe "# Azure AD Connect n'est pas installe sur ce serveur."
}

Write-HostSafe "# ============================="
Write-HostSafe "# Block 7 : Verifications AD"
Write-HostSafe "# ============================="

if (-not $EnvCapabilities.HasAD) {
    Write-HostSafe "# Bloc AD ignore : role Active Directory non detecte sur ce serveur."
} else {

# Modules externes figes (v3.3) : extraits depuis les archives verifiees de tools\modules,
# jamais depuis PSGallery ni GitHub. Le dossier d'extraction est neuf a chaque execution et passe
# en tete de PSModulePath pour que les dependances (PSWriteHTML, PSEventViewer) soient resolues localement.
$script:PinnedModuleManifests = @{}
$script:PinnedModulesLoaded = $false

function Initialize-PinnedModules {
    if ($script:PinnedModulesLoaded) { return }
    $script:PinnedModulesLoaded = $true
    if (-not $Config.ToolModules) { return }

    $root = Join-Path $env:TEMP ("DFI-MRE-modules-{0}" -f [guid]::NewGuid().Guid)
    New-Item -Path $root -ItemType Directory -Force | Out-Null
    $script:PinnedModulesRoot = $root

    foreach ($m in $Config.ToolModules) {
        $zip = Test-PinnedFile -RelativePath $m.Path -Sha256 $m.Sha256
        if (-not $zip) { continue }
        try {
            $dest = if ($m.ModuleRoot) { $root } else { Join-Path $root $m.Name }
            Expand-Archive -LiteralPath $zip -DestinationPath $dest -Force -ErrorAction Stop
        } catch {
            Write-HostSafe "# Extraction impossible pour $($m.Name) : $($_.Exception.Message)"
        }
    }

    if (($env:PSModulePath -split ';') -notcontains $root) {
        $env:PSModulePath = "$root;$($env:PSModulePath)"
    }

    Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $manifest = Get-ChildItem -Path $_.FullName -Recurse -Filter "$($_.Name).psd1" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($manifest) { $script:PinnedModuleManifests[$_.Name] = $manifest.FullName }
    }
}

# Retourne $true si le module fige est disponible (extrait depuis une archive dont l'empreinte est valide).
function Install-ModuleIfNeeded {
    param ([string]$moduleName)
    Initialize-PinnedModules
    $key = $script:PinnedModuleManifests.Keys | Where-Object { $_ -ieq $moduleName } | Select-Object -First 1
    if ($key) { return $true }
    Write-HostSafe "# Module fige $moduleName indisponible (archive absente ou empreinte invalide). Action ignoree."
    return $false
}

# Execute une action apres import du module fige, par chemin de manifeste (jamais par nom, pour ne pas
# charger une autre version installee ailleurs sur le serveur).
function ExecuteIfModuleAvailable {
    param (
        [string]$moduleName,
        [scriptblock]$action
    )
    if (-not (Install-ModuleIfNeeded -moduleName $moduleName)) { return }
    $key = $script:PinnedModuleManifests.Keys | Where-Object { $_ -ieq $moduleName } | Select-Object -First 1
    try {
        Import-Module $script:PinnedModuleManifests[$key] -Force -ErrorAction Stop
    } catch {
        Write-HostSafe "# Impossible d'importer le module fige $moduleName. Action ignoree. Erreur: $($_.Exception.Message)"
        return
    }
    & $action
}

# Fonction pour convertir les resultats de dcdiag (gere les erreurs et la langue)
function Convert-DcDiagResults {
    # v3.3 : analyse ligne par ligne. L'ancienne version recevait la sortie en [string] (lignes collees),
    # ce qui faisait echouer l'analyse et affichait "Aucun probleme detecte" meme en cas d'echec.
    # Formats geres :
    #   EN : "......................... DC01 passed test Connectivity"
    #   FR : "......................... Le test Connectivity de DC01 a réussi"  (accents tolerants : encodage console variable)
    param (
        [object]$DcDiagOutput
    )

    $lines = @(@($DcDiagOutput | ForEach-Object { "$_" }) -join "`n" -split "`r?`n")
    $results = @()
    # Raison d'un echec : derniere ligne "error/erreur/could not/warning" dans les 12 lignes precedant le verdict
    $reasonOf = {
        param($idx)
        for ($k = $idx - 1; $k -ge [math]::Max(0, $idx - 12); $k--) {
            $t = $lines[$k].Trim()
            if ($t -match '^Starting test|^Test omis|^D.marrage du test') { break }
            if ($t -match '(?i)error|erreur|could not|impossible|unavailable|warning|avertissement') {
                if ($t.Length -gt 200) { $t = $t.Substring(0, 200) }
                return $t
            }
        }
        return $null
    }
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line -match '^\s*\.{3,}\s*(\S+)\s+(passed|failed)\s+test\s+(\S+)') {
            $results += [PSCustomObject]@{ TestName = $matches[3]; Entity = $matches[1]; TestResult = $matches[2]; Reason = $(if ($matches[2] -eq 'failed') { & $reasonOf $i } else { $null }) }
        } elseif ($line -match '^\s*\.{3,}\s*(\S+)\s+(passed|failed)\s+test\s*$') {
            # Nom de test long renvoye a la ligne par dcdiag (OutboundSecureChannels, VerifyEnterpriseReferences...)
            $entity = $matches[1]; $verdict = $matches[2]; $name = $null
            for ($j = $i + 1; $j -lt [math]::Min($i + 4, $lines.Count); $j++) {
                if ($lines[$j].Trim()) { $name = ($lines[$j].Trim() -split '\s+')[0]; break }
            }
            $results += [PSCustomObject]@{ TestName = $(if ($name) { $name } else { '(nom illisible)' }); Entity = $entity; TestResult = $verdict; Reason = $(if ($verdict -eq 'failed') { & $reasonOf $i } else { $null }) }
        } elseif ($line -match '^\s*\.{3,}\s*Le test\s+(\S+)\s+de\s+(\S+)\s+a\s+(\S+)') {
            $testName = $matches[1]; $entity = $matches[2]; $raw = $matches[3]
            $verdict = if ($raw -match '^r.ussi') { 'passed' } elseif ($raw -match '^.chou') { 'failed' } else { $raw }
            $results += [PSCustomObject]@{ TestName = $testName; Entity = $entity; TestResult = $verdict }
        }
    }
    # Les appelants enveloppent le resultat dans @() : 0, 1 ou n resultats donnent toujours un tableau.
    return $results
}

# Check Backup AD
function Convert-TimeToDays {
    [CmdletBinding()]
    param (
        $StartTime,
        $EndTime,
        [string] $Ignore = '*1601*'
    )

    $Days = $null
    if ($null -ne $StartTime -and $null -ne $EndTime) {
        try {
            if ($StartTime -notlike $Ignore -and $EndTime -notlike $Ignore) {
                $Days = (New-TimeSpan -Start $StartTime -End $EndTime).Days
            }
        } catch {}
    } elseif ($null -ne $EndTime) {
        try {
            if ($StartTime -notlike $Ignore -and $EndTime -notlike $Ignore) {
                $Days = (New-TimeSpan -Start (Get-Date) -End $EndTime).Days
            }
        } catch {}
    } elseif ($null -ne $StartTime) {
        try {
            if ($StartTime -notlike $Ignore -and $EndTime -notlike $Ignore) {
                $Days = (New-TimeSpan -Start $StartTime -End (Get-Date)).Days
            }
        } catch {}
    }
    return $Days
}

function Get-WinADLastBackup {
    [CmdletBinding()]
    param(
        [string[]] $Domains
    )

    $NameUsed = [System.Collections.Generic.List[string]]::new()
    [DateTime] $CurrentDate = Get-Date

    if (-not $Domains) {
        try {
            $Forest = Get-ADForest -ErrorAction Stop
            $Domains = $Forest.Domains
        } catch {
            Write-Warning "Get-WinADLastBackup - Failed to gather Forest Domains $($_.Exception.Message)"
        }
    }

    foreach ($Domain in $Domains) {
        $Partitions = $null
        $domainController = $null

        try {
            [string[]]$Partitions = (Get-ADRootDSE -Server $Domain -ErrorAction Stop).namingContexts
            [System.DirectoryServices.ActiveDirectory.DirectoryContextType] $contextType = [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain
            [System.DirectoryServices.ActiveDirectory.DirectoryContext] $context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($contextType, $Domain)
            [System.DirectoryServices.ActiveDirectory.DomainController] $domainController = [System.DirectoryServices.ActiveDirectory.DomainController]::FindOne($context)
        } catch {
            Write-Warning "Get-WinADLastBackup - Failed to gather partitions information for $Domain with error $($_.Exception.Message)"
        }

        if (-not $Partitions -or -not $domainController) {
            continue
        }

        $Output = ForEach ($Name in $Partitions) {
            if ($NameUsed -contains $Name) {
                continue
            } else {
                $NameUsed.Add($Name)
            }

            try {
                $domainControllerMetadata = $domainController.GetReplicationMetadata($Name)
                $dsaSignature = $domainControllerMetadata.Item("dsaSignature")
                $LastBackup = [DateTime]$dsaSignature.LastOriginatingChangeTime

                [PSCustomObject]@{
                    Domain            = $Domain
                    NamingContext     = $Name
                    LastBackup        = $LastBackup
                    LastBackupDaysAgo = -(Convert-TimeToDays -StartTime $CurrentDate -EndTime $LastBackup)
                }
            } catch {
                Write-Warning "Get-WinADLastBackup - Failed to gather backup metadata for $Domain / $Name with error $($_.Exception.Message)"
            }
        }

        $Output
    }
}

    # Condition pour verifier si le role AD est present
$adRolePresent = $false
if ($Config.Services.CheckAD) {
    $adRolePresent = Get-WindowsFeature -Name AD-Domain-Services | Select-Object -ExpandProperty Installed
}

$mreAd = [ordered]@{ present = [bool]$adRolePresent; services = @(); dcdiag = @(); dcdiagDns = @(); krbtgt = $null; domainControllers = @(); replication = @(); backups = @() }
if ($adRolePresent) {
    Write-HostSafe "# Le role Active Directory est present."

    # Verification des services DC
    Write-HostSafe "# Verification des services DC"
    try {
        $dcSvcObjects = Get-Service -name ntds, adws, dns, dnscache, kdc, w32time, netlogon -ErrorAction Stop
        $mreAd.services = @($dcSvcObjects | ForEach-Object { [ordered]@{ name = $_.Name; status = [string]$_.Status } })
        $DCservice = $dcSvcObjects |
                     ConvertTo-Html Status, Name, DisplayName -Fragment -PreContent "<h3>Check Service AD</h3>"
        $DCservice = $DCservice -replace '<td>Running</td>', '<td class="GreenColor">Running</td>'
        $DCservice = $DCservice -replace '<td>Stopped</td>', '<td class="RedColor">Stopped</td>'
        $DCservice = "<div class='report-subsection'>" + $DCservice + "</div>"

        # Recommendation si des services AD critiques ne sont pas en cours d'exécution
        $stoppedDcSvcs = @($dcSvcObjects | Where-Object { $_.Status -ne 'Running' })
        if ($stoppedDcSvcs.Count -gt 0) {
            $svcNames = ($stoppedDcSvcs | Select-Object -ExpandProperty Name) -join ', '
            Add-ActionRecommendation -Category "AD" -Message "Active Directory : services critiques non demarres ($svcNames) - verifier et corriger l'etat des services AD/DNS/KDC/Netlogon." -Priority 1
        }
    } catch {
        Write-HostSafe "Erreur lors de la recuperation des services AD : $($_.Exception.Message)"
        $DCservice = "<div class='report-subsection'><h3>Check Service AD</h3><p>Erreur lors de la recuperation des services AD.</p></div>"
    }

    # Verification DC-Diag (avec gestion d'erreurs)
    Write-HostSafe "# Verification DC-Diag"
    try {
        $testDCdiag = dcdiag /e /v /c /skip:systemlog /skip:dns /s:$Hostname 2>&1 # Capture les erreurs vers stdout
        $dcdiagResults = @(Convert-DcDiagResults -DcDiagOutput $testDCdiag)
        $mreAd.dcdiag = @($dcdiagResults | ForEach-Object { $o = [ordered]@{}; foreach ($pp in $_.PSObject.Properties) { $o[$pp.Name] = [string]$pp.Value }; $o })
        if ($dcdiagResults.Count -gt 0) {
            $dcdiag = $dcdiagResults | ConvertTo-Html -Fragment -PreContent "<h3>Check DCDIAG</h3>" -PostContent "<p>Details of the event can be found in $($reportPath)dcdiag</p>"
            $dcdiag = $dcdiag -replace '<td>r&#233;ussi</td>', '<td class="GreenColor">Success</td>'
            $dcdiag = $dcdiag -replace '<td>&#233;chou&#233;</td>', '<td class="RedColor">Failed</td>'
            $dcdiag = $dcdiag -replace '<td>passed</td>', '<td class="GreenColor">Passed</td>'
            $dcdiag = $dcdiag -replace '<td>failed</td>', '<td class="RedColor">Failed</td>'
            $dcdiag = "<div class='report-subsection'>" + $dcdiag + "</div>"
        } else {
            # 0 resultat = sortie dcdiag non analysable, et non "aucun probleme" (v3.3)
            $dcdiag = "<div class='report-subsection'><h3>Check DCDIAG</h3><p>Aucun resultat de test exploitable dans la sortie dcdiag : verifier le fichier brut dans $($reportPath)dcdiag.</p></div>"
            Add-MreError -Section 'activeDirectory' -Message "Check DCDIAG : aucun resultat de test analysable"
            Add-ActionRecommendation -Category "AD" -Message "Active Directory : sortie Check DCDIAG non analysable - verifier manuellement le fichier brut dans $($reportPath)dcdiag." -Priority 2
        }

        # Actions recommandees en fonction des resultats dcdiag
        if ($dcdiagResults.Count -gt 0) {
            $failedDcdiag = @($dcdiagResults | Where-Object { $_.TestResult -match 'echoue|failed' })
            if ($failedDcdiag.Count -gt 0) {
            Add-ActionRecommendation -Category "AD" -Message "Active Directory : des tests DCDIAG ont echoue ($($failedDcdiag.Count) test(s)) - consulter la section AD / les fichiers dcdiag pour corriger avant impact production." -Priority 1
            }
        }
    } catch {
        Write-HostSafe "Erreur lors de l'execution de dcdiag : $($_.Exception.Message)"
        $dcdiag = "<div class='report-subsection'><h3>Check DCDIAG</h3><p>Erreur lors de l'execution de dcdiag.</p></div>"
    }

    # Verification DC-Diag-DNS (avec gestion d'erreurs)
    Write-Host "# Verification DC-Diag-DNS"
    try {
        $testDCdiagDNS = dcdiag /test:dns /v /e 2>&1 # Capture les erreurs vers stdout
        $dnsDiagResults = @(Convert-DcDiagResults -DcDiagOutput $testDCdiagDNS)
        $mreAd.dcdiagDns = @($dnsDiagResults | ForEach-Object { $o = [ordered]@{}; foreach ($pp in $_.PSObject.Properties) { $o[$pp.Name] = [string]$pp.Value }; $o })
        if ($dnsDiagResults.Count -gt 0) {
            $dcdiagdns = $dnsDiagResults | ConvertTo-Html -Fragment -PreContent "<h3>Check DCDIAG-DNS</h3>" -PostContent "<p>Details of the event can be found in $($reportPath)dcdiag</p>"
            $dcdiagdns = $dcdiagdns -replace '<td>r&#233;ussi</td>', '<td class="GreenColor">Success</td>'
            $dcdiagdns = $dcdiagdns -replace '<td>&#233;chou&#233;</td>', '<td class="RedColor">Failed</td>'
            $dcdiagdns = $dcdiagdns -replace '<td>passed</td>', '<td class="GreenColor">Passed</td>'
            $dcdiagdns = $dcdiagdns -replace '<td>failed</td>', '<td class="RedColor">Failed</td>'
            $dcdiagdns = "<div class='report-subsection'>" + $dcdiagdns + "</div>"
        } else {
            # 0 resultat = sortie dcdiag non analysable, et non "aucun probleme" (v3.3)
            $dcdiagdns = "<div class='report-subsection'><h3>Check DCDIAG-DNS</h3><p>Aucun resultat de test exploitable dans la sortie dcdiag : verifier le fichier brut dans $($reportPath)dcdiag.</p></div>"
            Add-MreError -Section 'activeDirectory' -Message "Check DCDIAG-DNS : aucun resultat de test analysable"
            Add-ActionRecommendation -Category "AD" -Message "Active Directory : sortie Check DCDIAG-DNS non analysable - verifier manuellement le fichier brut dans $($reportPath)dcdiag." -Priority 2
        }

        # Actions recommandees pour la partie DNS
        if ($dnsDiagResults.Count -gt 0) {
            $failedDns = @($dnsDiagResults | Where-Object { $_.TestResult -match 'echoue|failed' })
            if ($failedDns.Count -gt 0) {
            Add-ActionRecommendation -Category "AD" -Message "DNS / Active Directory : des tests DCDIAG-DNS ont echoue ($($failedDns.Count) test(s)) - corriger la configuration DNS/AD avant impact sur les clients." -Priority 1
            }
        }
    } catch {
        Write-HostSafe "Erreur lors de l'execution de dcdiag /test:dns : $($_.Exception.Message)"
        $dcdiagdns = "<div class='report-subsection'><h3>Check DCDIAG-DNS</h3><p>Erreur lors de l'execution de dcdiag /test:dns.</p></div>"
    }

    # Save raw outputs (en s'assurant que le repertoire existe)
    if (!(Test-Path "$($reportPath)dcdiag")) {
        try {
            New-Item "$($reportPath)dcdiag" -ItemType Directory -ErrorAction Stop | Out-Null
        } catch {
            Write-Host "Erreur lors de la creation du repertoire dcdiag : $($_.Exception.Message)"
        }
    }
    try {
        $testDCdiag > "$($reportPath)dcdiag\dcdiag_$(Get-Date -Format dd-MM-yy).txt"
        $testDCdiagDNS > "$($reportPath)dcdiag\dcdiagdns_$(Get-Date -Format dd-MM-yy).txt"
    } catch {
        Write-Host "Erreur lors de la sauvegarde des logs dcdiag : $($_.Exception.Message)"
    }

    # Verification du mot de passe Kerberos
    Write-Host "# Verification du mot de passe Kerberos"
    try {
        $krbtgt = Get-ADUser -Identity krbtgt -Properties PasswordLastSet -ErrorAction Stop
        $daysSinceLastChange = ($CurrentDate - $krbtgt.PasswordLastSet).Days
        $lastPasswordSetDate = $krbtgt.PasswordLastSet.ToString("yyyy-MM-dd")
        $mreAd.krbtgt = [ordered]@{ passwordLastSet = (ConvertTo-IsoDate $krbtgt.PasswordLastSet); ageDays = $daysSinceLastChange }
        if ($daysSinceLastChange -gt 365) {
            $KerberosAccount = "<h3>Compte Kerberos</h3><p><span style='color:red; font-weight:bold;'>Attention :</span> Le mot de passe Kerberos a plus de 1 an et doit etre change.</p>"
            Add-ActionRecommendation -Category "AD" -Message "Active Directory : le mot de passe du compte krbtgt n'a pas ete change depuis plus de 365 jours - planifier un renouvellement securise (double rotation) du mot de passe krbtgt." -Priority 2
        } elseif ($daysSinceLastChange -gt 300) {
            $KerberosAccount = "<h3>Compte Kerberos</h3><p>Attention : Pensez a changer le mot de passe Kerberos.</p>"
            Add-ActionRecommendation -Category "AD" -Message "Active Directory : le mot de passe du compte krbtgt approche de 1 an ($daysSinceLastChange jours) - preparer un plan de rotation securisee." -Priority 3
        } else {
            $KerberosAccount = "<h3>Compte Kerberos</h3>"
        }
        $KerberosAccount += "<p>Derniere modification du mot de passe : $lastPasswordSetDate</p>"
        $KerberosAccount += "<p>Nombre de jours depuis la derniere modification : $daysSinceLastChange</p>"
        $KerberosAccount = "<div class='report-subsection'>" + $KerberosAccount + "</div>"
    } catch {
        Write-Host "Erreur lors de la recuperation des informations du compte krbtgt : $($_.Exception.Message)"
        $KerberosAccount = "<div class='report-subsection'><h3>Compte Kerberos</h3><p>Erreur lors de la recuperation des informations du compte krbtgt.</p></div>"
    }

    # Check replication if multiple DCs
    try {
        $dclist = Get-ADDomainController -Filter * -ErrorAction Stop
    } catch {
        Write-Log -Message "Erreur lors de la recuperation des controleurs de domaine : $($_.Exception.Message)" -Level 'WARN'
        $dclist = $null
    }

    $dclist = @($dclist)
    $mreAd.domainControllers = @($dclist | ForEach-Object { [ordered]@{ name = $_.Name; site = $_.Site; os = $_.OperatingSystem; isGlobalCatalog = $_.IsGlobalCatalog; operationMasterRoles = @($_.OperationMasterRoles | ForEach-Object { [string]$_ }) } })
    if ($dclist.Count -gt 1) {
        Write-Host "# Verification de la replication Active Directory"
        try {
            $replRaw = @(Get-ADReplicationPartnerMetadata -Target $dclist.Name -ErrorAction Stop)
            $mreAd.replication = @($replRaw | ForEach-Object {
                [ordered]@{
                    server              = $_.Server
                    partner             = (($_.Partner -split ',')[1] -replace '^CN=','')
                    partition           = $_.Partition
                    lastAttempt         = (ConvertTo-IsoDate $_.LastReplicationAttempt)
                    lastSuccess         = (ConvertTo-IsoDate $_.LastReplicationSuccess)
                    lastResult          = $_.LastReplicationResult
                    consecutiveFailures = $_.ConsecutiveReplicationFailures
                } })
            # Colonnes utiles seulement : la sortie brute (29 colonnes, types .NET) etait illisible (v3.3)
            $ReplicationMetadata = $replRaw |
                Select-Object Server,
                              @{N='Partenaire';E={ ($_.Partner -split ',')[1] -replace '^CN=','' }},
                              Partition, LastReplicationAttempt, LastReplicationSuccess,
                              @{N='Resultat';E={ if ($_.LastReplicationResult -eq 0) { 'Success' } else { $_.LastReplicationResult } }},
                              @{N='Echecs consecutifs';E={ $_.ConsecutiveReplicationFailures }} |
                ConvertTo-Html -Fragment -PreContent "<h3>Replication AD Metadata</h3>"
            $ReplicationMetadata = $ReplicationMetadata -replace '<td>Success</td>', '<td class="GreenColor">Success</td>'
            foreach ($r in $replRaw) {
                if ($r.LastReplicationResult -ne 0 -or $r.ConsecutiveReplicationFailures -gt 0) {
                    Add-ActionRecommendation -Category "AD" -Message "Active Directory : replication en echec entre $($r.Server) et son partenaire (resultat $($r.LastReplicationResult), $($r.ConsecutiveReplicationFailures) echec(s) consecutif(s)) - executer repadmin /showrepl et corriger." -Priority 1
                    break
                }
            }
                $ReplicationMetadata = "<div class='report-subsection'>" + $ReplicationMetadata + "</div>"
        } catch {
            Write-Host "Erreur lors de la recuperation des metadonnees de replication : $($_.Exception.Message)"
                $ReplicationMetadata = "<div class='report-subsection'><h3>Replication AD Metadata</h3><p>Erreur lors de la recuperation des metadonnees de replication.</p></div>"
        }
    } else {
            $ReplicationMetadata = "<div class='report-subsection'><h3>Replication AD Metadata</h3><p>Un seul controleur de domaine detecte. La verification de la replication n'est pas applicable.</p></div>"
    }

    # Verification de la date du dernier backup AD
    try {
        $backupData = Get-WinADLastBackup
        $mreAd.backups = @($backupData | ForEach-Object { [ordered]@{ namingContext = $_.NamingContext; lastBackup = (ConvertTo-IsoDate $_.LastBackup); daysAgo = $_.LastBackupDaysAgo } })
        if ($backupData) {
            $BackupAD = $backupData |
                Sort-Object Domain, NamingContext |
                ConvertTo-Html -Fragment -PreContent "<h3>Check Backup AD</h3>"
            $BackupAD = "<div class='report-subsection'>" + $BackupAD + "</div>"
        } else {
            $BackupAD = "<div class='report-subsection'><h3>Check Backup AD</h3><p>Aucune donnee de backup AD disponible.</p></div>"
        }
    } catch {
        Write-HostSafe "Erreur lors de la verification du backup AD : $($_.Exception.Message)"
        $BackupAD = "<div class='report-subsection'><h3>Check Backup AD</h3><p>Erreur lors de la verification du backup AD.</p></div>"
    }

Set-MreSection -Name 'activeDirectory' -Value $mreAd

# Telecharger et Executer ADChecker
    Write-Host "# Verification de la sante de l'Active Directory avec ADChecker"
    $ADCheckerDir = Join-Path $Config.OutputPath "ADChecker"
    $ADCheckerScriptPath = "$ADCheckerDir\ADChecker.ps1"
    $ADHealthReportPath = "$ADCheckerDir\ADHealthReport.html"
    try {
        # Creer le repertoire ADChecker s'il n'existe pas
        if (!(Test-Path $ADCheckerDir)) {
            New-Item $ADCheckerDir -ItemType Directory -ErrorAction Stop | Out-Null
        }

        # Copie de la version figee (v3.3) : plus de telechargement, empreinte verifiee
        if (-not $Config.Services.CheckADHealthTool) {
            Write-HostSafe "# ADChecker desactive (CheckADHealthTool = false)."
        } elseif (-not (Copy-PinnedTool -Name 'ADHealth' -Destination $ADCheckerScriptPath)) {
            Write-HostSafe "# ADChecker fige indisponible - bloc ADChecker ignore."
        } else {
            # v3.3 :
            # - -Server limite le controle au DC local : le script tourne sur chaque DC, et interroger les autres
            #   passe par WinRM ; si WinRM est coupe entre DC, chaque test attend 4 min de reconnexion.
            # - execution dans un job avec delai maximal : un outil tiers bloque ne doit pas bloquer le rapport.
            # - -Report est indispensable : sans lui, Get-ADHealth n'ecrit aucun fichier HTML (bug v3.2).
            $adCheckerTimeoutSec = 300
            $adJob = Start-Job -ScriptBlock {
                param($dir, $scriptPath, $server)
                Set-Location -Path $dir
                & $scriptPath -Report -Server $server
            } -ArgumentList $ADCheckerDir, $ADCheckerScriptPath, $env:COMPUTERNAME
            if (Wait-Job -Job $adJob -Timeout $adCheckerTimeoutSec) {
                Receive-Job -Job $adJob -ErrorAction SilentlyContinue | Out-Null
            } else {
                Stop-Job -Job $adJob
                # Dernieres lignes produites : indiquent le controle sur lequel l'outil est bloque
                $partial = @(Receive-Job -Job $adJob -ErrorAction SilentlyContinue 2>&1 | ForEach-Object { "$_" } | Where-Object { $_.Trim() })
                $tail = ($partial | Select-Object -Last 4) -join ' | '
                Write-Log -Message "ADChecker interrompu apres $adCheckerTimeoutSec s. Dernieres lignes : $tail" -Level 'WARN'
                Add-MreError -Section 'activeDirectory' -Message "ADChecker interrompu apres $adCheckerTimeoutSec s ; dernieres lignes : $tail"
            }
            Remove-Job -Job $adJob -Force -ErrorAction SilentlyContinue

            # Attendre que le rapport soit genere (optionnel, mais peut aider)
            Start-Sleep -Seconds 5

            # Trouver le fichier rapport le plus recent (forest_health_report_*.html ou ADHealthCheck*.html)
            $latestReport = Get-ChildItem -Path $ADCheckerDir -Filter "*.html" |
                              Where-Object { $_.Name -match 'forest_health_report_|dc_health_report_|ADHealthCheck' } |
                              Sort-Object LastWriteTime -Descending |
                              Select-Object -First 1

            # Renommer le fichier en ADHealthReport.html
            if ($latestReport) {
                # Supprimer l'ancien rapport s'il existe
                if (Test-Path $ADHealthReportPath) {
                    Remove-Item $ADHealthReportPath -Force -ErrorAction SilentlyContinue
                }
                Rename-Item -Path $latestReport.FullName -NewName "ADHealthReport.html" -Force -ErrorAction Stop
            } else {
                Write-Warning "Aucun rapport ADChecker trouve."
                $ADHealthReportPath = $null
            }

            # Lire le contenu du rapport
            if ($ADHealthReportPath -and (Test-Path $ADHealthReportPath)) {
                $adCheckerContent = Get-Content $ADHealthReportPath -Raw
                # Extraire uniquement le contenu du body (a ameliorer avec l'inline CSS)
                $adCheckerBodyContent = if ($adCheckerContent -match '(?s)<body.*?>(.*)</body>') {
                    $matches[1]
                } else {
                    "<p>Impossible d'extraire le contenu du rapport AD Health Checker.</p>"
                }
            } else {
                $adCheckerBodyContent = $null
            }
        }

    } catch {
        Write-Log -Message "Erreur lors de l'execution de ADChecker : $($_.Exception.Message)" -Level 'WARN'
        $adCheckerBodyContent = $null
    }

    # Definir les chemins des rapports
    $gpozaurrPath = Join-Path $Config.OutputPath "GPOZaurr.html"
    $CleanUpMonster = Join-Path $Config.OutputPath "CleanUpMonster.html"

    # GPOZaurr et CleanupMonster analysent tout le domaine : chaque DC produirait le meme rapport (environ 9 Mo).
    # Ils ne tournent que sur l'emulateur PDC ; si le PDC n'a pas pu etre determine, ils tournent quand meme (v3.4.1).
    $runDomainWide = $true
    if ($Config.Services.DomainWideToolsOnPdcOnly -and $mreTime.isPdcEmulator -eq $false) {
        $runDomainWide = $false
        Write-HostSafe "# GPOZaurr et CleanupMonster ignores : ce DC n'est pas l'emulateur PDC (rapports produits sur le PDC)."
        $mreAd.domainWideTools = 'pdc'
    }
    if ($runDomainWide) {
        # Lancer GPOZaurr si possible
        Write-Host "# Lancement de GPOZaurr"
        Write-Host "# Note: GPOZaurr est optionnel. Si indisponible, le rapport continue sans cette donnee."
        ExecuteIfModuleAvailable -moduleName "GPOZaurr" -action {
            try {
                Invoke-GPOZaurr -FilePath $gpozaurrPath -HideHTML -ErrorAction Stop
            } catch {
                Write-Log -Message "Erreur lors de l'execution de GPOZaurr : $($_.Exception.Message)" -Level 'WARN'
            }
        }

        # Lancer CleanUpMonster si possible
        Write-Host "# Lancement de CleanUpMonster"
        ExecuteIfModuleAvailable -moduleName "CleanUpMonster" -action {
            try {
                # -ReportOnly : aucune desactivation ni suppression (verifie dans CleanupMonster 3.1.7) ; -WhatIf en double securite
                $cumResult = Invoke-ADComputersCleanup -WhatIf -ReportOnly -Disable -Delete -ReportPath $CleanUpMonster -ErrorAction Stop
                $prop = { param($o, $n) $p = $o.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } }
                $stale = @($cumResult.CurrentRun | Where-Object { $_ } | ForEach-Object {
                    [ordered]@{
                        name           = (& $prop $_ 'SamAccountName')
                        dnsHostName    = (& $prop $_ 'DNSHostName')
                        enabled        = (& $prop $_ 'Enabled')
                        action         = [string](& $prop $_ 'Action')
                        lastLogonDays  = (& $prop $_ 'LastLogonDays')
                        passwordDays   = (& $prop $_ 'PasswordLastChangedDays')
                        os             = (& $prop $_ 'OperatingSystem')
                    } })
                $script:MreStaleComputers = [ordered]@{ thresholdDays = 180; count = $stale.Count; computers = @($stale | Select-Object -First 40) }
            } catch {
                Write-Host "Erreur lors de l'execution de CleanUpMonster : $($_.Exception.Message)"
            }
        }
    }

    # Final report assembly - seulement si on a des données
    $adComponents = @()
    if ($KerberosAccount) { $adComponents += $KerberosAccount }
    if ($DCservice) { $adComponents += $DCservice }
    if ($dcdiag) { $adComponents += $dcdiag }
    if ($dcdiagdns) { $adComponents += $dcdiagdns }
    if ($ReplicationMetadata) { $adComponents += $ReplicationMetadata }
    if ($BackupAD) { $adComponents += $BackupAD }
    if ($adCheckerBodyContent) { $adComponents += "<div class='report-subsection'><h3>ADChecker</h3><div class='external-report'>$adCheckerBodyContent</div></div>" }
    
    if ($adComponents.Count -gt 0) {
        $ReportAD = ConvertTo-Html -Body ($adComponents -join " ")
    } else {
        Write-Log -Message "Aucune donnee AD disponible" -Level 'WARN'
        # $ReportAD reste $null
    }
    Write-HostSafe "# Verification de l'Active Directory terminee."

} else {
    Write-HostSafe "# Le role Active Directory n'est pas installe sur ce serveur."
    # $ReportAD reste $null - ne sera pas affiché dans le rapport
}

} # fin bloc HasAD

Write-HostSafe "# ============================="
Write-HostSafe "# Block 8 : Role Serveur d'impression"
Write-HostSafe "# ============================="

# Vérification robuste du rôle Print-Server
$WindowsFeature = $null
$Printers = $null

if (-not $EnvCapabilities.HasPrintServer -or -not $Config.Services.CheckPrintServer) {
    Write-HostSafe "# Bloc Serveur d'impression ignore : role Print-Server non detecte."
} else {
    $WindowsFeature = Get-WindowsFeature -Name Print-Server -ErrorAction SilentlyContinue
}

if ($WindowsFeature -and $WindowsFeature.Installed) {
    Write-HostSafe "# Verifications Serveur d'impression"

    try {
        # Préférence: module PrintManagement (WS 2012+)
        Import-Module PrintManagement -ErrorAction SilentlyContinue

        $printerList = Get-Printer -ErrorAction Stop |
            Where-Object { $_.Name -notmatch 'Microsoft|OneNote|XPS|PDF' }

        $printerTable = $printerList | Select-Object `
            Name, DriverName, PortName, `
            @{N='Shared';E={ $_.Shared }}, `
            @{N='Published';E={ $_.Published }}, `
            @{N='Jobs';E={ (Get-PrintJob -PrinterName $_.Name -ErrorAction SilentlyContinue).Count }}

        $Printers = $printerTable |
            ConvertTo-Html -Fragment -PreContent "<h2>Serveur d'impression</h2><h3>Imprimantes locales</h3>"
        Set-MreSection -Name 'printers' -Value @($printerTable | ForEach-Object {
            [ordered]@{ name = $_.Name; driver = $_.DriverName; port = $_.PortName; shared = [bool]$_.Shared; published = [bool]$_.Published; jobs = $_.Jobs } })

        # Un peu de colorisation
        $Printers = $Printers -replace '<td>True</td>','<td class="GreenColor">True</td>'
        $Printers = $Printers -replace '<td>False</td>','<td class="RedColor">False</td>'
        $Printers = $Printers -replace '<td>0</td>','<td class="GreenColor">0</td>'
    } catch {
        Write-HostSafe "# Module PrintManagement indisponible, fallback WMI (Win32_Printer)"

        try {
            $printerList = Get-CimInstance Win32_Printer |
                Where-Object { $_.Name -notmatch 'Microsoft|OneNote|XPS|PDF' }

            if ($printerList) {
                $printerTable = $printerList | Select-Object `
                    Name, DriverName, PortName, `
                    @{N='Shared';E={$_.Shared}}, `
                    @{N='Published';E={$_.Published}}, `
                    @{N='Jobs';E={ $_.JobCount }}

                $Printers = $printerTable |
                    ConvertTo-Html -Fragment -PreContent "<h2>Serveur d'impression</h2><h3>Imprimantes locales (WMI)</h3>"

                $Printers = $Printers -replace '<td>True</td>','<td class="GreenColor">True</td>'
                $Printers = $Printers -replace '<td>False</td>','<td class="RedColor">False</td>'
                $Printers = $Printers -replace '<td>0</td>','<td class="GreenColor">0</td>'
            } else {
                Write-Log -Message "Aucune imprimante trouvée" -Level 'INFO'
                # $Printers reste $null
            }
        } catch {
            Write-Log -Message "Erreur lors de la récupération des imprimantes : $($_.Exception.Message)" -Level 'WARN'
            # $Printers reste $null
        }
    }
} else {
    Write-Log -Message "Role Print-Server non installe" -Level 'INFO'
    # $Printers reste $null
}

Write-Host "# ============================= "
Write-Host "# Block 9 : Role Remote Desktop Services"
Write-Host "# ============================="

# Vérification robuste du rôle RDS-Licensing
$rdsFeature = $null
$ReportRDS = $null

if ($Config.Services.CheckRDS) {
    $rdsFeature = Get-WindowsFeature -Name RDS-Licensing -ErrorAction SilentlyContinue
}

if ($rdsFeature -and $rdsFeature.InstallState -eq "Installed") {
    Write-Host "# Verification du role RDS-Licensing"
    $server = $env:COMPUTERNAME
    try {
        $tsLicense = Get-CIMInstance -ComputerName $server -ClassName Win32_TSLicenseKeyPack -Filter "TotalLicenses!=0" -ErrorAction Stop | Where-Object { $_.TypeAndModel -ne 'Built-in TS Per Device CAL' }
        Set-MreSection -Name 'rdsLicensing' -Value @($tsLicense | ForEach-Object {
            [ordered]@{ type = $_.TypeAndModel; total = $_.TotalLicenses; issued = $_.IssuedLicenses; available = $_.AvailableLicenses; productVersion = $_.ProductVersion; expiration = (ConvertTo-IsoDate $_.ExpirationDate) } })
        if ($tsLicense) {
            $CALS = $tsLicense | Select-Object TypeAndModel, TotalLicenses, IssuedLicenses, AvailableLicenses, ProductVersion, ExpirationDate | ConvertTo-Html -Fragment -PreContent "<h2>Check RDS Licence</h2>"
            
            #Report RDS Check
            $ReportRDS = $CALS
        } else {
            Write-Log -Message "Aucune licence RDS trouvée" -Level 'INFO'
            # $ReportRDS reste $null - ne sera pas affiché dans le rapport
        }
    } catch {
        Write-Log -Message "Erreur lors de la récupération des informations de licence RDS : $($_.Exception.Message)" -Level 'WARN'
        # $ReportRDS reste $null
    }
} else {
    Write-Log -Message "Le rôle RDS-Licensing n'est pas installé sur ce serveur" -Level 'INFO'
    # $ReportRDS reste $null
}

Write-HostSafe "# ============================="
Write-HostSafe "# Block 10 : Veeam Backup & Restore"
Write-HostSafe "# ============================="

# Vérification robuste de Veeam Backup & Replication
$VBRInstall = $null
$ReportVBR = $null

if (-not $EnvCapabilities.HasVBR -or -not $Config.Services.CheckVeeam) {
    Write-HostSafe "# Bloc Veeam B&R ignore : Veeam Backup & Replication non detecte."
} elseif ($Config.Services.CheckVeeam -and (Test-ApplicationInstalled -ApplicationName "Veeam Backup & Replication" -MatchType "Contains")) {
    $VBRInstall = Get-InstalledApplication -ApplicationName "Veeam Backup & Replication" -MatchType "Contains"
    
    if ($VBRInstall) {
        Write-HostSafe "# Verification de Veeam Backup & Replication"
        try {
            $vbrVersion = $VBRInstall.DisplayVersion
            $moduleLoaded = $false
            
            # 1) Tentative standard: module PowerShell (v12, v13 et superieur)
            if (Test-PowerShellModuleAvailable -ModuleName "Veeam.Backup.PowerShell") {
                try {
                    Import-Module Veeam.Backup.PowerShell -ErrorAction Stop
                    $moduleLoaded = $true
                    Write-Log -Message "Module Veeam.Backup.PowerShell charge avec succes (version VBR detectee : $vbrVersion)." -Level 'INFO'
                } catch {
                    Write-Log -Message "Echec du chargement du module Veeam.Backup.PowerShell : $($_.Exception.Message)" -Level 'WARN'
                }
            }

            # 2) Fallback legacy: snapin pour anciennes versions (v10 / v11)
            if (-not $moduleLoaded -and ($vbrVersion -match "^10|^11")) {
                if (Get-PSSnapin -Name VeeamPSSnapin -ErrorAction SilentlyContinue) {
                    try {
                        Add-PSSnapin VeeamPSSnapin -ErrorAction Stop
                        $moduleLoaded = $true
                        Write-Log -Message "Snapin VeeamPSSnapin charge avec succes (version VBR detectee : $vbrVersion)." -Level 'INFO'
                    } catch {
                        Write-Log -Message "Echec du chargement du snapin VeeamPSSnapin : $($_.Exception.Message)" -Level 'WARN'
                    }
                } else {
                    Write-Log -Message "PSSnapin VeeamPSSnapin non trouve pour VBR v10/11" -Level 'WARN'
                }
            }
            
            if (-not $moduleLoaded) {
                Write-Log -Message "Impossible de charger les modules PowerShell Veeam B&R - verifications detaillees VBR ignorees (Veeam peut tout de meme etre installe et fonctionner normalement)." -Level 'INFO'
                # $ReportVBR reste $null
            } else {
                Connect-VBRServer -ErrorAction Stop

                Write-HostSafe "# Verification des repos VBR"
                $VBRRepo = $null
                try {
                    $script:MreVeeam.repositories = @(Get-VBRBackupRepository -ErrorAction Stop | ForEach-Object { [ordered]@{ name = $_.Name; path = $_.Path } })
                    $VBRRepo = Get-VBRBackupRepository -ErrorAction Stop | Select-Object Name, Path, CloudProvider, IsAvailable, VersionOfCreation | ConvertTo-Html -Fragment -PreContent "<h2>Check VBR repository</h2>"
                } catch {
                    Write-Log -Message "Erreur lors de la récupération des repositories VBR : $($_.Exception.Message)" -Level 'WARN'
                    $VBRRepo = $null
                }

                Write-HostSafe "# Verification des jobs VBR"
                $VBRJob = $null
                try {
                    $VBRJobObjects = Get-VBRJob -ErrorAction Stop
                    $script:MreVeeam.jobs = @($VBRJobObjects | ForEach-Object {
                        [ordered]@{ name = $_.Name; type = [string]$_.JobType; lastResult = [string]$_.Info.LatestStatus; isScheduleEnabled = $_.IsScheduleEnabled } })
                    $VBRJob = $VBRJobObjects | Select-Object Name, @{N="Last Result";E={$_.Info.LatestStatus}}, JobType, TargetDir, TargetFile | ConvertTo-Html -Fragment -PreContent "<h2>Check VBR job</h2>"
                    $VBRJob = $VBRJob -replace '<td>Success</td>', '<td class="GreenColor">Success</td>'
                    $VBRJob = $VBRJob -replace '<td>Warning</td>', '<td class="OrangeColor">Warning</td>'
                    $VBRJob = $VBRJob -replace '<td>Failed</td>', '<td class="RedColor">Failed</td>'

                    # Actions recommandées sur l'état des jobs VBR
                    if ($VBRJobObjects) {
                        $failedJobs = $VBRJobObjects | Where-Object { $_.Info.LatestStatus -eq "Failed" }
                        $warningJobs = $VBRJobObjects | Where-Object { $_.Info.LatestStatus -eq "Warning" }
                        if ($failedJobs.Count -gt 0) {
                            Add-ActionRecommendation -Category "Veeam" -Message "Veeam B&R : $($failedJobs.Count) job(s) en echec - analyser les derniers rapports de sauvegarde." -Priority 1
                        }
                        if ($warningJobs.Count -gt 0) {
                            Add-ActionRecommendation -Category "Veeam" -Message "Veeam B&R : $($warningJobs.Count) job(s) en avertissement - verifier la sante des sauvegardes." -Priority 2
                        }
                    }
                } catch {
                    Write-Log -Message "Erreur lors de la récupération des jobs VBR : $($_.Exception.Message)" -Level 'WARN'
                    $VBRJob = $null
                    $GlobalError = $true
                }

                Write-Host "# Verification des licences VBR"
                $VBRLicence = $null
                try {
            $VBRLicenceObj = Get-VBRInstalledLicense -ErrorAction Stop
            $script:MreVeeam.license = [ordered]@{ status = [string]$VBRLicenceObj.Status; type = [string]$VBRLicenceObj.Type; edition = [string]$VBRLicenceObj.Edition; supportExpiration = (ConvertTo-IsoDate $VBRLicenceObj.SupportExpirationDate) }
            $VBRLicence = $VBRLicenceObj | Select-Object Status, Type, Edition, SupportID, SupportExpirationDate | ConvertTo-Html -Fragment -PreContent "<h2>Check VBR licence</h2>"

            # Actions recommandées en fonction de la licence VBR
            try {
                if ($VBRLicenceObj.SupportExpirationDate) {
                    $daysToExpire = ($VBRLicenceObj.SupportExpirationDate - (Get-Date)).Days
                    if ($daysToExpire -le 60 -and $daysToExpire -ge 0) {
                        Add-ActionRecommendation -Category "Veeam" -Message "Veeam Backup & Replication : support se termine dans $daysToExpire jour(s) - planifier le renouvellement de la licence/support." -Priority 2
                    } elseif ($daysToExpire -lt 0) {
                        Add-ActionRecommendation -Category "Veeam" -Message "Veeam Backup & Replication : support expire - verifier la conformite des sauvegardes et renouveler la licence/support." -Priority 1
                    }
                }
            } catch {
                # on ignore les erreurs de calcul d'échéance, le rapport HTML reste valide
            }
                } catch {
                    Write-Log -Message "Erreur lors de la récupération des licences VBR : $($_.Exception.Message)" -Level 'WARN'
                    $VBRLicence = $null
                }

                try {
                    Disconnect-VBRServer -ErrorAction Stop
                } catch {
                    Write-Log -Message "Erreur lors de la déconnexion VBR : $($_.Exception.Message)" -Level 'WARN'
                }

                # Assembler le rapport seulement si on a des données
                $vbrComponents = @()
                if ($VBRRepo) { $vbrComponents += $VBRRepo }
                if ($VBRJob) { $vbrComponents += $VBRJob }
                if ($VBRLicence) { $vbrComponents += $VBRLicence }
                
                if ($vbrComponents.Count -gt 0) {
                    $ReportVBR = ConvertTo-HTML -Body ($vbrComponents -join " ")
                } else {
                    Write-Log -Message "Aucune donnée VBR disponible" -Level 'WARN'
                    # $ReportVBR reste $null
                }
            }
        } catch {
            Write-Log -Message "Erreur lors de la verification de Veeam Backup & Replication : $($_.Exception.Message)" -Level 'WARN'
            # $ReportVBR reste $null - ne sera pas affiché dans le rapport
        }
    } else {
        Write-Log -Message "Veeam Backup & Replication détecté mais impossible de récupérer les informations" -Level 'WARN'
        # $ReportVBR reste $null
    }
} else {
    Write-Log -Message "Veeam Backup & Replication n'est pas installé sur ce serveur" -Level 'INFO'
    # $ReportVBR reste $null
}

Write-HostSafe "# =============================" 
Write-HostSafe "# Block 11 : Veeam Backup for Microsoft 365"
Write-HostSafe "# ============================="

Function Import-VBOModule {
    try {
        Import-Module "C:\Program Files\Veeam\Backup365\Veeam.Archiver.PowerShell\Veeam.Archiver.PowerShell.psd1" -ErrorAction Stop
        # Les modules Explorers sont optionnels
        $explorerModules = @(
            "C:\Program Files\Veeam\Backup and Replication\Explorers\Exchange\Veeam.Exchange.PowerShell\Veeam.Exchange.PowerShell.psd1",
            "C:\Program Files\Veeam\Backup and Replication\Explorers\SharePoint\Veeam.SharePoint.PowerShell\Veeam.SharePoint.PowerShell.psd1",
            "C:\Program Files\Veeam\Backup and Replication\Explorers\Teams\Veeam.Teams.PowerShell\Veeam.Teams.PowerShell.psd1"
        )
        foreach ($modulePath in $explorerModules) {
            if (Test-Path $modulePath) {
                Import-Module $modulePath -ErrorAction SilentlyContinue
            }
        }
        Connect-VBOServer -ErrorAction Stop
        Write-HostSafe "# Modules VBO365 importes avec succes"
        return $true
    } catch {
        Write-Log -Message "Erreur lors de l'importation des modules VBO365 : $($_.Exception.Message)" -Level 'WARN'
        return $false
    }
}

# Vérification robuste de Veeam Backup for Microsoft 365
$VBOInstall = $null
$ReportVBO = $null

if (-not $EnvCapabilities.HasVBO -or -not $Config.Services.CheckVeeam365) {
    Write-HostSafe "# Bloc Veeam 365 ignore : Veeam Backup for Microsoft 365 non detecte."
} elseif ($Config.Services.CheckVeeam365 -and (Test-ApplicationInstalled -ApplicationName "Veeam Backup for Microsoft 365" -MatchType "Exact")) {
    $VBOInstall = Get-InstalledApplication -ApplicationName "Veeam Backup for Microsoft 365" -MatchType "Exact"
    
    if ($VBOInstall) {
        Write-Host "# Verification des sauvegardes VBO365"
        try {
            # Vérifier que les modules existent avant d'essayer de les importer
            $vboModulePath = "C:\Program Files\Veeam\Backup365\Veeam.Archiver.PowerShell\Veeam.Archiver.PowerShell.psd1"
            if (-not (Test-Path $vboModulePath)) {
                Write-Log -Message "Modules VBO365 non trouvés - Veeam Backup for Microsoft 365 peut ne pas être correctement installé" -Level 'WARN'
                # $ReportVBO reste $null
            } else {
                $moduleImported = Import-VBOModule
                if (-not $moduleImported) {
                    Write-Log -Message "Impossible d'importer les modules VBO365" -Level 'WARN'
                    # $ReportVBO reste $null
                } else {
                    Write-Host "# Verification des repos VBO365"
                $VBORepo = $null
                try {
                    $VBORepo = Get-VBORepository -ErrorAction Stop | Select-Object Name, Path, IsOutdated,
            @{n = "Capacity (GB)"; e = { [math]::Round($_.Capacity / 1GB, 2) } }, 
            @{n = "FreeSpace (GB)"; e = { [math]::Round($_.FreeSpace / 1GB, 2) } }, 
            @{n = "UsedSpace (GB)"; e = { [math]::Round((($_.Capacity - $_.FreeSpace) / 1GB), 2) } }, 
                    @{name = "PercentFree (GB)"; expression = { [math]::Round(($_.FreeSpace / $_.Capacity) * 100, 2) } } |
                    ConvertTo-Html -Fragment -PreContent "<h2>Check VBO365 repository</h2><h3>Repository local</h3>"
                } catch {
                    Write-Log -Message "Erreur lors de la récupération des repositories VBO365 : $($_.Exception.Message)" -Level 'WARN'
                    $VBORepo = $null
                }

                $VBORepoObject = $null
                try {
                    $VBORepoObject = Get-VBOObjectStorageRepository -ErrorAction Stop | Select-Object Name, Type, SizeLimit,
                        @{n = "UsedSpace (GB)"; e = { [math]::Round((($_.UsedSpace) / 1GB), 2) } },
                        FreeSpace | ConvertTo-Html -Fragment -PreContent "<h3>Repository cloud</h3>"
                } catch {
                    Write-Log -Message "Erreur lors de la récupération des repositories cloud VBO365 : $($_.Exception.Message)" -Level 'WARN'
                    $VBORepoObject = $null
                }

                Write-Host "# Verification des jobs VBO365"
                $VBOJob = $null
                try {
                    $VBOJobObjects = Get-VBOJob -ErrorAction Stop
                    $script:MreVeeam.m365Jobs = @($VBOJobObjects | ForEach-Object {
                        [ordered]@{ name = $_.Name; repository = [string]$_.Repository; lastStatus = [string]$_.LastStatus; lastRun = (ConvertTo-IsoDate $_.LastRun); nextRun = (ConvertTo-IsoDate $_.NextRun); enabled = $_.IsEnabled } })
                    $VBOJob = $VBOJobObjects | Select-Object Name, Repository, LastStatus, NextRun, IsEnabled | 
                        ConvertTo-Html -Fragment -PreContent "<h2>Check VBO365 job</h2>"
                    $VBOJob = $VBOJob -replace '<td>Success</td>', '<td class="GreenColor">Success</td>'
                    $VBOJob = $VBOJob -replace '<td>Warning</td>', '<td class="OrangeColor">Warning</td>'
                    $VBOJob = $VBOJob -replace '<td>Failed</td>', '<td class="RedColor">Failed</td>'

                    # Actions recommandées sur l'état des jobs VBO365
                    if ($VBOJobObjects) {
                        $failedVBO = $VBOJobObjects | Where-Object { $_.LastStatus -eq "Failed" }
                        $warningVBO = $VBOJobObjects | Where-Object { $_.LastStatus -eq "Warning" }
                        if ($failedVBO.Count -gt 0) {
                            Add-ActionRecommendation -Category "Veeam365" -Message "Veeam Backup for Microsoft 365 : $($failedVBO.Count) job(s) en echec - verifier les sauvegardes O365." -Priority 1
                        }
                        if ($warningVBO.Count -gt 0) {
                            Add-ActionRecommendation -Category "Veeam365" -Message "Veeam Backup for Microsoft 365 : $($warningVBO.Count) job(s) en avertissement - analyser les causes (quota, latence, etc.)." -Priority 2
                        }
                    }
                } catch {
                    Write-Log -Message "Erreur lors de la récupération des jobs VBO365 : $($_.Exception.Message)" -Level 'WARN'
                    $VBOJob = $null
                    $GlobalError = $true
                }

                Write-Host "# Verification des licences VBO365"
                $VBOLicence = $null
                try {
            $VBOLicenceObj = Get-VBOLicense -ErrorAction Stop
            $VBOLicence = $VBOLicenceObj | Select-Object Status, ExpirationDate, UsedNumber, TotalNumber | 
                        ConvertTo-Html -As List -Fragment -PreContent "<h2>Check VBO365 licence</h2>"

            # Actions recommandées en fonction de la licence VBO365
            try {
                if ($VBOLicenceObj.ExpirationDate) {
                    $daysToExpireVBO = ($VBOLicenceObj.ExpirationDate - (Get-Date)).Days
                    if ($daysToExpireVBO -le 60 -and $daysToExpireVBO -ge 0) {
                        Add-ActionRecommendation -Category "Veeam365" -Message "Veeam Backup for Microsoft 365 : licence se termine dans $daysToExpireVBO jour(s) - planifier le renouvellement." -Priority 2
                    } elseif ($daysToExpireVBO -lt 0) {
                        Add-ActionRecommendation -Category "Veeam365" -Message "Veeam Backup for Microsoft 365 : licence expiree - verifier l'etat des sauvegardes et renouveler la licence." -Priority 1
                    }
                }

                if ($VBOLicenceObj.TotalNumber -gt 0) {
                    $usedPercentVBO = [math]::Round(($VBOLicenceObj.UsedNumber / $VBOLicenceObj.TotalNumber) * 100, 2)
                    if ($usedPercentVBO -ge 90) {
                        Add-ActionRecommendation -Category "Veeam365" -Message "Veeam Backup for Microsoft 365 : $usedPercentVBO% des licences utilisees - prevoir une extension de capacite." -Priority 3
                    }
                }
            } catch {
                # Ignorer les erreurs de calcul
            }
                } catch {
                    Write-Log -Message "Erreur lors de la récupération des licences VBO365 : $($_.Exception.Message)" -Level 'WARN'
                    $VBOLicence = $null
                }

                try {
                    Disconnect-VBOServer -ErrorAction Stop
                } catch {
                    Write-Log -Message "Erreur lors de la déconnexion VBO365 : $($_.Exception.Message)" -Level 'WARN'
                }

                # Assembler le rapport seulement si on a des données
                $vboComponents = @()
                if ($VBORepo) { $vboComponents += $VBORepo }
                if ($VBORepoObject) { $vboComponents += $VBORepoObject }
                if ($VBOJob) { $vboComponents += $VBOJob }
                if ($VBOLicence) { $vboComponents += $VBOLicence }
                
                    if ($vboComponents.Count -gt 0) {
                        $ReportVBO = ConvertTo-HTML -Body ($vboComponents -join " ")
                    } else {
                        Write-Log -Message "Aucune donnée VBO365 disponible" -Level 'WARN'
                        # $ReportVBO reste $null
                    }
                }
            }
        } catch {
            Write-Log -Message "Erreur lors de l'importation des modules VBO365 : $($_.Exception.Message)" -Level 'WARN'
            # $ReportVBO reste $null
        }
    } else {
        Write-Log -Message "Veeam Backup for Microsoft 365 détecté mais impossible de récupérer les informations" -Level 'WARN'
        # $ReportVBO reste $null
    }
} else {
    Write-Log -Message "Veeam Backup for Microsoft 365 n'est pas installé sur ce serveur" -Level 'INFO'
    # $ReportVBO reste $null
}

Write-HostSafe "# =============================" 
Write-HostSafe "# Block 12 : Verification Exchange"
Write-HostSafe "# ============================="

# Vérification robuste d'Exchange
$ExchangeInstall = $null
$ExchangeReport = $null

if (-not $EnvCapabilities.HasExchange -or -not $Config.Services.CheckExchange) {
    Write-HostSafe "# Bloc Exchange ignore : Exchange non detecte sur ce serveur."
} elseif ($Config.Services.CheckExchange -and (Test-ExchangeInstalled)) {
    # Vérifier aussi dans Appslist pour obtenir la version
    $ExchangeApp = $Appslist | Where-Object { $_.DisplayName -match "Exchange" } | Select-Object -First 1
    if ($ExchangeApp) {
        $ExchangeInstall = $ExchangeApp
    }
    
    # Charger les cmdlets Exchange AVANT de tester leur presence (v3.3). En v3.2 le snap-in n'etait charge
    # que plus bas (bloc HealthChecker) : hors Exchange Management Shell, tout le bloc Exchange etait saute.
    # 1) snap-in local : fonctionne dans une console admin et sous le compte SYSTEM (NinjaOne)
    # 2) secours : RemoteExchange.ps1 + Connect-ExchangeServer (session distante sur le serveur local)
    $exchangeCmdletsAvailable = $false
    $exchangeLoadMethod = $null
    if (Get-Command -Name Get-ServerComponentState -ErrorAction SilentlyContinue) {
        $exchangeLoadMethod = 'deja charge (Exchange Management Shell)'
    } else {
        try {
            Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction Stop
            $exchangeLoadMethod = 'snap-in local'
        } catch {
            Write-Log -Message "Snap-in Exchange indisponible : $($_.Exception.Message)" -Level 'WARN'
            try {
                $remoteExchange = Join-Path $env:ExchangeInstallPath 'bin\RemoteExchange.ps1'
                if ($env:ExchangeInstallPath -and (Test-Path $remoteExchange)) {
                    . $remoteExchange
                    Connect-ExchangeServer -auto -ClientApplication:ManagementShell
                    $exchangeLoadMethod = 'RemoteExchange.ps1'
                }
            } catch {
                Write-Log -Message "Connexion Exchange (RemoteExchange) impossible : $($_.Exception.Message)" -Level 'WARN'
            }
        }
    }
    if (Get-Command -Name Get-ServerComponentState -ErrorAction SilentlyContinue) {
        $exchangeCmdletsAvailable = $true
        Write-HostSafe "# Cmdlets Exchange chargees ($exchangeLoadMethod)."
    } else {
        Write-Log -Message "Cmdlets Exchange non disponibles - Exchange peut ne pas être correctement installé ou configuré" -Level 'WARN'
        Add-MreError -Section 'exchange' -Message "cmdlets Exchange non chargees (snap-in et RemoteExchange en echec) : bloc Exchange non collecte"
    }
    
    if ($exchangeCmdletsAvailable) {
        Write-HostSafe "# Verification Exchange"
        
        # Creation des dossiers necessaires
        $healthreportPath = Join-Path $Config.OutputPath "HealthChecker"
        $ExchangeSizeReport = Join-Path $Config.OutputPath "ExchangeSizeReport"
        try {
            if (!(Test-Path $healthreportPath)) { New-Item $healthreportPath -ItemType Directory -ErrorAction Stop | Out-Null }
            if (!(Test-Path $ExchangeSizeReport)) { New-Item $ExchangeSizeReport -ItemType Directory -ErrorAction Stop | Out-Null }

            Write-HostSafe "# Verification de la sante du serveur Exchange"
            $ExchangeReportPath = "$healthreportPath\ExchangeAllServersReport.html"
            if (Test-Path $ExchangeReportPath) {
                $ts = Get-Date -Format "yyyyMMddHHmmss"
                Rename-Item -Path $ExchangeReportPath -NewName "ExchangeAllServersReport_$ts.html" -ErrorAction SilentlyContinue
            }

            # HealthChecker fige (v3.3) : release CSS-Exchange assemblee, empreinte verifiee
            $healthCheckerBodyContent = $null
            try {
                if (-not (Copy-PinnedTool -Name 'HealthChecker' -Destination "$healthreportPath\HealthChecker.ps1")) {
                    throw "HealthChecker fige indisponible."
                }

                $exchangeLocationPushed = $false
                try {
                    Push-Location -Path $healthreportPath
                    $exchangeLocationPushed = $true
                    # -ScriptUpdateOnly supprime (v3.3) : il remplacait la version figee par la derniere publiee.
                    Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction SilentlyContinue
                    & .\HealthChecker.ps1 -SkipVersionCheck
                    & .\HealthChecker.ps1 -BuildHtmlServersReport -HtmlReportFile $ExchangeReportPath -SkipVersionCheck
                } finally {
                    if ($exchangeLocationPushed) { Pop-Location }
                }

                if (Test-Path $ExchangeReportPath) {
                    $healthCheckerContent = Get-Content $ExchangeReportPath -Raw
                    if ($healthCheckerContent -match '(?s)<body.*?>(.*)</body>') {
                        $healthCheckerBodyContent = $matches[1]
                    } else {
                        $healthCheckerBodyContent = "<p>Impossible d'extraire le contenu du rapport HealthChecker.</p>"
                    }
                    Write-HostSafe "# Contenu du rapport HealthChecker extrait avec succes."
                }
                # Constats HealthChecker pour le JSON (v3.3), lus dans son fichier texte : lignes "Error", "Warning"
                # et "Security Vulnerability". Une sous-ligne "Error: ..." est prefixee par le parametre parent.
                # Seulement un fichier produit par CETTE execution : un ancien fichier donnerait des constats perimes
                $hcTxt = Get-ChildItem -Path $healthreportPath -Filter 'HealthChecker-*.txt' -ErrorAction SilentlyContinue |
                         Where-Object { $_.LastWriteTime -ge $CurrentDate } |
                         Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ($hcTxt) {
                    $hc = [ordered]@{ file = $hcTxt.Name; errors = @(); warnings = @(); vulnerabilities = @() }
                    $parent = ''
                    foreach ($l in (Get-Content -LiteralPath $hcTxt.FullName -ErrorAction SilentlyContinue)) {
                        $t = $l.Trim()
                        if (-not $t) { continue }
                        if ($t -notmatch '^(Error|Warning|More (details|information|Information)|Note)\b' -and $t -match '^([^:]{2,60}):') { $parent = $matches[1] }
                        $text = if ($t -match '^(Error|Warning)\b' -and $parent) { "$parent - $t" } else { $t }
                        if ($text.Length -gt 300) { $text = $text.Substring(0, 300) }
                        if ($t -match '^Security Vulnerability\s*:') { $hc.vulnerabilities += $text }
                        elseif ($t -match '(^|---\s*|\s)Error\b|--ERROR--|Not supported') { $hc.errors += $text }
                        elseif ($t -match '(^|---\s*|:\s*)Warning\b') { $hc.warnings += $text }
                    }
                    $script:MreExchange.healthChecker = $hc
                } else {
                    Add-MreError -Section 'exchange' -Message "HealthChecker : aucun fichier texte produit par cette execution"
                }
            } catch {
                Write-Log -Message "Erreur HealthChecker : $($_.Exception.Message)" -Level 'WARN'
                $healthCheckerBodyContent = $null
                $GlobalError = $true
            }
            
            Write-Host "# Verification des services Exchange"
            $EXCHService = $null
            try {
                # Seulement les composants non actifs (une trentaine sont "Active" en temps normal)
                $script:MreExchange.componentStates = @(Get-ServerComponentState -Identity $Hostname -ErrorAction Stop | Where-Object { [string]$_.State -ne 'Active' } | ForEach-Object { [ordered]@{ component = $_.Component; state = [string]$_.State } })
                $EXCHService = Get-ServerComponentState -Identity $Hostname -ErrorAction Stop | 
                    Select-Object Component, State | 
                    ConvertTo-Html -Fragment -PreContent "<h2>Check Exchange Services</h2>"
                $EXCHService = $EXCHService -replace '<td>Active</td>', '<td class="GreenColor">Active</td>'
            } catch {
                Write-Log -Message "Erreur lors de la récupération des services Exchange : $($_.Exception.Message)" -Level 'WARN'
                $EXCHService = $null
            }

            Write-Host "# Verification des certificats SSL Exchange"
            $EXCHSSL = $null
            try {
                # Tous les certificats pour le JSON, avec alerte d'expiration (SMTP et IIS) - v3.3
                $exchCertsAll = @(Get-ExchangeCertificate -ErrorAction Stop)
                $script:MreExchange.certificates = @($exchCertsAll | ForEach-Object {
                    [ordered]@{ thumbprint = $_.Thumbprint; subject = $_.Subject; friendlyName = $_.FriendlyName; services = [string]$_.Services; notAfter = (ConvertTo-IsoDate $_.NotAfter); daysLeft = [int](($_.NotAfter - (Get-Date)).TotalDays); selfSigned = $_.IsSelfSigned; status = [string]$_.Status } })
                try {
                    $exSrv = Get-ExchangeServer -Identity $Hostname -ErrorAction Stop
                    $script:MreExchange.server = [ordered]@{
                        version              = [string]$exSrv.AdminDisplayVersion
                        edition              = [string]$exSrv.Edition
                        isTrial              = [bool]$exSrv.IsExchangeTrialEdition
                        isExpiredTrial       = [bool]$exSrv.IsExpiredExchangeTrialEdition
                        remainingTrialPeriod = [string]$exSrv.RemainingTrialPeriod
                    }
                } catch { Add-MreError -Section 'exchange' -Message "Get-ExchangeServer : $($_.Exception.Message)" }
                try { $script:MreExchange.authCertificateThumbprint = [string](Get-AuthConfig -ErrorAction Stop).CurrentCertificateThumbprint } catch { }
                try { $script:MreExchange.internalTransportCertificateThumbprint = [string](Get-TransportService -Identity $Hostname -ErrorAction Stop).InternalTransportCertificateThumbprint } catch { }

                foreach ($c in $exchCertsAll) {
                    $svc = [string]$c.Services
                    if ($svc -match 'SMTP|IIS') {
                        $left = [int](($c.NotAfter - (Get-Date)).TotalDays)
                        if ($left -lt 0) {
                            Add-ActionRecommendation -Category "Exchange" -Message "Exchange : certificat $($c.Thumbprint) ($($c.Subject), services $svc) expire depuis $(-$left) jour(s) - le renouveler et le reaffecter." -Priority 1
                        } elseif ($left -le 30) {
                            Add-ActionRecommendation -Category "Exchange" -Message "Exchange : certificat $($c.Thumbprint) ($($c.Subject), services $svc) expire dans $left jour(s) - planifier le renouvellement." -Priority 2
                        }
                    }
                }
                $EXCHSSL = Get-ExchangeCertificate -ErrorAction Stop | 
                    Where-Object {$_.Services -match "iis" -and $_.FriendlyName -notmatch "microsoft"} | 
                    ConvertTo-Html FriendlyName, Subject, Services, NotAfter, Status -Fragment -PreContent "<h2>Check SSL Exchange</h2>"
                $EXCHSSL = $EXCHSSL -replace '<td>Valid</td>', '<td class="GreenColor">Valid</td>'
            } catch {
                Write-Log -Message "Erreur lors de la récupération des certificats Exchange : $($_.Exception.Message)" -Level 'WARN'
                $EXCHSSL = $null
            }

            # Taille des boites mails
            $MailboxSize = $null
            $TopMailboxSize = $null
            try {
                $MailboxSize = Get-MailboxDatabase -ErrorAction Stop | 
                    Get-MailboxStatistics -ErrorAction Stop | 
                    Sort-Object TotalItemSize -Descending | 
                    Select-Object DisplayName, TotalItemSize, ItemCount, @{Label="Database"; Expression={$_.Database.Name}}
                $TopMailboxSize = $MailboxSize | Select-Object -First 10 | 
                    ConvertTo-Html -Property DisplayName, TotalItemSize, ItemCount, Database -PreContent "<h2>Top 10 Mailbox Sizes</h2>"
            } catch {
                Write-Log -Message "Erreur lors de la récupération des tailles de boites mails : $($_.Exception.Message)" -Level 'WARN'
                $MailboxSize = $null
                $TopMailboxSize = $null
            }

            # Rapport SMTP
            $SMTPAddresses = $null
            try {
                $SMTPAddresses = Get-Mailbox -ErrorAction Stop | 
                    Where-Object {$_.PrimarySmtpAddress -notmatch "Discovery"} | 
                    Select-Object PrimarySmtpAddress, @{Name="EmailAddresses"; Expression={$_.EmailAddresses | Where-Object {$_ -like "smtp:*" } | ForEach-Object {$_ -replace "^smtp:",""}}} | 
                    ConvertTo-Html -Property PrimarySmtpAddress, EmailAddresses -PreContent "<h2>SMTP Addresses</h2>"
            } catch {
                Write-Log -Message "Erreur lors de la récupération des adresses SMTP : $($_.Exception.Message)" -Level 'WARN'
                $SMTPAddresses = $null
            }

            # Export rapport taille (seulement si on a des données)
            if ($MailboxSize) {
                try {
                    $CompleteMailboxSizeReport = $MailboxSize | ConvertTo-Html -Property DisplayName, TotalItemSize, ItemCount, Database -PreContent "<h2>Complete Mailbox Size Report</h2>"
                    $SizeReport = ConvertTo-HTML -Body "<h1>Mailbox Size Check</h1>$CompleteMailboxSizeReport$SMTPAddresses"
                    $SizeReport | Out-File "$ExchangeSizeReport\MailboxSize_$(Get-Date -Format dd-MM-yy).html" -Encoding UTF8
                } catch {
                    Write-Log -Message "Erreur lors de l'export du rapport de taille : $($_.Exception.Message)" -Level 'WARN'
                }
            }

            # Test-ExchangeServerHealth (desactive par defaut, voir CheckExchangeLegacyHealth)
            $exchangeHealthBodyContent = $null
            if ($Config.Services.CheckExchangeLegacyHealth) { try {
                # Toujours recopier la version figee : un ancien fichier present dans le dossier ne serait pas verifie (v3.3)
                if (-not (Copy-PinnedTool -Name 'TestExchangeServerHealth' -Destination "$healthreportPath\Test-ExchangeServerHealth.ps1")) {
                    throw "Test-ExchangeServerHealth fige indisponible."
                }
                & "$healthreportPath\Test-ExchangeServerHealth.ps1" -ReportMode

                $exchangeHealthHtmlPath = "$healthreportPath\exchangeserverhealth.html"
                if (Test-Path $exchangeHealthHtmlPath) {
                    $exchangeHealthContent = Get-Content $exchangeHealthHtmlPath -Raw
                    if ($exchangeHealthContent -match '(?s)<body.*?>(.*)</body>') {
                        $exchangeHealthBodyContent = $matches[1]
                    }
                }
            } catch {
                Write-Log -Message "Erreur Test-ExchangeServerHealth : $($_.Exception.Message)" -Level 'WARN'
                $exchangeHealthBodyContent = $null
            } }

            # Assembler le rapport Exchange seulement si on a des données
            $exchangeComponents = @()
            if ($EXCHService) { $exchangeComponents += $EXCHService }
            if ($EXCHSSL) { $exchangeComponents += $EXCHSSL }
            if ($TopMailboxSize) { $exchangeComponents += $TopMailboxSize }
            if ($exchangeHealthBodyContent) { $exchangeComponents += $exchangeHealthBodyContent }
            if ($healthCheckerBodyContent) { $exchangeComponents += $healthCheckerBodyContent }
            
            if ($exchangeComponents.Count -gt 0) {
                $ExchangeReport = ConvertTo-HTML -Body ($exchangeComponents -join " ")
            } else {
                Write-Log -Message "Aucune donnée Exchange disponible" -Level 'WARN'
                # $ExchangeReport reste $null
            }
            
        } catch {
            Write-Log -Message "Erreur lors de la création des dossiers Exchange : $($_.Exception.Message)" -Level 'WARN'
            # $ExchangeReport reste $null
        }
    } else {
        Write-Log -Message "Cmdlets Exchange non disponibles - Exchange n'est pas correctement installé ou configuré" -Level 'WARN'
    # $ExchangeReport reste $null
    }
} else {
    Write-Log -Message "Exchange n'est pas installé sur ce serveur" -Level 'INFO'
    # $ExchangeReport reste $null
}

Write-HostSafe "# ============================="
Write-HostSafe "# Block 13 : Verification Windows Update"
Write-HostSafe "# ============================="

# Vérification si le service Windows Update est présent
$wuservice = $null
if ($Config.Services.CheckWindowsUpdate) {
    $wuservice = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
}

if ($null -ne $wuservice) {
    Write-HostSafe "# Verification des mises a jour Windows"

    # S'assurer que le service est demarre
    if ($wuservice.Status -ne "Running") {
        Write-HostSafe "# Le service Windows Update n'est pas demarre, tentative de demarrage..."
        try {
            Start-Service -Name wuauserv -ErrorAction Stop
            Write-HostSafe "# Service demarre avec succes."
        } catch {
            Write-Warning "Impossible de démarrer le service Windows Update : $($_.Exception.Message)"
        }
    }

    $UpdateCheckError = $null
    $UpdateAvailable = @()
    $history = @()
    # Recherche des mises a jour via l'API Windows Update native (COM), sans module externe (v3.3).
    # Remplace PSWindowsUpdate, qui imposait NuGet et PSGallery a chaque execution.
    try {
        Write-HostSafe "# Recherche des mises a jour disponibles..."
        $wuSession = New-Object -ComObject 'Microsoft.Update.Session'
        $wuSearcher = $wuSession.CreateUpdateSearcher()
        $wuResult = $wuSearcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
        $UpdateAvailable = @()
        for ($i = 0; $i -lt $wuResult.Updates.Count; $i++) {
            $u = $wuResult.Updates.Item($i)
            $kbs = @()
            for ($k = 0; $k -lt $u.KBArticleIDs.Count; $k++) { $kbs += "KB$($u.KBArticleIDs.Item($k))" }
            $UpdateAvailable += [pscustomobject]@{
                Title          = $u.Title
                KB             = ($kbs -join ', ')
                # MaxDownloadSize = taille maximale (tous les paquets express) : souvent tres superieure au telechargement reel
                MaxDownloadMB  = [math]::Round(([double]$u.MaxDownloadSize) / 1MB, 0)
                Severity       = $u.MsrcSeverity
                RebootRequired = [bool]$u.RebootRequired
            }
        }
        if ($UpdateAvailable.Count -gt 0) {
            $Update = $UpdateAvailable | Select-Object Title, Severity, @{N="Taille max (MB)"; E={$_.MaxDownloadMB}} |
                ConvertTo-Html -Fragment -PreContent "<h2>Check Windows Update</h2><h3>Updates Available</h3>"

            # Action recommandée : mises à jour en attente
            Add-ActionRecommendation -Category "WindowsUpdate" -Message "Windows Update : des mises a jour sont en attente - planifier une fenetre de maintenance pour les installer." -Priority 2
        } else {
            $Update = "<h2>Check Windows Update</h2><p>Aucune mise à jour disponible</p>"
        }
    } catch {
        Write-Warning "Impossible de verifier les mises a jour : $($_.Exception.Message)"
        $UpdateCheckError = $_.Exception.Message
        $Update = "<h2>Check Windows Update</h2><p>Erreur lors de la verification des mises a jour</p>"
        Add-ActionRecommendation -Category "WindowsUpdate" -Message "Windows Update : erreur lors de la verification des mises a jour - verifier manuellement l'etat de Windows Update sur ce serveur." -Priority 2
        $GlobalError = $true
    }

    # Historique des mises a jour (60 derniers jours)
    try {
        Write-HostSafe "# Recuperation de l'historique des mises a jour..."
        $session = New-Object -ComObject 'Microsoft.Update.Session'
        $MAJAge = [DateTime]::Today.AddDays(-60)
        $history = $session.QueryHistory("", 0, [Int32]::MaxValue) |
                   Where-Object { $_.Title -notmatch "Defender" -and $_.Date -ge $MAJAge }

        $ReportWU = $history | Select-Object Date, Title,
            @{Name="Result"; Expression={
                switch ($_.ResultCode) {
                    {$_ -in 1,2} {"Success"}
                    3 {"Success with Warning"}
                    4 {"Failed"}
                    default {"Unknown"}
                }
            }} | ConvertTo-Html -Fragment -PreContent "<h3>Historique des mises à jour (60 derniers jours)</h3>"

        $ReportWU = $ReportWU -replace '<td>Success</td>', '<td class="GreenColor">Success</td>'
        $ReportWU = $ReportWU -replace '<td>Failed</td>', '<td class="RedColor">Failed</td>'
    } catch {
        Write-Warning "Erreur lors de la récupération de l'historique : $($_.Exception.Message)"
        $ReportWU = "<p>Impossible de récupérer l'historique des mises à jour</p>"
    }

    # JSON : en attente + historique resume par mise a jour (v3.3)
    $resultLabel = { param($c) switch ([int]$c) { 1 {'InProgress'} 2 {'Succeeded'} 3 {'SucceededWithErrors'} 4 {'Failed'} 5 {'Aborted'} default {'Unknown'} } }
    $histEntries = @($history | Where-Object { $_.Title })
    # Les applications du Store (identifiants 9N.../9P...) sont comptees a part : elles noient l'historique
    $isStoreApp = { param($t) $t -match '^9[A-Z0-9]{11}-' }
    $mreWuHistory = @($histEntries | Where-Object { -not (& $isStoreApp $_.Title) } | Group-Object Title | ForEach-Object {
        $sorted = @($_.Group | Sort-Object Date -Descending)
        [ordered]@{
            title      = $_.Name
            attempts   = $sorted.Count
            failures   = @($sorted | Where-Object { $_.ResultCode -in 4,5 }).Count
            lastResult = (& $resultLabel $sorted[0].ResultCode)
            lastDate   = (ConvertTo-IsoDate $sorted[0].Date)
        } } | Sort-Object { $_.lastDate } -Descending)
    $storeEntries = @($histEntries | Where-Object { & $isStoreApp $_.Title })
    Set-MreSection -Name 'windowsUpdate' -Value ([ordered]@{
        checkError       = $UpdateCheckError
        pending          = @($UpdateAvailable | Where-Object { $_ } | ForEach-Object {
                               [ordered]@{ title = $_.Title; kb = $_.KB; severity = $_.Severity; maxDownloadMB = $_.MaxDownloadMB; rebootRequired = $_.RebootRequired } })
        historyDays      = 60
        history          = $mreWuHistory
        storeApps        = [ordered]@{ entries = $storeEntries.Count; failures = @($storeEntries | Where-Object { $_.ResultCode -in 4,5 }).Count }
        rebootPending    = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
    })

    # Assemblage du rapport
    $WindowsUpdateReport = ConvertTo-Html -Body "$Update $ReportWU"
    Write-HostSafe "# Verification Windows Update terminee."

} else {
    Write-HostSafe "# Le service Windows Update n'est pas disponible sur ce systeme."
    # $WindowsUpdateReport reste $null - ne sera pas affiché dans le rapport
}

$menuHtml = @"
<nav>
  <ul>
        <li><a href="#executif"><i class="fas fa-bullseye"></i> Executif</a></li>
        <li class="nav-separator"></li>
    <li><a href="#systeme"><i class="fas fa-desktop"></i> Systeme</a></li>
    <li><a href="#cpu"><i class="fas fa-microchip"></i> CPU</a></li>
    <li><a href="#ram"><i class="fas fa-memory"></i> RAM</a></li>
    <li><a href="#disques"><i class="fas fa-hdd"></i> Disques</a></li>
    <li><a href="#reseau"><i class="fas fa-network-wired"></i> Reseau</a></li>
    <li class="nav-separator"></li>
    <li><a href="#logiciels"><i class="fas fa-th-list"></i> Logiciels</a></li>
    <li><a href="#antivirus"><i class="fas fa-shield-alt"></i> Antivirus</a></li>
    <li><a href="#evenements"><i class="fas fa-history"></i> Evenements</a></li>
"@
$hasServices = ($Config.Services.CheckAD -and $adRolePresent) -or ($Config.Services.CheckPrintServer -and $WindowsFeature -and $WindowsFeature.Installed) -or ($Config.Services.CheckRDS -and $rdsFeature -and $rdsFeature.InstallState -eq "Installed" -and $ReportRDS) -or ($IsFileServer -and $FileSharesInfo -and $FileSharesInfo.Count -gt 0)
if ($hasServices) {
    $menuHtml += '    <li class="nav-separator"></li>' + "`n"
}
if ($Config.Services.CheckAD -and $adRolePresent) { 
    $menuHtml += '    <li><a href="#ad"><i class="fas fa-sitemap"></i> Active Directory</a></li>' + "`n"
}
if ($Config.Services.CheckPrintServer -and $WindowsFeature -and $WindowsFeature.Installed) {
    $menuHtml += '    <li><a href="#imprimantes"><i class="fas fa-print"></i> Imprimantes</a></li>' + "`n"
}
if ($Config.Services.CheckRDS -and $rdsFeature -and $rdsFeature.InstallState -eq "Installed" -and $ReportRDS) { 
    $menuHtml += '    <li><a href="#rds"><i class="fas fa-desktop"></i> RDS</a></li>' + "`n" 
}
if ($IsFileServer -and $FileSharesInfo -and $FileSharesInfo.Count -gt 0) { 
    $menuHtml += '    <li><a href="#fileserver"><i class="fas fa-folder-open"></i> Fichiers</a></li>' + "`n" 
}
if (($Config.Services.CheckVeeam -and $VBRInstall -and $ReportVBR) -or ($Config.Services.CheckVeeam365 -and $VBOInstall -and $ReportVBO) -or ($Config.Services.CheckExchange -and $ExchangeInstall -and $ExchangeReport)) {
    $menuHtml += '    <li class="nav-separator"></li>' + "`n"
}
if ($Config.Services.CheckVeeam -and $VBRInstall -and $ReportVBR) { 
    $menuHtml += '    <li><a href="#veeam"><i class="fas fa-database"></i> Veeam</a></li>' + "`n" 
}
if ($Config.Services.CheckVeeam365 -and $VBOInstall -and $ReportVBO) { 
    $menuHtml += '    <li><a href="#veeam365"><i class="fas fa-cloud"></i> Veeam 365</a></li>' + "`n" 
}
if ($Config.Services.CheckExchange -and $ExchangeInstall -and $ExchangeReport) { 
    $menuHtml += '    <li><a href="#exchange"><i class="fas fa-envelope"></i> Exchange</a></li>' + "`n" 
}
$hasMaintenance = ($Config.Services.CheckWindowsUpdate -and $wuservice) -or ($ActionRecommendations.Count -gt 0)
if ($hasMaintenance) {
    $menuHtml += '    <li class="nav-separator"></li>' + "`n"
}
if ($Config.Services.CheckWindowsUpdate -and $wuservice) { 
    $menuHtml += '    <li><a href="#updates"><i class="fas fa-sync-alt"></i> Windows Update</a></li>' + "`n" 
}
if ($ActionRecommendations.Count -gt 0) { 
    $menuHtml += '    <li><a href="#actions"><i class="fas fa-tasks"></i> Actions</a></li>' + "`n" 
}
$menuHtml += @"
  </ul>
</nav>
"@

$rolesSummary = @()
$rolesSummary += [PSCustomObject]@{
    Name   = "Active Directory"
    Status = if ($Config.Services.CheckAD -and $adRolePresent) { "Présent" } else { "Non installé" }
}
$rolesSummary += [PSCustomObject]@{
    Name   = "Serveur d'impression"
    Status = if ($Config.Services.CheckPrintServer -and $WindowsFeature -and $WindowsFeature.Installed) { "Présent" } else { "Non installé" }
}
$rolesSummary += [PSCustomObject]@{
    Name   = "RDS Licensing"
    Status = if ($Config.Services.CheckRDS -and $rdsFeature -and $rdsFeature.InstallState -eq "Installed") { "Présent" } else { "Non installé" }
}
$rolesSummary += [PSCustomObject]@{
    Name   = "Veeam Backup & Replication"
    Status = if ($Config.Services.CheckVeeam -and $VBRInstall) { "Présent" } else { "Non installé" }
}
$rolesSummary += [PSCustomObject]@{
    Name   = "Serveur de fichiers"
    Status = if ($IsFileServer) { "Présent" } else { "Non détecté" }
}
$rolesSummary += [PSCustomObject]@{
    Name   = "Veeam Backup for Microsoft 365"
    Status = if ($Config.Services.CheckVeeam365 -and $VBOInstall) { "Présent" } else { "Non installé" }
}
$rolesSummary += [PSCustomObject]@{
    Name   = "Exchange"
    Status = if ($Config.Services.CheckExchange -and $ExchangeInstall) { "Présent" } else { "Non installé" }
}
$rolesSummary += [PSCustomObject]@{
    Name   = "Windows Update"
    Status = if ($Config.Services.CheckWindowsUpdate -and $wuservice) { "Activé" } else { "Non disponible / désactivé" }
}

$rolesHtml = "<div class='section' id='roles'><h2>Rôles détectés</h2><table><tr><th>Rôle</th><th>Statut</th></tr>`n"
foreach ($r in $rolesSummary) {
    $statusClass = switch ($r.Status) {
        "Présent" { "GreenColor" }
        "Activé" { "GreenColor" }
        "Non installé" { "muted" }
        default { "OrangeColor" }
    }
    $rolesHtml += "  <tr><td>$($r.Name)</td><td class='$statusClass'>$($r.Status)</td></tr>`n"
}
$rolesHtml += "</table></div>`n"

# Normalisation des recommandations pour les calculs de synthese
$normalizedRecommendations = foreach ($rec in $ActionRecommendations) {
    if ($rec -is [string]) {
        [pscustomobject]@{
            Category = "General"
            Message  = $rec
            Priority = 2
        }
    } else {
        $rec
    }
}

# Scores par domaines metier
$domainDefinitions = @(
    @{ Name = "Active Directory"; Categories = @("AD", "DNS") },
    @{ Name = "Sauvegardes"; Categories = @("Veeam", "Veeam365") },
    @{ Name = "Securite"; Categories = @("Securite", "SecureBoot", "Exchange") },
    @{ Name = "Patching"; Categories = @("WindowsUpdate") },
    @{ Name = "Systeme"; Categories = @("OS", "Uptime", "CPU", "RAM", "Disque", "EventLog", "Ressources", "TimeSync") }
)

$domainScores = foreach ($def in $domainDefinitions) {
    Get-DomainHealthScore -DomainName $def.Name -Categories $def.Categories -Recommendations $normalizedRecommendations
}

$executiveSummaryHtml = New-ExecutiveSummaryHtml -GlobalScore $HealthScore -GlobalLabel $HealthLabel -Recommendations $normalizedRecommendations -DomainScores $domainScores

$htmlContent = @"
<!DOCTYPE html>
<html lang="fr" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Rapport de Maintenance - Serveur</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
<style>
:root{
    --bg-grad-1:#f8fafc; --bg-grad-2:#f1f5f9;
    --card:#ffffff; --text:#1e293b; --muted:#64748b;
    --primary:#3b82f6; --primary-2:#60a5fa; --primary-3:#2563eb;
    --primary-light:#dbeafe; --primary-dark:#1e40af;
    --green:#10b981; --green-light:#d1fae5; --red:#ef4444; --red-light:#fee2e2;
    --orange:#f59e0b; --orange-light:#fef3c7;
    --table-even:#f8fafc; --table-hover:#f1f5f9; --table-border:#e2e8f0;
    --nav-bg:#ffffff; --nav-border:#e2e8f0;
    --shadow-sm:0 1px 2px 0 rgba(0,0,0,0.05);
    --shadow:0 4px 6px -1px rgba(0,0,0,0.1),0 2px 4px -1px rgba(0,0,0,0.06);
    --shadow-md:0 10px 15px -3px rgba(0,0,0,0.1),0 4px 6px -2px rgba(0,0,0,0.05);
    --shadow-lg:0 20px 25px -5px rgba(0,0,0,0.1),0 10px 10px -5px rgba(0,0,0,0.04);
    --shadow-xl:0 25px 50px -12px rgba(0,0,0,0.25);
}
[data-theme="dark"]{
    --bg-grad-1:#1a202c; --bg-grad-2:#1a202c;
    --card:#2c374a; --text:#ffffff; --muted:#b0b0b0;
    --primary:#3498db; --primary-2:#4a89f5; --primary-3:#2980b9;
    --primary-light:rgba(52,152,219,0.15); --primary-dark:#1e3a8a;
    --green:#2ecc71; --green-light:rgba(46,204,113,0.15); --red:#e74c3c; --red-light:rgba(231,76,60,0.15);
    --orange:#f39c12; --orange-light:rgba(243,156,18,0.15);
    --table-even:#2c374a; --table-hover:#34495e; --table-border:#34495e;
    --nav-bg:#1a202c; --nav-border:#2c374a;
    --shadow-sm:0 1px 2px 0 rgba(0,0,0,0.5);
    --shadow:0 4px 6px -1px rgba(0,0,0,0.6),0 2px 4px -1px rgba(0,0,0,0.5);
    --shadow-md:0 10px 15px -3px rgba(0,0,0,0.7),0 4px 6px -2px rgba(0,0,0,0.6);
    --shadow-lg:0 20px 25px -5px rgba(0,0,0,0.8),0 10px 10px -5px rgba(0,0,0,0.7);
    --shadow-xl:0 25px 50px -12px rgba(0,0,0,0.9);
}

/* Base */
*{ box-sizing:border-box; }
body{
    font-family:'Segoe UI',-apple-system,BlinkMacSystemFont,'Inter',system-ui,sans-serif;
    background:var(--bg-grad-1);
    background-attachment:fixed;
    color:var(--text); margin:0; padding:20px 16px;
    line-height:1.6; -webkit-font-smoothing:antialiased; -moz-osx-font-smoothing:grayscale;
    transition:background 0.3s ease, color 0.3s ease;
}
.container{
    width:96%; margin:20px auto; max-width:1400px;
    background:var(--card); border-radius:16px;
    box-shadow:var(--shadow-lg);
    padding:32px; border:1px solid var(--table-border);
    transition:box-shadow 0.3s ease;
}
.container:hover{ box-shadow:var(--shadow-xl); }
.header{ display:flex; align-items:center; justify-content:space-between; gap:16px; margin-bottom:24px; padding-bottom:20px; border-bottom:2px solid var(--table-border); }
.brand{ display:flex; align-items:center; gap:14px; }
.brand h1{ margin:0; font-size:1.75rem; font-weight:700; letter-spacing:-0.02em; color:var(--text); }
[data-theme="dark"] .brand h1{ color:#ffffff; }
.controls{ display:flex; gap:10px; align-items:center; }
.btn{ background:linear-gradient(135deg,var(--primary) 0%,var(--primary-2) 100%); color:#fff; padding:10px 18px; border-radius:10px; border:none; cursor:pointer; font-weight:600; font-size:0.9rem; box-shadow:var(--shadow); transition:all 0.3s cubic-bezier(0.4,0,0.2,1); position:relative; overflow:hidden; }
.btn::before{ content:''; position:absolute; top:50%; left:50%; width:0; height:0; border-radius:50%; background:rgba(255,255,255,0.3); transform:translate(-50%,-50%); transition:width 0.6s,height 0.6s; }
.btn:hover::before{ width:300px; height:300px; }
.btn:hover{ transform:translateY(-2px); box-shadow:var(--shadow-md); }
.btn:active{ transform:translateY(0); }
.btn--muted{ background:transparent; color:var(--primary); border:2px solid var(--primary); box-shadow:none; }
.btn--muted:hover{ background:var(--primary-light); }

/* System info inline layout */
.info-card{ display:flex; gap:24px; flex-wrap:wrap; align-items:flex-start; margin-top:8px }
.info-card > div{ flex:1 1 260px; min-width:220px; box-sizing:border-box }
.info-card h3{ margin-bottom:6px }

h1{ font-size:2rem; font-weight:800; margin:0 0 8px 0; color:var(--text); }
h2{ color:var(--primary); margin:32px 0 16px 0; font-size:1.5rem; font-weight:700; padding-bottom:12px; border-bottom:2px solid var(--table-border); display:flex; align-items:center; gap:12px; }
h2::before{ content:''; width:4px; height:24px; background:linear-gradient(135deg,var(--primary) 0%,var(--primary-2) 100%); border-radius:2px; }
h3{ color:var(--text); margin:16px 0 10px 0; font-size:1.15rem; font-weight:600; }

/* Nav */
nav{ background:var(--nav-bg); border:1px solid var(--nav-border); border-radius:12px; margin:24px 0 28px; padding:14px 18px; box-shadow:var(--shadow-sm); backdrop-filter:blur(10px); }
nav.sticky{ position:sticky; top:16px; z-index:100; }
nav ul{ list-style:none; margin:0; padding:0; display:flex; flex-wrap:wrap; gap:8px; align-items:center; }
nav a{ color:var(--primary); text-decoration:none; font-weight:600; padding:10px 16px; border-radius:10px; transition:all 0.3s cubic-bezier(0.4,0,0.2,1); display:flex; align-items:center; gap:8px; font-size:0.9rem; position:relative; }
nav a i{ font-size:0.95rem; }
nav a:hover, nav a:focus{ background:var(--primary-light); color:var(--primary-3); transform:translateY(-1px); }
nav a.active{ background:var(--primary); color:#fff; box-shadow:var(--shadow); }
[data-theme="dark"] nav a.active{ background:#3498db; }
nav a.active::after{ content:''; position:absolute; bottom:0; left:50%; transform:translateX(-50%); width:60%; height:3px; background:#fff; border-radius:2px 2px 0 0; }
.nav-separator{ width:1px; height:24px; background:var(--table-border); margin:0 4px; flex-shrink:0; }

/* Responsive layout */
.grid{ display:grid; grid-template-columns: repeat(12, 1fr); gap:18px; }
.col-6{ grid-column: span 6; }
.col-4{ grid-column: span 4; }
.col-12{ grid-column: span 12; }

/* Tables */
table{ width:100%; border-collapse:separate; border-spacing:0; margin:20px 0; background:var(--card); border-radius:12px; overflow:hidden; box-shadow:var(--shadow-sm); border:1px solid var(--table-border); }
th,td{ padding:14px 16px; text-align:left; border-bottom:1px solid var(--table-border); transition:background 0.2s ease; }
thead th{ position:sticky; top:0; z-index:10; cursor:pointer; background:var(--primary); color:#fff; font-weight:700; font-size:0.95rem; text-transform:uppercase; letter-spacing:0.5px; padding:16px; }
thead th:hover{ background:var(--primary-3); }
[data-theme="dark"] thead th{ background:#3498db; }
[data-theme="dark"] thead th:hover{ background:#2980b9; }
tbody tr{ transition:all 0.2s ease; }
tbody tr:nth-child(even){ background:var(--table-even); }
tbody tr:hover{ background:var(--table-hover); transform:scale(1.01); box-shadow:var(--shadow-sm); }
tbody tr:last-child td{ border-bottom:none; }
tbody td{ font-size:0.95rem; }

/* Cards */
.card{ background:var(--card); padding:18px; border-radius:12px; border:1px solid var(--table-border); box-shadow:var(--shadow-sm); transition:all 0.3s cubic-bezier(0.4,0,0.2,1); position:relative; overflow:hidden; }
.card::before{ content:''; position:absolute; top:0; left:0; width:100%; height:3px; background:linear-gradient(90deg,var(--primary) 0%,var(--primary-2) 100%); transform:scaleX(0); transform-origin:left; transition:transform 0.3s ease; }
.card:hover::before{ transform:scaleX(1); }
.card:hover{ transform:translateY(-4px); box-shadow:var(--shadow-md); border-color:var(--primary-light); }
.card h3{ margin:0 0 8px 0; }

/* Details and summary */
details{ background:transparent; border-radius:8px; padding:8px; }
summary{ cursor:pointer; outline:none; font-weight:700; }

/* Badges & couleurs */
.badge-success{ background:linear-gradient(135deg,var(--green) 0%,#059669 100%); color:#fff; border-radius:8px; padding:6px 14px; font-size:0.85rem; font-weight:600; box-shadow:var(--shadow-sm); display:inline-flex; align-items:center; gap:6px; }
.badge-error{ background:linear-gradient(135deg,var(--red) 0%,#dc2626 100%); color:#fff; border-radius:8px; padding:6px 14px; font-size:0.85rem; font-weight:600; box-shadow:var(--shadow-sm); display:inline-flex; align-items:center; gap:6px; }
.badge-warning{ background:linear-gradient(135deg,var(--orange) 0%,#d97706 100%); color:#fff; border-radius:8px; padding:6px 14px; font-size:0.85rem; font-weight:600; box-shadow:var(--shadow-sm); display:inline-flex; align-items:center; gap:6px; }
.GreenColor{ color:var(--green); font-weight:700; }
.RedColor{ color:var(--red); font-weight:700; }
.OrangeColor{ color:var(--orange); font-weight:700; }

/* Small screens */
@media (max-width:900px){
    .grid{ grid-template-columns: repeat(6, 1fr); }
    .col-6{ grid-column: span 6; }
    nav ul{ gap:8px; }
}

@media (max-width:520px){
    .grid{ grid-template-columns: repeat(2, 1fr); }
    .col-6,.col-4{ grid-column: span 2; }
    .header{ flex-direction:column; align-items:flex-start; gap:8px; }
}
.chip--bad{ background:color-mix(in srgb,var(--red) 20%, transparent); color:var(--red); border:1px solid var(--red); }

/* Barres de progression */
.progress{ position:relative; height:20px; background:var(--table-border); border-radius:10px; overflow:hidden; box-shadow:inset 0 2px 4px rgba(0,0,0,0.1); }
.progress>span{ position:absolute; left:0; top:0; bottom:0; background:#10b981; display:block; border-radius:10px; transition:width 0.6s cubic-bezier(0.4,0,0.2,1), background 0.3s ease; box-shadow:0 2px 4px rgba(16,185,129,0.3); }
/* Les couleurs seront appliquées dynamiquement par JavaScript selon les valeurs */
.progress b{ position:absolute; right:8px; top:0; bottom:0; display:flex; align-items:center; font-size:0.8rem; font-weight:700; color:#fff; text-shadow:0 1px 2px rgba(0,0,0,0.2); z-index:1; }

/* Rapports externes */
.section{ margin-bottom:40px; }
.report-subsection{ margin:18px 0; overflow-x:auto; }
.report-subsection h3{ margin-top:0; }
.external-report{ width:100%; overflow-x:auto; margin:18px 0; padding-bottom:10px; }
.external-report table{ min-width:1200px; border-collapse:collapse; }
.external-report th{ background:linear-gradient(90deg,#3182bd 0%,#6ec6f3 100%); color:#fff; padding:6px 10px; font-size:.95em; white-space:nowrap; text-align:left; }
.external-report td{ background:var(--card); color:var(--text); padding:6px 10px; font-size:.95em; white-space:nowrap; text-align:left; }

/* Footer */
footer{ text-align:center; margin-top:60px; color:var(--muted); font-size:13px; letter-spacing:.03em; }

/* Toolbar (thème + haut de page) */
.toolbar{ display:flex; gap:10px; justify-content:flex-end; margin:-8px 0 12px; }
.btn{ border:1px solid var(--table-border); background:var(--card); color:var(--text);
      padding:6px 10px; border-radius:8px; cursor:pointer; }
.btn:hover{ background:var(--table-hover); }
#toTop{ position:fixed; right:24px; bottom:24px; display:none; z-index:1000; width:50px; min-height:50px; border-radius:50%; background:linear-gradient(135deg,var(--primary) 0%,var(--primary-2) 100%); color:#fff; border:none; cursor:pointer; font-size:11px; box-shadow:var(--shadow-lg); transition:all 0.3s ease; flex-direction:column; align-items:center; justify-content:center; gap:2px; padding:6px 4px; line-height:1.2; }
#toTop i{ font-size:14px; line-height:1; display:block; }
#toTop span{ font-size:10px; line-height:1; display:block; }
#toTop:hover{ transform:translateY(-4px) scale(1.1); box-shadow:var(--shadow-xl); }
#toTop:active{ transform:translateY(-2px) scale(1.05); }

@media (max-width:900px){
  .container{ width:100%; padding:5px; }
  table,th,td{ font-size:13px; }
  .info-card{ flex-direction:column; gap:0; }
  nav ul{ gap:12px; }
}
/* --- UI++ (meters, callouts, sticky nav, copy btns, details, print) --- */
.meter{height:12px;border-radius:8px;background:var(--table-border);overflow:hidden;box-shadow:inset 0 2px 4px rgba(0,0,0,0.1);position:relative}
.meter>span{display:block;height:100%;background:#10b981;transition:width 0.8s cubic-bezier(0.4,0,0.2,1), background 0.3s ease;border-radius:8px;box-shadow:0 2px 4px rgba(16,185,129,0.2);position:relative}
.meter>span::after{content:'';position:absolute;top:0;left:0;right:0;bottom:0;background:linear-gradient(180deg,rgba(255,255,255,0.3) 0%,transparent 100%);border-radius:8px}

/* KPI cards */
.kpi-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px;align-items:stretch;width:100%;margin:24px 0}
.kpi-card{padding:20px;border-radius:14px;display:flex;flex-direction:column;gap:12px;align-items:flex-start;justify-content:center;transition:all 0.3s cubic-bezier(0.4,0,0.2,1);min-height:130px;box-sizing:border-box;width:100%;position:relative;overflow:hidden;background:var(--card);border:1px solid var(--table-border);box-shadow:var(--shadow-sm)}
.kpi-card::after{content:'';position:absolute;top:0;right:0;width:100px;height:100px;background:radial-gradient(circle,var(--primary-light) 0%,transparent 70%);opacity:0;transition:opacity 0.3s ease}
.kpi-card:hover::after{opacity:0.3}
.kpi-card:hover{transform:translateY(-8px) scale(1.02);box-shadow:var(--shadow-lg);border-color:var(--primary-light)}
.kpi-card h4{margin:0;color:var(--primary);font-size:1rem;font-weight:600}
.stat-value{font-size:2rem;font-weight:900;color:var(--text);line-height:1.2;background:linear-gradient(135deg,var(--text) 0%,var(--muted) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.small-note{font-size:0.875rem;color:var(--muted);font-weight:500}
.progress span{background:linear-gradient(90deg,var(--primary) 0%,var(--primary-2) 100%);border-radius:10px}

/* KPI visual enhancements (icon + big number) */
.kpi-header{display:flex;align-items:center;gap:16px;width:100%}
.kpi-icon{width:64px;height:64px;border-radius:50%;display:flex;align-items:center;justify-content:center;background:var(--primary-light);border:2px solid var(--primary);color:var(--primary);font-size:24px;box-shadow:var(--shadow-sm);transition:all 0.3s ease}
[data-theme="dark"] .kpi-icon{background:rgba(52,152,219,0.2);border-color:#3498db;color:#ffffff}
.kpi-card:hover .kpi-icon{transform:scale(1.1) rotate(5deg);box-shadow:var(--shadow);background:linear-gradient(135deg,var(--primary) 0%,var(--primary-2) 100%);color:#fff;border-color:var(--primary)}
.kpi-number{display:flex;flex-direction:column;align-items:flex-start;flex:1}
.kpi-number .stat-value{font-size:2rem;font-weight:900}
.kpi-number .label{font-size:1rem;color:var(--muted);font-weight:600;margin-top:4px}

/* Non-animated info value (strings) */
.info-value{font-size:1.25rem;font-weight:700;color:var(--text);line-height:1.1}

/* Ensure KPI/info cards inside info-card have equal height and centered content */
.info-card .kpi-card{min-height:140px;display:flex;flex-direction:column;justify-content:center;padding:14px}
.info-card .kpi-number .info-value{font-size:1.25rem}
.info-card .kpi-number .stat-value{font-size:1.6rem}
.meter-label{font-size:.9em;opacity:.8;margin-top:6px}
.kpi{display:flex;gap:12px;align-items:center}
.kpi .dot{width:8px;height:8px;border-radius:999px;background:#34a853}
.kpi.warn .dot{background:#fbbc04}
.kpi.crit .dot{background:#ea4335}

.callout{border-left:4px solid var(--primary);background:var(--primary-light);padding:16px 20px;border-radius:12px;margin:20px 0;box-shadow:var(--shadow-sm);transition:all 0.3s ease;position:relative;overflow:hidden}
.callout::before{content:'';position:absolute;left:0;top:0;bottom:0;width:4px;background:linear-gradient(180deg,var(--primary) 0%,var(--primary-2) 100%)}
.callout.warn{border-left-color:var(--orange);background:var(--orange-light)}
.callout.warn::before{background:linear-gradient(180deg,var(--orange) 0%,#d97706 100%)}
.callout.danger{border-left-color:var(--red);background:var(--red-light)}
.callout.danger::before{background:linear-gradient(180deg,var(--red) 0%,#dc2626 100%)}
.callout:hover{transform:translateX(4px);box-shadow:var(--shadow-md)}
.callout .title{font-weight:800;margin-bottom:8px;font-size:1.1rem;color:var(--text)}

nav{position:sticky;top:8px;z-index:5}
nav a.active{background:#cfe3ff;color:#0b57d0}
.section{scroll-margin-top:90px}

.copy{cursor:pointer;font-size:.85em;border:1px solid #d7dbe4;border-radius:6px;padding:4px 8px;margin-left:8px;background:#f7f9fc}
.copy:active{transform:scale(.98)}
.inline-kv{display:flex;align-items:center;gap:6px}

details{background:#f7faff;border:1px solid #dfe7f6;border-radius:10px;padding:10px 12px;margin:14px 0}
details summary{cursor:pointer;font-weight:600;list-style:none}
details summary::-webkit-details-marker{display:none}

@media print{
  nav,.toolbar{display:none!important}
  body{background:#fff!important}
  .container{box-shadow:none;margin:0;padding:0;max-width:100%}
  h2{border-left:none;color:#000}
  table{page-break-inside:auto}
  tr{page-break-inside:avoid;page-break-after:auto}
  .callout,.info-card{border:1px solid #aaa;background:#fff}
}

/* Dark-mode specific tweaks for better KPI readability */
[data-theme="dark"] .card,
[data-theme="dark"] .kpi-card {
        background: #2c374a;
        border: 1px solid #34495e;
        box-shadow: 0 8px 20px rgba(0,0,0,0.5);
        color: #ffffff;
}

[data-theme="dark"] .kpi-icon {
        background: rgba(52,152,219,0.2);
        border: 2px solid #3498db;
        color: #ffffff;
        box-shadow: 0 2px 8px rgba(0,0,0,0.35) inset;
}

[data-theme="dark"] .stat-value { color: #ffffff; text-shadow: none; }
[data-theme="dark"] .info-value { color: #ffffff; }
[data-theme="dark"] .label, [data-theme="dark"] .small-note { color: #b0b0b0; opacity:1; }
[data-theme="dark"] .progress { background: rgba(255,255,255,0.03); }
[data-theme="dark"] .progress span { border-radius:8px; box-shadow:0 4px 12px rgba(0,0,0,0.45) inset; }

/* Dark-mode: improve event logs / external tables readability */
[data-theme="dark"] .external-report { background: transparent; padding: 8px 0; }
[data-theme="dark"] .external-report table { width:100%; border-collapse:collapse; background:transparent; }
[data-theme="dark"] .external-report th {
    background: #3498db;
    color: #ffffff;
    padding:10px 12px; font-weight:700; border-bottom:1px solid #2980b9;
}
[data-theme="dark"] .external-report td {
    background: #2c374a;
    color: #ffffff;
    padding:10px 12px; vertical-align:middle; border-bottom:1px solid #34495e;
}
[data-theme="dark"] .external-report tr:nth-child(even) td { background: #34495e; }
[data-theme="dark"] .external-report tr:hover td { background: #3d5468; }

[data-theme="dark"] details { background: #2c374a; border: 1px solid #34495e; }
[data-theme="dark"] summary { color: #3498db; font-weight:700; }
/* Dark-mode: callouts (info / warn / danger) with distinct accents */
[data-theme="dark"] .callout { 
    background: #2c374a;
    color: #b0b0b0; 
    border-left: 4px solid #3498db;
    border-radius:8px; 
    padding:12px 14px; 
    box-shadow: 0 6px 22px rgba(0,0,0,0.5);
}
[data-theme="dark"] .callout .title { color: #ffffff; font-weight:800; }

/* Info (blue) */
[data-theme="dark"] .callout.info { border-left-color: #3498db; }

/* Warning (amber) */
[data-theme="dark"] .callout.warn { border-left-color: #f39c12; }

/* Danger (red) */
[data-theme="dark"] .callout.danger { border-left-color: #e74c3c; }

/* Sticky headers for large external tables */
.external-report th { position: sticky; top: 90px; z-index: 6; }

/* Theme toggle button */
.btn--theme{ 
    width:44px !important; 
    height:44px !important; 
    padding:0 !important; 
    display:flex !important; 
    align-items:center !important; 
    justify-content:center !important; 
    border-radius:50% !important; 
    background:var(--primary-light) !important; 
    border:2px solid var(--primary) !important; 
    color:var(--primary) !important; 
    cursor:pointer !important; 
    transition:all 0.3s ease !important; 
    box-shadow:var(--shadow-sm) !important;
    margin-left:8px;
}
.btn--theme:hover{ 
    background:var(--primary) !important; 
    color:#fff !important; 
    transform:scale(1.1) !important; 
    box-shadow:var(--shadow) !important;
}
.btn--theme i{ 
    font-size:1.2rem !important; 
    pointer-events:none !important; 
}
[data-theme="dark"] .btn--theme{ 
    background:rgba(52,152,219,0.2) !important; 
    border-color:#3498db !important; 
    color:#3498db !important; 
}
[data-theme="dark"] .btn--theme:hover{ 
    background:#3498db !important; 
    color:#fff !important; 
}

</style>
</head>
<body>
<div class="container">
<div class="toolbar">
    <button id="toTop" class="btn" style="display:flex; flex-direction:column; align-items:center; justify-content:center; gap:2px; padding:4px;"><i class="fas fa-arrow-up"></i><span>Haut</span></button>
</div>
    <!-- JS error panel (visible if errors occur) -->
    <div id="jsErrorPanel" style="display:none;background:linear-gradient(180deg,#2b0f14,#3a1014);color:#ffe6e6;padding:12px;border-radius:8px;margin:12px 0;border:1px solid rgba(255,100,100,0.12);">
        <strong style="display:block;margin-bottom:6px;color:#ffdede">Erreurs JavaScript détectées :</strong>
        <pre id="jsErrors" style="white-space:pre-wrap;margin:0;font-size:13px;color:#fff;max-height:220px;overflow:auto"></pre>
    </div>
    
    <div class="header">
        <div class="brand">
            <i class="fas fa-server" style="font-size:2rem;color:var(--primary);"></i>
            <h1>Rapport de Maintenance - Serveur</h1>
        </div>
        <div class="controls">
            <span style="color:var(--muted);font-size:0.9rem;font-weight:500;">$($Hostname)</span>
            <button id="themeToggle" class="btn btn--theme" title="Basculer entre mode clair et sombre">
                <i class="fas fa-moon" id="themeIcon"></i>
            </button>
        </div>
    </div>
    $menuHtml
    $executiveSummaryHtml
    $rolesHtml
        <div class="section" id="systeme">
            <h2>Informations systeme</h2>
            <div class="info-card">
                <div class="kpi-card card" data-metric="higher-is-bad" style="padding:14px;">
                    <div class="kpi-header">
                        <div class="kpi-icon"><i class="fas fa-server"></i></div>
                        <div class="kpi-number">
                            <div class="info-value">$($Hostname)</div>
                            <div class="label">Nom du Système</div>
                        </div>
                    </div>
                    <div class="small-note">Nom NetBIOS ou FQDN</div>
                </div>

                <div class="kpi-card card" style="padding:14px;">
                    <div class="kpi-header">
                        <div class="kpi-icon"><i class="fas fa-clock"></i></div>
                        <div class="kpi-number">
                            <div class="info-value">$($Uptime.Days)j $($Uptime.Hours)h</div>
                            <div class="label">Uptime</div>
                        </div>
                    </div>
                    <div class="small-note">Temps depuis le dernier démarrage</div>
                </div>

                <div class="kpi-card card" style="padding:14px;">
                    <div class="kpi-header">
                        <div class="kpi-icon"><i class="fas fa-microchip"></i></div>
                        <div class="kpi-number">
                            <div class="info-value">$($CPUName)</div>
                            <div class="label">CPU</div>
                        </div>
                    </div>
                    <div class="small-note">Modèle processeur</div>
                </div>
            </div>
            $($OSInfo)
            $($WarningOS)
        </div>

    <!-- KPI: résumé visuel visible sous Informations systeme -->
    <div class="section" id="kpi">
        <h2>Résumé de Santé du Serveur</h2>
        <div class="kpi-row" style="margin:12px 0 18px; display:flex; flex-wrap:wrap; gap:16px;">
            <!-- Carte Score global -->
            <div class="kpi-card card" style="flex:1 1 260px; display:flex; flex-direction:column; justify-content:space-between;">
                <div class="kpi-header">
                    <div class="kpi-icon"><i class="fas fa-heartbeat"></i></div>
                    <div class="kpi-number">
                        <div class="stat-value" data-target="$HealthScore">$HealthScore/100</div>
                        <div class="label">Score de santé global</div>
                    </div>
                </div>
                <div style="margin-top:8px;">
                    <span class="$HealthBadgeClass"><i class="fas fa-circle"></i> $HealthLabel</span>
                </div>
                <div class="small-note" style="margin-top:8px;">
                    Basé sur l'utilisation CPU, RAM et l'espace disque libre moyen.
                </div>
                <div class="small-note" style="margin-top:6px;">
                    $(if (@($HealthFindings).Count -gt 0) {
                        "<strong>Points à surveiller :</strong><ul>" + ($HealthFindings | ForEach-Object { "<li>$($_)</li>" }) -join '' + "</ul>"
                    } else {
                        "Aucun point bloquant détecté par rapport aux seuils configurés."
                    })
                </div>
            </div>

            <!-- Carte CPU -->
            <div class="kpi-card card" data-metric="higher-is-bad" style="flex:1 1 220px;">
                <div class="kpi-header">
                    <div class="kpi-icon"><i class="fas fa-microchip"></i></div>
                    <div class="kpi-number">
                        <div class="stat-value" data-target="$([math]::Round($CPUUsage,2))">$([math]::Round($CPUUsage,2))%</div>
                        <div class="label">CPU</div>
                    </div>
                </div>
                <div class="progress" style="height:10px;border-radius:8px;margin-top:10px">
                    <span style="width:$([math]::Round($CPUUsage,2))%" data-target="$([math]::Round($CPUUsage,2))" data-metric="higher-is-bad"></span>
                </div>
                <div class="small-note">Utilisation moyenne processeur</div>
            </div>

            <!-- Carte RAM -->
            <div class="kpi-card card" data-metric="higher-is-bad" style="flex:1 1 220px;">
                <div class="kpi-header">
                    <div class="kpi-icon"><i class="fas fa-memory"></i></div>
                    <div class="kpi-number">
                        <div class="stat-value" data-target="$([math]::Round($UsedRAMPercent,2))">$([math]::Round($UsedRAMPercent,2))%</div>
                        <div class="label">RAM</div>
                    </div>
                </div>
                <div class="progress" style="height:10px;border-radius:8px;margin-top:10px">
                    <span style="width:$([math]::Round($UsedRAMPercent,2))%" data-target="$([math]::Round($UsedRAMPercent,2))" data-metric="higher-is-bad"></span>
                </div>
                <div class="small-note">Pourcentage de RAM utilisée</div>
            </div>

            <!-- Carte Disques -->
            <div class="kpi-card card" data-metric="higher-is-good" style="flex:1 1 220px;">
                <div class="kpi-header">
                    <div class="kpi-icon"><i class="fas fa-hdd"></i></div>
                    <div class="kpi-number">
                        <div class="stat-value" data-target="$($AvgDiskFreePercent)">$($AvgDiskFreePercent)%</div>
                        <div class="label">Disque (moyenne libre)</div>
                    </div>
                </div>
                <div class="progress" style="height:10px;border-radius:8px;margin-top:10px">
                    <span style="width:$($AvgDiskFreePercent)%" data-target="$($AvgDiskFreePercent)" data-metric="higher-is-good"></span>
                </div>
                <div class="small-note">Pourcentage moyen d'espace libre</div>
            </div>
        </div>
    </div>

        <div class="section" id="cpu">
            <h2>Utilisation du CPU</h2>
            <div class="info-card">
                <div class="kpi-card card" style="padding:14px;">
                    <div class="kpi-header">
                        <div class="kpi-icon"><i class="fas fa-tachometer-alt"></i></div>
                        <div class="kpi-number">
                            <div class="stat-value" data-target="$([math]::Round($CPUUsage,2))">$([math]::Round($CPUUsage,2))%</div>
                            <div class="label">Utilisation Globale</div>
                        </div>
                    </div>
                    <div class="progress" style="height:10px;border-radius:8px;margin-top:10px"><span style="width:$([math]::Round($CPUUsage,2))%" data-target="$([math]::Round($CPUUsage,2))" data-metric="higher-is-bad"></span></div>
                    <div class="small-note">Utilisation moyenne processeur</div>
                </div>

                <div class="kpi-card card" style="padding:14px;">
                    <div class="kpi-header">
                        <div class="kpi-icon"><i class="fas fa-microchip"></i></div>
                        <div class="kpi-number">
                            <div class="info-value">$($TotalCores)</div>
                            <div class="label">Nombre de Cœurs</div>
                        </div>
                    </div>
                    <div class="small-note">Cœurs physiques</div>
                </div>

                <div class="kpi-card card" style="padding:14px;">
                    <div class="kpi-header">
                        <div class="kpi-icon"><i class="fas fa-stream"></i></div>
                        <div class="kpi-number">
                            <div class="info-value">$($TotalThreads)</div>
                            <div class="label">Nombre de Threads</div>
                        </div>
                    </div>
                    <div class="small-note">Threads logiques / processeurs</div>
                </div>
            </div>
        </div>

        <div class="section" id="ram">
            <h2>Utilisation de la RAM</h2>
            <div class="info-card">
                <div>
                    <h3>RAM Totale</h3>
                    <p>$($TotalRAM.ToString("F2")) GB</p>
                </div>
                <div style="flex:2">
                    <h3>RAM Utilisée</h3>
                    <div class="kpi $(if($UsedRAMPercent -ge 85){'crit'}elseif($UsedRAMPercent -ge 70){'warn'}else{'ok'})">
                        <span class="dot"></span>
                        <p style="margin:0;">
                            $($UsedRAM.ToString("F2")) GB 
                            ($($UsedRAMPercent.ToString("F0"))%)
                        </p>
                    </div>
                    <div class="meter">
                        <span style="width:$($UsedRAMPercent)%" data-target="$($UsedRAMPercent)" data-metric="higher-is-bad"></span>
                    </div>
                    <div class="meter-label">
                        Libre : $($FreeRAM.ToString("F2")) GB 
                        ($((100 - $UsedRAMPercent).ToString("F0"))%)
                    </div>
                </div>
            </div>
        </div>

        <div class="section" id="disques">
            <h2>Disques Locaux</h2>
            <table>
                <tr>
                    <th>Nom du Disque</th>
                    <th>Espace Total (GB)</th>
                    <th>Espace Libre (GB)</th>
                    <th>Pourcentage Libre</th>
                </tr>
"@

foreach ($disk in $DiskInfo) {
    $htmlContent += @"
                <tr>
                    <td>$($disk.DiskName)</td>
                    <td>$($disk.TotalSpaceGB) GB</td>
                    <td>$($disk.FreeSpaceGB) GB</td>
                    <td>
                        <div class='meter'><span style="width:$($disk.FreePercent)%" data-target="$($disk.FreePercent)" data-metric="higher-is-good"></span></div>
                        <div class='meter-label'>$($disk.FreePercentStr)% libre</div>
                    </td>
                </tr>
"@
}

$htmlContent += @"
            </table>
        </div>

        <div class="section" id="reseau">
            <h2>Informations Réseau</h2>
            <table>
                <tr>
                    <th>Adresse IP</th>
                    <td>$($IP)</td>
                </tr>
                <tr>
                    <th>Masque de Sous-Réseau</th>
                    <td>$($SubnetMask)</td>
                </tr>
                <tr>
                    <th>Passerelle</th>
                    <td>$($Gateway)</td>
                </tr>
                <tr>
                    <th>Serveurs DNS</th>
                    <td>$DnsServersHtml</td>
                </tr>
            </table>
        </div>

        $(if ($htmlapps) { @"
        <div class="section" id="logiciels">
            $htmlapps
        </div>
"@ })

        $(if ($htmlreport) { @"
        <div class="section" id="antivirus">
            $htmlreport
        </div>
"@ })

        <div class="section" id="evenements">
            <h2>Journaux d'événements</h2>
            <details open>
                <summary>Voir / masquer les événements</summary>
                $ApplicationEvent
                $SystemEvent
                $events4625HTML
                $events2004
            </details>
        </div>
"@

if ($adRolePresent) {
    $adConnectSection = $null
    if ($ADConnectInstalled) {
        $adConnectSection = @"
            <h2>Informations sur Azure AD Connect</h2>
            <h3>Version Azure AD Connect : $(Escape-Html $ADConnectVersion)</h3>
"@
    }
    if ($ReportAD) {
        $htmlContent += @"
        <div class="section" id="ad">
            <h2>Verifications Active Directory</h2>
            $ReportAD
            $(if ($adConnectSection) { $adConnectSection })
            <h2>Scripts Externes</h2>
            <ul>
                <li><a href="file:///$CleanUpMonster">CleanUp Monster</a></li>
                <li><a href="file:///$gpozaurrPath">GPOZaurr</a></li>
            </ul>
        </div>
"@
    }
}

if ($Config.Services.CheckPrintServer -and $WindowsFeature -and $WindowsFeature.Installed -and $Printers) {
    $htmlContent += @"
        <div class="section" id="imprimantes">
            $Printers
        </div>
"@
}

if ($Config.Services.CheckRDS -and $rdsFeature -and $rdsFeature.InstallState -eq "Installed" -and $ReportRDS) {
    $htmlContent += @"
        <div class="section" id="rds">
            $ReportRDS
        </div>
"@
}

if ($IsFileServer -and $FileSharesInfo -and $FileSharesInfo.Count -gt 0) {
    $fileServerHtml = "<div class='section' id='fileserver'><h2>Serveur de fichiers</h2><table>`n"
    $fileServerHtml += "  <tr><th>Nom du partage</th><th>Chemin</th><th>Description</th></tr>`n"
    foreach ($share in $FileSharesInfo) {
        $desc = if ($share.Description) { $share.Description } else { "" }
        $fileServerHtml += "  <tr><td>$($share.Name)</td><td>$($share.Path)</td><td>$desc</td></tr>`n"
    }
    $fileServerHtml += "</table></div>`n"
    $htmlContent += $fileServerHtml
}

if ($Config.Services.CheckVeeam -and $VBRInstall -and $ReportVBR) {
    $htmlContent += @"
        <div class="section" id="veeam">
            $ReportVBR
        </div>
"@
}

if ($Config.Services.CheckVeeam365 -and $VBOInstall -and $ReportVBO) {
    $htmlContent += @"
        <div class="section" id="veeam365">
            $ReportVBO
        </div>
"@
}

if ($Config.Services.CheckExchange -and $ExchangeInstall -and $ExchangeReport) {
    $htmlContent += @"
        <div class="section" id="exchange">
            $ExchangeReport
        </div>
"@
}

if ($Config.Services.CheckWindowsUpdate -and $wuservice -and $WindowsUpdateReport) {
    $htmlContent += @"
        <div class="section" id="updates">
            $WindowsUpdateReport
        </div>
"@
}

if ($ActionRecommendations.Count -gt 0) {
    # Normaliser et trier les recommandations (par priorite puis categorie)
    $normalizedRecs = foreach ($rec in $ActionRecommendations) {
        if ($rec -is [string]) {
            [pscustomobject]@{
                Category = "General"
                Message  = $rec
                Priority = 2
            }
        } else {
            $rec
        }
    }

    $grouped = $normalizedRecs |
        Sort-Object Priority, Category, Message |
        Get-Unique -AsString |
        Group-Object Priority

    $actionsHtml = "<div class='section' id='actions'><h2>Actions recommandees</h2>`n"

    foreach ($prioGroup in $grouped) {
        $p = $prioGroup.Name
        $prioLabel = switch ($p) {
            1 { "Priorite haute" }
            2 { "Priorite moyenne" }
            3 { "Information" }
            default { "Divers" }
        }
        $actionsHtml += "<h3>$prioLabel</h3><ul>`n"

        foreach ($item in ($prioGroup.Group | Sort-Object Category, Message)) {
            $cat = if ($item.Category) { "[$($item.Category)] " } else { "" }
            $msg = $item.Message
            $actionsHtml += "  <li>$cat$msg</li>`n"
        }

        $actionsHtml += "</ul>`n"
    }

    $actionsHtml += "</div>`n"
    $htmlContent += $actionsHtml
}

$htmlContent += @"
    <footer>
        Rapport genere le : <span id="CreationDate">$(Get-Date)</span> par Script PowerShell
    </footer>
</div>
"@

if ($GlobalError) {
    $htmlContent += @"
<div class="callout danger">
  <div class="title">Attention : erreurs lors de la generation du rapport</div>
  <p>Certaines sections n'ont pas pu etre generees correctement (ex. sauvegardes, Exchange ou Windows Update). Consulter les logs du script pour le detail des erreurs et verifier manuellement les elements critiques.</p>
</div>
"@
}

$htmlContent += @"
<script>
// Injection des seuils depuis la configuration PowerShell
window.maintenanceThresholds = {
    cpu: { good: $($Config.Thresholds.CPU.Good), warning: $($Config.Thresholds.CPU.Warning) },
    ram: { good: $($Config.Thresholds.RAM.Good), warning: $($Config.Thresholds.RAM.Warning) },
    disk: { good: $($Config.Thresholds.Disk.Good), warning: $($Config.Thresholds.Disk.Warning) }
};
</script>
<script>
/* ========= Utilitaires ========= */
var qs = function(sel, root){ root = root || document; return root.querySelector(sel); };
var qsa = function(sel, root){ root = root || document; return Array.prototype.slice.call(root.querySelectorAll(sel)); };

// JS error capture: display runtime errors in the page for easier debugging
function showJSError(msg){
    try {
        var panel = qs('#jsErrorPanel');
        var box = qs('#jsErrors');
        if (!panel || !box) return;
        panel.style.display = 'block';
        box.textContent += msg + "\n";
    } catch(e){ console && console.error && console.error('showJSError failed', e); }
}


window.addEventListener && window.addEventListener('error', function(ev){
    try {
        var msg = (ev && ev.message) ? ev.message : String(ev);
        var src = (ev && ev.filename) ? (' at ' + ev.filename + ':' + ev.lineno + ':' + ev.colno) : '';
        showJSError('[error] ' + msg + src);
    } catch(e){ /* ignore */ }
});
window.addEventListener && window.addEventListener('unhandledrejection', function(ev){
    try { showJSError('[unhandledrejection] ' + (ev && ev.reason ? String(ev.reason) : String(ev))); } catch(e){}
});


/* ========= Back to top ========= */
(function() {
  var toTop = qs('#toTop');
  function onScroll() { if (toTop) toTop.style.display = window.scrollY > 400 ? 'block' : 'none'; }
  window.addEventListener('scroll', onScroll, { passive:true });
  onScroll();
  if (toTop) toTop.addEventListener('click', function() { window.scrollTo({ top:0, behavior:'smooth' }); });
})();


/* ========= Surbrillance du lien de nav actif ========= */
(function() {
  var navEl = qs('nav');
  if (navEl) navEl.classList.add('sticky');

  var links = qsa('nav a[href^="#"]');
  var secs = [];
  links.forEach(function(a) {
    var el = document.querySelector(a.getAttribute('href'));
    if (el) secs.push(el);
  });

  if (!secs.length) return;

  var io = new IntersectionObserver(function(entries) {
    entries.forEach(function(e) {
      if (e.isIntersecting) {
        links.forEach(function(l) { l.classList.remove('active'); });
        var id = '#'+e.target.id;
        links.forEach(function(l) { if (l.getAttribute('href')===id) l.classList.add('active'); });
      }
    });
  }, { rootMargin:'-40% 0px -55% 0px', threshold:0 });

  secs.forEach(function(s) { io.observe(s); });
})();

/* ========= Tri basique des tableaux ========= */
(function() {
  qsa('table').forEach(function(t) {
    var tbody = t.tBodies && t.tBodies[0] ? t.tBodies[0] : t;
    var ths = qsa('th', t);
    ths.forEach(function(th, idx) {
      th.style.cursor = 'pointer';
      th.addEventListener('click', function() {
        var rows = qsa('tr', tbody);
        var asc = th.dataset.sort !== 'asc';
        rows.sort(function(a,b) {
          var ta = a.children[idx] ? a.children[idx].innerText.trim() : '';
          var tb = b.children[idx] ? b.children[idx].innerText.trim() : '';
          var na = parseFloat(ta.replace(',','.'));
          var nb = parseFloat(tb.replace(',','.'));
          if (!isNaN(na) && !isNaN(nb)) return asc ? na - nb : nb - na;
          return asc ? ta.localeCompare(tb) : tb.localeCompare(ta);
        });
        ths.forEach(function(x) { x.removeAttribute('data-sort'); });
        th.dataset.sort = asc ? 'asc' : 'desc';
        rows.forEach(function(r) { tbody.appendChild(r); });
      });
    });
  });
})();

/* ========= Theme Toggle ========= */
(function(){
    function updateThemeIcon(theme) {
        var icon = document.getElementById('themeIcon');
        if (icon) {
            icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
        }
    }
    
    function initTheme() {
        try {
            var savedTheme = localStorage.getItem('theme') || 'light';
            document.documentElement.setAttribute('data-theme', savedTheme);
            updateThemeIcon(savedTheme);
        } catch(e) {
            console.error('Error initializing theme:', e);
        }
    }
    
    function toggleTheme() {
        try {
            var currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
            var newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            updateThemeIcon(newTheme);
        } catch(e) {
            console.error('Error toggling theme:', e);
        }
    }
    
    function setupThemeToggle() {
        var toggleBtn = document.getElementById('themeToggle');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', function(e) {
                e.preventDefault();
                toggleTheme();
            });
        }
    }
    
    // Initialize
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function() {
            initTheme();
            setupThemeToggle();
        });
    } else {
        initTheme();
        setupThemeToggle();
    }
})();

/* ========= KPI animation (compteurs et barres) ========= */
(function(){
    var els = qsa('[data-target]');
    if (!els || !els.length) return;

    function chooseColor(t, m) {
        // Seuils configurables (peuvent être injectés depuis PowerShell)
        var thresholds = window.maintenanceThresholds || {
            cpu: { good: 40, warning: 75 },
            ram: { good: 40, warning: 75 },
            disk: { good: 60, warning: 30 }
        };
        
        if (m === 'higher-is-good') {
            // Pour l'espace disque libre : plus c'est haut, mieux c'est
            if (t >= thresholds.disk.good) return '#10b981'; // Vert
            if (t >= thresholds.disk.warning) return '#f59e0b'; // Orange/Jaune
            return '#ef4444'; // Rouge
        } else {
            // Pour CPU/RAM : plus c'est haut, pire c'est
            var threshold = (m === 'cpu' || m.includes('cpu')) ? thresholds.cpu : thresholds.ram;
            if (t <= threshold.good) return '#10b981'; // Vert
            if (t <= threshold.warning) return '#f59e0b'; // Orange/Jaune
            return '#ef4444'; // Rouge
        }
    }

    els.forEach(function(el){
        var raw = el.getAttribute('data-target');
        if (!raw) return;
        var metric = el.getAttribute('data-metric') || (el.closest && el.closest('.kpi-card') && el.closest('.kpi-card').getAttribute('data-metric')) || 'higher-is-bad';
        var target = parseFloat(String(raw).replace('%',''));
        if (isNaN(target)) return;

        var span = null;
        if (el.tagName === 'SPAN') span = el;
        else {
            var p = el.parentElement && el.parentElement.querySelector('.progress span');
            if (p) span = p;
            // Chercher aussi dans .meter
            if (!span) {
                var m = el.parentElement && el.parentElement.querySelector('.meter span');
                if (m) span = m;
            }
        }

        var current = 0, steps = 45, step = Math.max(0.1, target/steps);
        if (span) {
            // Appliquer la couleur initiale
            span.style.background = chooseColor(target, metric);
            // Ajuster l'ombre selon la couleur
            if (target <= 40 || (metric === 'higher-is-good' && target >= 60)) {
                span.style.boxShadow = '0 2px 4px rgba(16,185,129,0.3)';
            } else if (target <= 75 || (metric === 'higher-is-good' && target >= 30)) {
                span.style.boxShadow = '0 2px 4px rgba(245,158,11,0.3)';
            } else {
                span.style.boxShadow = '0 2px 4px rgba(239,68,68,0.3)';
            }
        }

        var t = setInterval(function(){
            current = Math.min(target, current + step);
            if (el.classList && el.classList.contains('stat-value')) {
                el.textContent = Math.round(current*100)/100 + '%';
            }
            if (span) {
                span.style.width = current + '%';
                span.style.background = chooseColor(current, metric);
                // Ajuster l'ombre selon la couleur actuelle
                if (current <= 40 || (metric === 'higher-is-good' && current >= 60)) {
                    span.style.boxShadow = '0 2px 4px rgba(16,185,129,0.3)';
                } else if (current <= 75 || (metric === 'higher-is-good' && current >= 30)) {
                    span.style.boxShadow = '0 2px 4px rgba(245,158,11,0.3)';
                } else {
                    span.style.boxShadow = '0 2px 4px rgba(239,68,68,0.3)';
                }
            }
            if (current >= target) clearInterval(t);
        }, 12);
    });
})();
</script>
</body>
</html>
"@

Write-HostSafe "# ============================="
Write-HostSafe "# Block 14 : Sauvegarde du Rapport HTML"
Write-HostSafe "# ============================="

# Sauvegarder le rapport HTML localement
$htmlContent | Out-File -FilePath $outputPath -Encoding utf8
Write-HostSafe "Le rapport HTML a ete genere avec succes a l'emplacement : $outputPath"

Write-HostSafe "# ============================="
Write-HostSafe "# Block 14b : Rapport complet a onglets et archive"
Write-HostSafe "# ============================="

# Les outils (ADChecker, GPOZaurr, CleanupMonster, HealthChecker...) ecrivent chacun leur rapport dans leur dossier.
# On les regroupe dans un seul HTML autonome (un onglet par rapport), puis dans un zip avec les fichiers d'origine :
#   Export\<SERVEUR>_Maintenance_<AAAAMM>.html et .zip
# Seuls les fichiers produits par cette execution sont repris (un ancien rapport ne doit pas passer pour actuel).
function New-MaintenanceArchive {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$MainReport,
        [Parameter(Mandatory)][datetime]$Since,
        [string]$Server = $env:COMPUTERNAME,
        [string]$Period = (Get-Date -Format 'yyyyMM')
    )
    # Ordre des onglets ; Kind = html (affiche tel quel) ou text (affiche en texte brut)
    $sources = @(
        @{ Title = 'Maintenance';              Dir = '';                   Filter = [System.IO.Path]::GetFileName($MainReport); Kind = 'html' },
        @{ Title = 'AD Health';                Dir = 'ADChecker';          Filter = 'ADHealthReport.html';             Kind = 'html' },
        @{ Title = 'GPOZaurr';                 Dir = '';                   Filter = 'GPOZaurr.html';                   Kind = 'html' },
        @{ Title = 'CleanupMonster';           Dir = '';                   Filter = 'CleanUpMonster.html';             Kind = 'html' },
        @{ Title = 'Exchange HealthChecker';   Dir = 'HealthChecker';      Filter = 'ExchangeAllServersReport.html';   Kind = 'html' },
        @{ Title = 'Boites aux lettres';       Dir = 'ExchangeSizeReport'; Filter = 'MailboxSize_*.html';              Kind = 'html' },
        @{ Title = 'HealthChecker (texte)';    Dir = 'HealthChecker';      Filter = 'HealthChecker-*.txt';             Kind = 'text' },
        @{ Title = 'dcdiag';                   Dir = 'dcdiag';             Filter = 'dcdiag_*.txt';                    Kind = 'text' },
        @{ Title = 'dcdiag DNS';               Dir = 'dcdiag';             Filter = 'dcdiagdns_*.txt';                 Kind = 'text' },
        @{ Title = 'Echecs de connexion';      Dir = 'events';             Filter = 'logonfail_*.csv';                 Kind = 'text' }
    )
    $found = @()
    foreach ($s in $sources) {
        $dir = if ($s.Dir) { Join-Path $Root $s.Dir } else { $Root }
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        $file = Get-ChildItem -Path $dir -Filter $s.Filter -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge $Since } |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($file) {
            $rel = if ($s.Dir) { "$($s.Dir)/$($file.Name)" } else { $file.Name }
            $found += [pscustomobject]@{ Title = $s.Title; Kind = $s.Kind; Path = $file.FullName; Rel = $rel }
        }
    }
    if ($found.Count -eq 0) { throw "aucun rapport produit par cette execution" }

    $exportDir = Join-Path $Root 'Export'
    if (-not (Test-Path -LiteralPath $exportDir)) { New-Item -ItemType Directory -Path $exportDir -Force | Out-Null }
    $baseName = "${Server}_Maintenance_$Period"
    $htmlPath = Join-Path $exportDir "$baseName.html"
    $zipPath  = Join-Path $exportDir "$baseName.zip"
    $enc = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }

    # Chaque rapport est stocke encode dans un <textarea> et charge dans une iframe (srcdoc) au premier clic :
    # les styles et scripts des outils restent isoles et la page s'ouvre vite meme avec de gros rapports.
    $tabs = New-Object System.Text.StringBuilder
    $panes = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $found.Count; $i++) {
        $f = $found[$i]
        $raw = [System.IO.File]::ReadAllText($f.Path)
        $active = if ($i -eq 0) { ' active' } else { '' }
        [void]$tabs.Append("<button class='tab$active' data-i='$i' title='$(& $enc $f.Rel)'>$(& $enc $f.Title)</button>")
        if ($f.Kind -eq 'html') {
            [void]$panes.Append("<div class='pane$active' id='p$i'><textarea hidden id='s$i'>$(& $enc $raw)</textarea><iframe id='f$i'></iframe></div>")
        } else {
            [void]$panes.Append("<div class='pane$active' id='p$i'><pre>$(& $enc $raw)</pre></div>")
        }
    }
    $generated = Get-Date -Format 'dd.MM.yyyy HH:mm'
    $page = @"
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>$(& $enc $Server) - Maintenance $Period</title>
<style>
html, body { margin: 0; height: 100%; font-family: Segoe UI, Arial, sans-serif; }
body { display: flex; flex-direction: column; }
header { background: #1f3a5f; color: #fff; padding: 8px 16px; }
header h1 { margin: 0; font-size: 18px; }
header span { font-size: 12px; opacity: .8; }
nav { display: flex; flex-wrap: wrap; gap: 2px; background: #e8edf3; padding: 4px 8px 0; border-bottom: 1px solid #b8c4d2; }
.tab { border: 1px solid #b8c4d2; border-bottom: none; background: #f6f8fa; padding: 6px 12px; cursor: pointer; font-size: 13px; border-radius: 4px 4px 0 0; }
.tab.active { background: #fff; font-weight: 600; }
main { flex: 1; position: relative; }
.pane { display: none; position: absolute; inset: 0; overflow: auto; }
.pane.active { display: block; }
.pane iframe { border: 0; width: 100%; height: 100%; }
.pane pre { margin: 0; padding: 12px 16px; font: 12px Consolas, monospace; white-space: pre-wrap; }
</style>
</head>
<body>
<header><h1>$(& $enc $Server) - Maintenance $Period</h1><span>Genere le $generated</span></header>
<nav>$($tabs.ToString())</nav>
<main>$($panes.ToString())</main>
<script>
(function () {
  function show(i) {
    document.querySelectorAll('.tab, .pane').forEach(function (e) { e.classList.remove('active'); });
    document.querySelector('.tab[data-i="' + i + '"]').classList.add('active');
    document.getElementById('p' + i).classList.add('active');
    var f = document.getElementById('f' + i), s = document.getElementById('s' + i);
    if (f && s && !f.dataset.loaded) { f.srcdoc = s.value; f.dataset.loaded = '1'; }
  }
  document.querySelectorAll('.tab').forEach(function (b) { b.addEventListener('click', function () { show(b.dataset.i); }); });
  show(0);
})();
</script>
</body>
</html>
"@
    [System.IO.File]::WriteAllText($htmlPath, $page, (New-Object System.Text.UTF8Encoding $false))

    # Zip : le rapport complet a la racine, les fichiers d'origine dans originaux\ (arborescence conservee)
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
    $zip = [System.IO.Compression.ZipFile]::Open($zipPath, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $htmlPath, "$baseName.html")
        foreach ($f in $found) {
            [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $f.Path, "originaux/$($f.Rel)")
        }
    } finally { $zip.Dispose() }

    $zipItem = Get-Item -LiteralPath $zipPath
    return [ordered]@{
        file      = $zipItem.Name
        path      = $zipItem.FullName
        sizeBytes = $zipItem.Length
        sha256    = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash
        tabs      = @($found | ForEach-Object { $_.Title })
    }
}

$script:MreArchive = $null
try {
    $runStart = [datetime]::Parse($script:Mre.generatedAt, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime().AddMinutes(-1)
    $script:MreArchive = New-MaintenanceArchive -Root $Config.OutputPath -MainReport $outputPath -Since $runStart -Server $Hostname
    Write-HostSafe "Rapport complet et archive : $($script:MreArchive.path) ($([math]::Round($script:MreArchive.sizeBytes / 1MB, 1)) Mo, onglets : $($script:MreArchive.tabs -join ', '))"
} catch {
    Write-Warning "Rapport complet / archive impossible : $($_.Exception.Message)"
    Add-MreError -Section 'export' -Message "archive des rapports impossible : $($_.Exception.Message)"
}

# Depot du zip dans le partage Nextcloud (WebDAV public : identifiant = jeton du partage, mot de passe du partage).
# Le partage est en depot seul : le serveur ne peut ni lire ni lister ce que les autres ont depose.
# Le nom porte l'horodatage : un nouveau passage dans le mois n'ecrase rien, le moteur prend le plus recent
# dont l'empreinte correspond au JSON.
function Send-MaintenanceArchive {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ShareUrl,
        [string]$Password = '',
        [string]$ProxyServer = '',
        [string]$ProxyBypass = ''
    )
    if ($ShareUrl -notmatch '^(https?://[^/]+(?:/.*?)?)/(?:index\.php/)?s/([A-Za-z0-9]+)/?$') {
        throw "lien de partage Nextcloud non reconnu : $ShareUrl"
    }
    $base, $token = ($matches[1] -replace '/index\.php$', ''), $matches[2]
    $item = Get-Item -LiteralPath $Path
    $name = [System.IO.Path]::GetFileNameWithoutExtension($item.Name) + '_' + (Get-Date -Format 'yyyyMMdd-HHmmss') + $item.Extension
    # Adresse WebDAV publique actuelle (Nextcloud 29+). Un partage "demande de fichiers" exige un pseudonyme
    # (X-NC-Nickname) : on donne le nom du serveur.
    $uri = [Uri]("$base/public.php/dav/files/$token/" + [Uri]::EscapeDataString($name))

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $req = [System.Net.HttpWebRequest]::Create($uri)
    $req.Method = 'PUT'
    $req.Timeout = 600000
    $req.ReadWriteTimeout = 600000
    $req.AllowWriteStreamBuffering = $false
    $req.ContentLength = $item.Length
    $req.ContentType = 'application/zip'
    $req.Headers['Authorization'] = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("${token}:$Password"))
    $req.Headers['X-Requested-With'] = 'XMLHttpRequest'
    $req.Headers['X-NC-Nickname'] = $env:COMPUTERNAME
    # Proxy WinHTTP de la machine (System ne l'applique pas forcement), sauf si l'hote est dans la liste d'exclusion
    $req.Proxy = $null
    if ($ProxyServer) {
        $hostName = $uri.Host
        $bypassed = $false
        foreach ($b in ($ProxyBypass -split '[;,\s]+' | Where-Object { $_ })) {
            if ($b -eq '<local>') { if ($hostName -notmatch '\.') { $bypassed = $true } }
            elseif ($hostName -like $b) { $bypassed = $true }
        }
        if (-not $bypassed) {
            $proxy = $ProxyServer
            if ($proxy -match '(?i)(?:^|;)https=([^;\s]+)') { $proxy = $matches[1] }
            elseif ($proxy -match '(?i)(?:^|;)http=([^;\s]+)') { $proxy = $matches[1] }
            if ($proxy -notmatch '^[a-z]+://') { $proxy = "http://$proxy" }
            $req.Proxy = New-Object System.Net.WebProxy($proxy)
            $req.Proxy.UseDefaultCredentials = $true
        }
    }
    $in = [System.IO.File]::OpenRead($item.FullName)
    try {
        $out = $req.GetRequestStream()
        try { $in.CopyTo($out) } finally { $out.Dispose() }
    } finally { $in.Dispose() }
    $resp = $req.GetResponse()
    try { $code = [int]$resp.StatusCode } finally { $resp.Dispose() }
    return [ordered]@{ status = 'ok'; name = $name; httpStatus = $code }
}

if ($script:MreArchive -and $DropUrl) {
    try {
        $script:MreArchive.upload = Send-MaintenanceArchive -Path $script:MreArchive.path -ShareUrl $DropUrl -Password $DropPassword `
            -ProxyServer ([string]$mreWinHttpProxy.server) -ProxyBypass ([string]$mreWinHttpProxy.bypass)
        Write-HostSafe "Archive deposee dans Nextcloud : $($script:MreArchive.upload.name)"
    } catch {
        $msg = $_.Exception.Message
        if ($_.Exception.InnerException) { $msg = $_.Exception.InnerException.Message }
        $script:MreArchive.upload = [ordered]@{ status = 'error'; error = $msg }
        Write-Warning "Depot Nextcloud impossible : $msg"
        Add-MreError -Section 'export' -Message "depot Nextcloud impossible : $msg"
    }
}

Write-HostSafe "# ============================="
Write-HostSafe "# Block 15 : Export JSON (v3.3)"
Write-HostSafe "# ============================="

try {
    Set-MreSection -Name 'roles' -Value @($rolesSummary | ForEach-Object { [ordered]@{ name = $_.Name; status = $_.Status } })
    Set-MreSection -Name 'recommendations' -Value @($normalizedRecommendations | Where-Object { $_ } | ForEach-Object {
        [ordered]@{ category = $_.Category; priority = $_.Priority; message = [System.Net.WebUtility]::HtmlDecode([string]$_.Message) } })
    Set-MreSection -Name 'scores' -Value ([ordered]@{
        global  = [ordered]@{ score = $HealthScore; label = $HealthLabel }
        domains = @($domainScores | Where-Object { $_ } | ForEach-Object {
            [ordered]@{ domain = $_.Domain; score = $_.Score; label = $_.Label; high = $_.High; medium = $_.Medium; info = $_.Info } })
    })
    if ($VBRInstall -or $VBOInstall) { Set-MreSection -Name 'veeam' -Value $script:MreVeeam }
    if ($ExchangeInstall) { Set-MreSection -Name 'exchange' -Value $script:MreExchange }

    if ($script:MreStaleComputers -and $script:Mre.sections.activeDirectory) {
        $script:Mre.sections.activeDirectory.staleComputers = $script:MreStaleComputers
    }
    $script:Mre.toolIntegrityErrors = @($script:ToolIntegrityErrors)
    $script:Mre.reportHtml = $outputPath
    $script:Mre.reportArchive = $script:MreArchive
    $script:Mre.completedAt = (Get-Date).ToUniversalTime().ToString('o')

    $jsonFull = $script:Mre | ConvertTo-Json -Depth 12
    $jsonPath = [System.IO.Path]::ChangeExtension($outputPath, 'json')
    [System.IO.File]::WriteAllText($jsonPath, $jsonFull, (New-Object System.Text.UTF8Encoding $false))
    Write-HostSafe "Le rapport JSON a ete genere : $jsonPath"
} catch {
    Write-Warning "Export JSON impossible : $($_.Exception.Message)"
    $jsonFull = $null
}

# Purge des anciens artefacts : on garde les KeepLastReports plus recents de chaque famille de fichiers
# (MaxLogFiles pour les journaux). Les sous-dossiers d'archives manuelles (ex. 2026\) ne sont pas touches.
function Clear-OldArtifacts {
    $root = $Config.OutputPath
    $keep = [int]$Config.Export.KeepLastReports
    if ($keep -lt 1) { $keep = 10 }
    $keepLogs = [int]$Config.Logging.MaxLogFiles
    if ($keepLogs -lt 1) { $keepLogs = 30 }
    $families = @(
        @{ Dir = '';                   Filter = "$($reportPrefix)_*.html" },
        @{ Dir = '';                   Filter = "$($reportPrefix)_*.json" },
        @{ Dir = 'dcdiag';             Filter = 'dcdiag_*.txt' },
        @{ Dir = 'dcdiag';             Filter = 'dcdiagdns_*.txt' },
        @{ Dir = 'events';             Filter = 'logonfail_*.csv' },
        @{ Dir = 'HealthChecker';      Filter = 'HealthChecker-*.txt' },
        @{ Dir = 'HealthChecker';      Filter = 'HealthChecker-*.xml' },
        @{ Dir = 'HealthChecker';      Filter = 'ExchangeAllServersReport_*.html' },
        @{ Dir = 'ExchangeSizeReport'; Filter = 'MailboxSize_*.html' },
        @{ Dir = 'Export';             Filter = '*_Maintenance_*.html' },
        @{ Dir = 'Export';             Filter = '*_Maintenance_*.zip' },
        @{ Dir = 'logs';               Filter = '*'; Keep = $keepLogs }
    )
    $removed = 0
    foreach ($f in $families) {
        $dir = if ($f.Dir) { Join-Path $root $f.Dir } else { $root }
        if (-not (Test-Path $dir)) { continue }
        $n = if ($f.Keep) { $f.Keep } else { $keep }
        $old = @(Get-ChildItem -Path $dir -Filter $f.Filter -File -ErrorAction SilentlyContinue |
                 Sort-Object LastWriteTime -Descending | Select-Object -Skip $n)
        foreach ($o in $old) {
            try { Remove-Item -LiteralPath $o.FullName -Force -ErrorAction Stop; $removed++ }
            catch { Write-Warning "Purge impossible : $($o.FullName) ($($_.Exception.Message))" }
        }
    }
    # Modules extraits par les executions precedentes (ceux de l'execution en cours restent charges)
    Get-ChildItem -Path $env:TEMP -Directory -Filter 'DFI-MRE-modules-*' -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -ne $script:PinnedModulesRoot } | ForEach-Object {
            Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
            if (-not (Test-Path -LiteralPath $_.FullName)) { $removed++ }
        }
    Write-HostSafe "Purge : $removed ancien(s) element(s) supprime(s) (conservation : $keep par type, $keepLogs journaux)."
}

try { Clear-OldArtifacts } catch { Write-Warning "Purge des anciens artefacts impossible : $($_.Exception.Message)" }

# Ecriture dans le custom field NinjaOne (uniquement sous l'agent NinjaOne et si -NinjaField est fourni)
function ConvertTo-Gzip64 {
    param([string]$Text)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $ms = New-Object System.IO.MemoryStream
    $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress)
    $gz.Write($bytes, 0, $bytes.Length)
    $gz.Close()
    return 'gz64:' + [Convert]::ToBase64String($ms.ToArray())
}

# Ninja-Property-Set n'existe que dans la session lancee par l'agent ; ninjarmm-cli.exe sert de repli
function Set-NinjaField {
    param([string]$Name, [string]$Value)
    if (Get-Command Ninja-Property-Set -ErrorAction SilentlyContinue) {
        Ninja-Property-Set -Name $Name -Value $Value | Out-Null
        return $true
    }
    $cli = Join-Path $env:ProgramData 'NinjaRMMAgent\ninjarmm-cli.exe'
    if (Test-Path $cli) {
        & $cli set $Name $Value | Out-Null
        return ($LASTEXITCODE -eq 0)
    }
    return $false
}

if ($NinjaField) {
    $ninjaAvailable = [bool](Get-Command Ninja-Property-Set -ErrorAction SilentlyContinue) -or (Test-Path (Join-Path $env:ProgramData 'NinjaRMMAgent\ninjarmm-cli.exe'))
    if (-not $ninjaAvailable) {
        Write-Warning "-NinjaField fourni mais ni Ninja-Property-Set ni ninjarmm-cli.exe ne sont disponibles (agent NinjaOne absent ?)."
    } elseif (-not $jsonFull) {
        $null = Set-NinjaField -Name $NinjaField -Value ("error:export JSON impossible sur $env:COMPUTERNAME a " + (Get-Date).ToUniversalTime().ToString('o'))
    } else {
        $payload = ConvertTo-Gzip64 -Text ($script:Mre | ConvertTo-Json -Depth 12 -Compress)
        if ($payload.Length -gt $NinjaMaxChars) {
            # Allegement : on retire les champs volumineux et secondaires, en le signalant dans le JSON
            Write-Warning "JSON compresse trop volumineux ($($payload.Length) > $NinjaMaxChars) : allegement."
            foreach ($log in @($script:Mre.sections.eventLogs.logs.Values)) {
                foreach ($g in @($log.groups)) { $g.sample = $null }
            }
            $script:Mre.sections.software = $null
            $script:Mre.reduced = $true
            $payload = ConvertTo-Gzip64 -Text ($script:Mre | ConvertTo-Json -Depth 12 -Compress)
        }
        if ($payload.Length -gt $NinjaMaxChars) {
            Write-Warning "JSON toujours trop volumineux ($($payload.Length)) : marqueur d'erreur ecrit a la place."
            $null = Set-NinjaField -Name $NinjaField -Value ("error:JSON trop volumineux ($($payload.Length) caracteres) sur $env:COMPUTERNAME, voir $jsonPath")
        } else {
            if (Set-NinjaField -Name $NinjaField -Value $payload) {
                Write-HostSafe "JSON ecrit dans le custom field NinjaOne '$NinjaField' ($($payload.Length) caracteres)."
            } else {
                Write-Warning "Echec de l'ecriture du custom field NinjaOne '$NinjaField'."
            }
        }
    }
}
