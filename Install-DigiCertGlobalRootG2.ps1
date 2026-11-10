# Ajoute la racine DigiCert Global Root G2 au magasin "Autorites de certification racines de confiance"
# de l'ordinateur (script NinjaOne, a executer en tant que System).
#
# Utile sur les serveurs sans mise a jour automatique des racines (DC sans acces Windows Update, GPO
# "Turn off Automatic Root Certificates Update") : le depot des rapports dans Nextcloud (certificat RapidSSL,
# racine DigiCert Global Root G2) y echoue avec "Could not establish trust relationship for the SSL/TLS
# secure channel". Sans effet si la racine est deja presente. Texte en ASCII (encodage NinjaOne).

$Thumbprint = 'DF3C24F9BFD666761B268073FE06D1CC8D4F82A4'   # SHA-1 publie par DigiCert
$Sha256     = 'CB3CCBB76031E5E0138F8DD39A23F9DE47FFC35E43C1144CEA27D46A5AB1CB5F'
$CertB64    = 'MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBhMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBHMjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI2/Ou8jqJkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx1x7e/dfgy5SDN67sH0NO3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQq2EGnI/yuum06ZIya7XzV+hdG82MHauVBJVJ8zUtluNJbd134/tJS7SsVQepj5WztCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyMUNGPHgm+F6HmIcr9g+UQvIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV5uNu5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY1Yl9PMWLSn/pvtsrF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4NeF22d+mQrvHRAiGfzZ0JFrabA0UWTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NGFdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBHQRFXGU7Aj64GxJUTFy8bJZ918rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/iyK5S9kJRaTepLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LZZm6zNTflMrY='

$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine')
$store.Open('ReadWrite')
try {
    if ($store.Certificates | Where-Object { $_.Thumbprint -eq $Thumbprint }) {
        Write-Output "DigiCert Global Root G2 deja presente ($env:COMPUTERNAME)."
        exit 0
    }
    $bytes = [Convert]::FromBase64String($CertB64)
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$bytes)
    $sha = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($bytes)) -replace '-', ''
    if ($cert.Thumbprint -ne $Thumbprint -or $sha -ne $Sha256) {
        Write-Output "ERREUR : empreinte inattendue ($($cert.Thumbprint)), rien n'est importe."
        exit 1
    }
    $store.Add($cert)
    Write-Output "DigiCert Global Root G2 ajoutee ($env:COMPUTERNAME), expire le $($cert.NotAfter.ToString('dd.MM.yyyy'))."
} finally {
    $store.Close()
}

# Verification : connexion HTTPS a Nextcloud
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $r = [System.Net.HttpWebRequest]::Create('https://nextcloud.cheops-services.ch/status.php')
    $r.Timeout = 15000
    $resp = $r.GetResponse(); Write-Output "Test HTTPS Nextcloud : $([int]$resp.StatusCode)"; $resp.Close()
} catch {
    Write-Output "Test HTTPS Nextcloud en echec : $($_.Exception.Message)"
}
exit 0
