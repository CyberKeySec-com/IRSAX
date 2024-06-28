# Fonction pour récupérer le DN du domaine
function Get-DomainDN {
    try {
        $domainDN = (Get-ADDomain).DistinguishedName
        return $domainDN
    } catch {
        Write-Error "Error retrieving domain DN: $_"
        return $null
    }
}

function Get-PrimaryDC {
    try {
        $PrimaryDC = (Get-ADDomainController -Discover -Service PrimaryDC).Name
        return $PrimaryDC
    }
    catch {
        Write-Error "Error retrieving PrimaryDC: $_"
        return $null
    }
}

# Demander les paramètres liés au script
$outputDirectory = Read-Host 'Enter the output directory (default: $PSScriptRoot\Output)'
if (-not $outputDirectory) { $outputDirectory = '$PSScriptRoot\Output' }

$inputDirectory = Read-Host 'Enter the input directory (default: $PSScriptRoot\Source)'
if (-not $inputDirectory) { $inputDirectory = '$PSScriptRoot\Source' }

$logFilePath = Read-Host 'Enter the log file path (default: $PSScriptRoot\Logs\ScriptLog.txt)'
if (-not $logFilePath) { $logFilePath = '$PSScriptRoot\Logs\ScriptLog.txt' }

# Demander les informations de domaine
# Récupérer le DN du domaine
$domainDN = Get-DomainDN
if (-not $domainDN) {
    Write-Warning "Failed to retrieve the domain DN."
    $oldDomainName = Read-Host "Enter the old domain name (e.g., DC=old,DC=com)"    
}
else{
    # Demander si l'utilisateur veut utiliser le DN récupéré automatiquement
    $useAutoDN = Read-Host "Use the automatically retrieved domain DN ($domainDN)? [Y/N] (default: Y)"
    if (-not $useAutoDN) { $useAutoDN = 'Y' }
    if ($useAutoDN -ieq 'Y') {
        $oldDomainName = $domainDN
    } else {
        $oldDomainName = Read-Host "Enter the old domain name DN (e.g., DC=old,DC=com)"
    }
}

$newDomainName = Read-Host "Enter the new domain name (e.g., DC=new,DC=com)"

# Récupérer le PrimaryDC
$primaryDC = Get-PrimaryDC
if (-not $primaryDC) {
    Write-Warning "Failed to retrieve the PrimaryDC."
    $domainController = Read-Host "Enter the domain controller (e.g., DC1)"    
}
else{
    # Demander si l'utilisateur veut utiliser le DN récupéré automatiquement
    $useAutoDC = Read-Host "Use the automatically retrieved PrimaryDC name ($primaryDC)? [Y/N] (default: Y)"
    if (-not $useAutoDC) { $useAutoDC = 'Y' }
    if ($useAutoDC -ieq 'Y') {
        $domainController = $primaryDC
    } else {
        $domainController = Read-Host "Enter the domain controller (e.g., DC1)"
    }
}

# Créer l'objet de configuration
$config = @{
    Parameters = @{
        OutputDirectory = $outputDirectory
        InputDirectory = $inputDirectory
        LogFilePath = $logFilePath
    }
    DomainInfo = @{
        OldDomainName = $oldDomainName
        NewDomainName = $newDomainName
        DomainController = $domainController
    }
}

# Convertir l'objet de configuration en JSON et sauvegarder dans un fichier
$config | ConvertTo-Json -Depth 10 | Set-Content -Path "$PSScriptRoot\Source\config.json" -Force

Write-Output "Configuration file 'config.json' created successfully."
