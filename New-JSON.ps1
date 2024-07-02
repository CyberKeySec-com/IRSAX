# Fonction pour récupérer le DN du domaine
function Get-DomainInformation {    
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("NetBIOS", "DNS", "DistinguishedName", "Master")]
        [string]$Type,

        [Parameter(Mandatory=$true)]        
        [string]$Information
    )
    $useAuto = Read-Host "Use the automatically retrieved domain $Type ($Information)? [Y/N] (default: Y)"
    if (-not $useAuto) { $useAuto = 'Y' }
    if ($useAuto -ieq 'Y') {
        return $Information
    } else {
        switch ($Type) {
            NetBIOS { return Read-Host "Enter the old domain NetBIOS DN (e.g., OLD)" }
            DNS { return Read-Host "Enter the old domain name (e.g., old.com)" }
            DistinguishedName { return Read-Host "Enter the old domain DN (e.g., DC=old,DC=com)" }
            Master { return Read-Host "Enter the old master domain controller (e.g., SRVDC01)" }
            Default {"Type unknow...`nPlease select correctly type of your information and try again (`"NetBIOS`", `"DNS`", `"DistinguishedName`", `"Master`")";return $null}
        }        
    }
}

function Convert-DomainToDistinguishedName {
    param (
        [Parameter(Mandatory=$true)]
        [string]$DomainName
    )    
    
    $components        = $DomainName.Split('.')
    $dnParts           = $components | ForEach-Object { "DC=$_"}
    $distinguishedName = $dnParts -join ','
    
    return $distinguishedName
}

# Demander les paramètres liés au script
$outputDirectory = Read-Host 'Enter the output directory (default: $PSScriptRoot\Output)'
if (-not $outputDirectory) { $outputDirectory = '$PSScriptRoot\Output' }

$inputDirectory = Read-Host 'Enter the input directory (default: $PSScriptRoot\Source)'
if (-not $inputDirectory) { $inputDirectory = '$PSScriptRoot\Source' }

$logFilePath = Read-Host 'Enter the log file path (default: $PSScriptRoot\Logs\ScriptLog.txt)'
if (-not $logFilePath) { $logFilePath = '$PSScriptRoot\Logs\ScriptLog.txt' }

try { $domain = Get-ADDomain }catch { Write-Output "Failed to retrieve Active Directory informations: $_" }

$oldDomainDN    = Get-DomainInformation -Type DistinguishedName -Information ($domain).DistinguishedName # DC = annuaire, DC = irsax, DC = com
$oldNetBIOSName = Get-DomainInformation -Type NetBIOS -Information ($domain).NetBIOSName # ANNUAIRE
$oldDomainName  = Get-DomainInformation -Type DNS -Information ($domain).DNSRoot # annuaire.irsax.com
$MasterDC       = Get-DomainInformation -Type Master -Information (($domain).InfrastructureMaster).Split(".")[0] # SRVDCPV01

# Créer l'objet de configuration
$config = @{
    Parameters = @{
        OutputDirectory = $outputDirectory
        InputDirectory  = $inputDirectory
        LogFilePath     = $logFilePath
    }
    DomainInfo = @{
        Old = @{
            Name              = $oldDomainName
            DistinguishedName = $oldDomainDN
            NetBIOS           = $oldNetBIOSName
            MasterDC          = $MasterDC
        }              
    }
}

# Convertir l'objet de configuration en JSON et sauvegarder dans un fichier
$config | ConvertTo-Json -Depth 10 | Set-Content -Path "$PSScriptRoot\Source\config.json" -Force

Write-Output "Configuration file 'config.json' created successfully."