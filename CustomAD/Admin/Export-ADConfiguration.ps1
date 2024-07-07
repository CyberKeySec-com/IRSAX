#region modules
Import-Module ActiveDirectory
#endregion

#region functions

# Function to log messages to a file
function Log-Message {
    param (
        [string]$message,
        [string]$type = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp [$type] - $message" | Out-File -Append -FilePath "$PSScriptRoot\Logs\Scriptfile-admin.txt"
}

# Function to handle errors
function Handle-Error {
    param (
        [string]$errorMessage
    )
    Log-Message $errorMessage "ERROR"
    exit 1
}

# Function to backup GPOs
function Backup-GPOs {
    param (
        [Parameter(Mandatory = $true)]
        [string]$exportDir
    )    
    $permissions = @()
    $gpoData = @()

    # Create the directory if it does not exist
    if (-not (Test-Path -Path $exportDir)) {
        New-Item -ItemType Directory -Path $exportDir | Out-Null        
    }

    # Get all GPOs
    $GPOs = Get-GPO -All

    # Export each GPO
    foreach ($GPO in $GPOs) {
        $GPOName       = $GPO.DisplayName
        $GPOBackupPath = Join-Path -Path $exportDir -ChildPath $GPOName

        Log-Message "Exporting GPO: $GPOName to $GPOBackupPath"

        # Create a directory for each GPO
        if (-not (Test-Path -Path $GPOBackupPath)) {
            New-Item -ItemType Directory -Path $GPOBackupPath | Out-Null
        }

        # Export the GPO
        Backup-GPO -Name $GPOName -Path $GPOBackupPath | Out-Null

        $acls = Get-GPODelegation -Name $GPO.Id        
        foreach($acl in $acls){
            $trustee = $acl.Trustee | Select-Object Domain, Name, @{Name='Sid'; Expression={$_.Sid.Value}}, SidType
            $action = $acl.Permission 
            $inherited = $acl.Inherited 
            $inheritable = $acl.Inheritable
            $object = [PSCustomObject]@{
                Trustee             = $trustee
                Permission          = $action
                Inherited           = $inherited
                Inheritable         = $inheritable
            }
            $permissions += $object
        }        
        $gpoData += [PSCustomObject]@{
            DisplayName         = $GPO.DisplayName
            Id                  = $GPO.Id
            Owner               = $GPO.Owner
            UserVersion         = $GPO.UserVersion
            ComputerVersion     = $GPO.ComputerVersion
            Permissions         = $permissions            
        }
    }
    $gpoData | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path (Split-Path -Path $exportDir) "GPOs.json") -Encoding UTF8
    Log-Message "GPO export completed successfully."
}

# Function to convert domain name to Distinguished Name
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

# Function to export AD groups
function Export-Groups {
    param (
        [Parameter(Mandatory = $true)]
        [string]$exportDir
    )

    # Create the directory if it does not exist
    if (-not (Test-Path -Path $exportDir)) {
        New-Item -ItemType Directory -Path $exportDir | Out-Null
    }

    $groups = Get-ADGroup -Filter * -Properties DistinguishedName, Name, GroupScope, GroupCategory, Description | Select-Object DistinguishedName, Name, GroupScope, GroupCategory, Description
    $groupData = @()

    foreach ($group in $groups) {
        $members = Get-ADGroupMember -Identity $group.DistinguishedName | Where-Object {$_.objectClass -eq "group"} | Select-Object DistinguishedName, Name

        $groupData += [PSCustomObject]@{
            DistinguishedName = $group.DistinguishedName
            Name              = $group.Name
            Description       = $group.Description
            GroupScope        = $group.GroupScope
            GroupCategory     = $group.GroupCategory
            Members           = $members
        }
    }

    $groupData | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $exportDir "Groups.json") -Encoding UTF8
    Log-Message "Groups exported successfully."
}

# Function to export OUs
function Export-OUs {
    param (
        [Parameter(Mandatory = $true)]
        [string]$exportDir
    )
    if (-not (Test-Path -Path $exportDir)) {
        New-Item -ItemType Directory -Path $exportDir | Out-Null
    }

    $ous = Get-ADOrganizationalUnit -Filter * -Properties DistinguishedName, Name, Description | Select-Object DistinguishedName, Name, Description
    $ouData = @()

    foreach ($ou in $ous) {
        $ouDN = $ou.DistinguishedName   
        $acl = Get-ACL -Path "AD:$ouDN" 
        $owner = $acl.Owner
        $ownerGroup = $acl.Group
        $inheritance = Get-GPInheritance -Target $ouDN
        $inheritanceBlocked = $inheritance.GpoInheritanceBlocked
        $gpoLinks = $inheritance.GpoLinks
        $ouData += [PSCustomObject]@{            
            DistinguishedName   = $ou.DistinguishedName
            Name                = $ou.Name
            Description         = $ou.Description
            Owner               = $owner
            OwnerGroup          = $ownerGroup            
            InheritanceBlocked  = $inheritanceBlocked
            Links               = ($gpoLinks | Select-Object DisplayName, Enabled, Enforced, Order | ForEach-Object {
                if ([string]::IsNullOrWhiteSpace($_.DisplayName)) {
                    $_.DisplayName = 'None'
                }
                if ([string]::IsNullOrWhiteSpace($_.Enabled)) {
                    $_.Enabled = 'None'
                }
                if ([string]::IsNullOrWhiteSpace($_.Enforced)) {
                    $_.Enforced = 'None'
                }
                if ([string]::IsNullOrWhiteSpace($_.Order)) {
                    $_.Order = 'None'
                }
                $_
            })
        }               
    }            

    $ouData | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $exportDir "OUs.json") -Encoding UTF8
    Log-Message "OUs exported successfully."
}

# Function to load configuration from a JSON file
function Get-Config {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath
    )

    # Internal function to replace variables in paths and interpret them correctly
    function Replace-VariablesInPath {
        param (
            [Parameter(Mandatory = $true)]
            [string]$Path
        )

        # Replace PowerShell variables in the path
        $Path = $Path -replace '\$PSScriptRoot', $PSScriptRoot
        $Path = $Path -replace '\$env:([^\\]*)', { param($matches) [System.Environment]::GetEnvironmentVariable($matches[1]) }
        return $Path
    }

    # Read the JSON config file
    $config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json

    # Replace and interpret variables in paths
    $config.Parameters.OutputDirectory = Replace-VariablesInPath -Path $config.Parameters.OutputDirectory
    $config.Parameters.InputDirectory = Replace-VariablesInPath -Path $config.Parameters.InputDirectory
    $config.Parameters.LogFilePath = Replace-VariablesInPath -Path $config.Parameters.LogFilePath

    # Return the updated config object
    return $config
}

# Function to get domain information
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
            Default {"Unknown type...`nPlease select the correct type of your information and try again (`"NetBIOS`", `"DNS`", `"DistinguishedName`", `"Master`")";return $null}
        }        
    }
}

# Function to retrieve GPO delegation
function Get-GPODelegation {    
    param (
        [Parameter(Mandatory = $true)]
        [string]
        [Alias("Id")]
        $Name
    )
    if (-not($Name -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')) {
        $gpo = Get-GPO -Name $Name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id
    }
    else {
        $gpo = $Name 
    }
    if(-not($null -eq $gpo)){
        try {
            $acl = Get-GPPermission -Guid $gpo -All
            return $acl
        }
        catch {
            Log-Message "Failed to retrieve delegation permissions: $_" "ERROR"
            return $null
        }                
    }
    else {
        Log-Message "Incorrect GPO name or GUID: $_" "ERROR"
        return $null
    }
}

# Function to create a new JSON configuration file
function New-Json {
    # Ask for script-related parameters
    $outputDirectory = Read-Host 'Enter the output directory (default: $PSScriptRoot\Output)'
    if (-not $outputDirectory) { $outputDirectory = '$PSScriptRoot\Output' }

    $inputDirectory = Read-Host 'Enter the input directory (default: $PSScriptRoot\Input)'
    if (-not $inputDirectory) { $inputDirectory = '$PSScriptRoot\Input' }

    $logFilePath = Read-Host 'Enter the log file path (default: $PSScriptRoot\Logs\Scriptfile.txt)'
    if (-not $logFilePath) { $logFilePath = '$PSScriptRoot\Logs\Scriptfile.txt' }

    try { $domain = Get-ADDomain } catch { Handle-Error "Failed to retrieve Active Directory information: $_" }

    $oldDomainDN    = Get-DomainInformation -Type DistinguishedName -Information ($domain).DistinguishedName # e.g., DC=old,DC=com
    $oldNetBIOSName = Get-DomainInformation -Type NetBIOS -Information ($domain).NetBIOSName # e.g., OLD
    $oldDomainName  = Get-DomainInformation -Type DNS -Information ($domain).DNSRoot # e.g., old.com
    $MasterDC       = Get-DomainInformation -Type Master -Information (($domain).InfrastructureMaster).Split(".")[0] # e.g., SRVDC01

    # Create the configuration object
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

    # Convert the configuration object to JSON and save to a file
    $config | ConvertTo-Json -Depth 10 | Set-Content -Path "$PSScriptRoot\Input\config.json" -Force

    Log-Message "Configuration file 'config.json' created successfully."
}
#endregion

#region main
Clear-Host

#region verify PowerShell version
$currentVersion = $PSVersionTable.PSVersion
$maxVersion = [Version]"5.1.20348.2400"
if ($currentVersion -gt $maxVersion) {
    Write-Host "[ERROR]: This script requires PowerShell 5.1 or earlier. Current version: $currentVersion" -ForegroundColor Red
    Pause
    exit 1
} else {
    Write-Host "[INFO]: PowerShell version compatible: $currentVersion"
}
#endregion

$newJSON = Read-Host "Create new JSON file? [Y/N] (default: Y)"
if (-not $newJSON) { $newJSON = 'Y' }
if ($newJSON -ieq 'Y') {
    New-Json
}

#region init
$config = Get-Config -ConfigPath "$PSScriptRoot\Input\config.json"
$exportDir = $config.Parameters.InputDirectory

if (-not (Test-Path -Path $exportDir)) {
    New-Item -ItemType Directory -Path $exportDir | Out-Null
}
#endregion

try {
    Export-OUs -exportDir $exportDir
    Write-Host "OUs exported successfull !" -ForegroundColor Green
}
catch {
    Write-Host "Error during export for OUs..." -ForegroundColor Red
}         

try {
    Export-Groups -exportDir $exportDir
    Write-Host "Groups exported successfull !" -ForegroundColor Green      
}
catch {
    Write-Host "Error during export for Groups..." -ForegroundColor Red
}    

try {
    Backup-GPOs -exportDir "$exportDir\GPO_Report"
    Write-Host "GPOs exported successfull !" -ForegroundColor Green
    Log-Message "Active Directory configuration exported successfully."
}
catch {
    Write-Host "Error during export for GPOs..." -ForegroundColor Red
}  
#endregion

# Display completion message
Add-Type -AssemblyName PresentationFramework
[System.Windows.MessageBox]::Show("Active Directory exported is complete. Check Scriptfile-admin.txt for any error")
exit