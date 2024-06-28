#region modules
Import-Module ActiveDirectory
# Import-Module GroupPolicy
#endregion

#region verify PowerShell version
$currentVersion = $PSVersionTable.PSVersion
$maxVersion = [Version]"5.1.20348.2400"
if ($currentVersion -gt $maxVersion) {
    Write-Host "Ce script nécessite PowerShell 5.1 ou une version antérieure."
    Write-Host "Version actuelle : $currentVersion"
    exit 1
} else {
    Write-Host "Version de PowerShell compatible : $currentVersion"
}
#endregion

#region init
function Get-Config {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath
    )

    # Fonction interne pour remplacer les variables dans les chemins et les interpréter correctement
    function Replace-VariablesInPath {
        param (
            [Parameter(Mandatory = $true)]
            [string]$Path
        )

        # Remplacer les variables PowerShell dans le chemin
        $Path = $Path -replace '\$PSScriptRoot', $PSScriptRoot
        $Path = $Path -replace '\$env:([^\\]*)', { param($matches) [System.Environment]::GetEnvironmentVariable($matches[1]) }
        return $Path
    }

    # Lire le fichier de configuration JSON
    $config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json

    # Remplacer et interpréter les variables dans les chemins
    $config.Parameters.OutputDirectory = Replace-VariablesInPath -Path $config.Parameters.OutputDirectory
    $config.Parameters.InputDirectory = Replace-VariablesInPath -Path $config.Parameters.InputDirectory
    $config.Parameters.LogFilePath = Replace-VariablesInPath -Path $config.Parameters.LogFilePath

    # Retourner l'objet de configuration mis à jour
    return $config
}
# Exemple d'appel de la fonction
$config = Get-Config -ConfigPath "$PSScriptRoot\Source\config.json"
# Directory to store export files
$exportDir = $config.Parameters.OutputDirectory

if (-not (Test-Path -Path $exportDir)) {
    New-Item -ItemType Directory -Path $exportDir | Out-Null
}
#endregion

#region function
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
    Write-Output "OUs exported successfully."
}

function Export-Groups {
    param (
        [Parameter(Mandatory = $true)]
        [string]$exportDir
    )

    # Créer le répertoire principal si nécessaire
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
    Write-Output "Groups exported successfully."
}

function Export-GPOs {
    param (
        [Parameter(Mandatory = $true)]
        [string]$exportDir
    )
    $exportDirReports=(Join-Path $exportDir "GPO_Report")    
    if (-not (Test-Path -Path $exportDir)) {
        New-Item -ItemType Directory -Path $exportDir | Out-Null
        New-Item -ItemType Directory -Path $exportDirReports | Out-Null
    }
    elseif (-not (Test-Path -Path $exportDirReports)) {
        New-Item -ItemType Directory -Path $exportDirReports | Out-Null
    }
    
    $gpos = Get-GPO -All
    $gpoData = @()
    $permissions = @()

    foreach ($gpo in $gpos) {
        $gpo | Get-GPOReport -ReportType Xml -Path (Join-Path $exportDirReports "$($gpo.DisplayName).xml")        
        $acls = Get-GPODelegation -Name $gpo.Id
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
            DisplayName         = $gpo.DisplayName
            Id                  = $gpo.Id
            Owner               = $gpo.Owner
            UserVersion         = $gpo.UserVersion
            ComputerVersion     = $gpo.ComputerVersion
            Permissions         = $permissions            
        }
    }

    $gpoData | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $exportDir "GPOs.json") -Encoding UTF8
    Write-Output "GPOs exported successfully."
}

function Get-GPODelegation{    
    param (
        [Parameter(Mandatory = $true)]
        [string]
        [Alias("Id")]
        $Name
    )
    if (-not($Name -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')) {
        $gpo = Get-GPO -Name $Name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id
    }
    else{
        $gpo = $Name 
    }
    if(-not($null -eq $gpo)){
        try {
            $acl = Get-GPPermission -Guid $gpo -All
            return $acl
        }
        catch {
            Write-Output "Failed to retrieve delegation permissions: $_"
            return $null
        }                
    }
    else {
        Write-Output "Incorect GPO name or GUID: $_"
        return $null
    }
}

#endregion

#region main
# Export-OUs -exportDir "$exportDir\OUs"
# Export-Groups -exportDir "$exportDir\Groups"
# Export-GPOs -exportDir "$exportDir\GPOs"
Export-OUs -exportDir $exportDir
Export-Groups -exportDir $exportDir
Export-GPOs -exportDir $exportDir


#Write-Output "Active Directory configuration exported successfully."
#endregion