# Define a function to replace domain names in a given string
function Replace-DomainNames {
    param (
        [string]$inputString,
        [string]$oldNetBIOSName,
        [string]$newNetBIOSName,
        [string]$oldDNSName,
        [string]$newDNSName
    )

    # Replace old domain components with new ones
    $inputString = $inputString -replace "DC=$($oldDNSName -replace '\.',',DC=')", "DC=$($newDNSName -replace '\.',',DC=')"
    $inputString = $inputString -replace [regex]::Escape($oldDNSName), $newDNSName
    $inputString = $inputString -replace [regex]::Escape($oldNetBIOSName), $newNetBIOSName
    return $inputString
}
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

$config = Get-Config -ConfigPath "$PSScriptRoot\Source\config.json"
$exportDir = $config.Parameters.OutputDirectory
# Load JSON files
$ousJson    = Get-Content -Raw -Path "$exportDir\OUs.json" | ConvertFrom-Json
$groupsJson = Get-Content -Raw -Path "$exportDir\Groups.json" | ConvertFrom-Json
$gposJson   = Get-Content -Raw -Path "$exportDir\GPOs.json" | ConvertFrom-Json

# Set old and new domain names
$oldNetBIOSName = $config.DomainInfo.Old.NetBIOS
$newNetBIOSName = $config.DomainInfo.New.NetBIOS
$oldDNSName     = $config.DomainInfo.Old.Name
$newDNSName     = $config.DomainInfo.New.Name

# Replace domain names in OUs
foreach ($ou in $ousJson) {
    if ($null -ne $ou.DistinguishedName) {
        $ou.DistinguishedName = Replace-DomainNames -inputString $ou.DistinguishedName -oldNetBIOSName $oldNetBIOSName -newNetBIOSName $newNetBIOSName -oldDNSName $oldDNSName -newDNSName $newDNSName
    }
    if ($null -ne $ou.Owner) {
        $ou.Owner = Replace-DomainNames -inputString $ou.Owner -oldNetBIOSName $oldNetBIOSName -newNetBIOSName $newNetBIOSName -oldDNSName $oldDNSName -newDNSName $newDNSName
    }
    if ($null -ne $ou.OwnerGroup) {
        $ou.OwnerGroup = Replace-DomainNames -inputString $ou.OwnerGroup -oldNetBIOSName $oldNetBIOSName -newNetBIOSName $newNetBIOSName -oldDNSName $oldDNSName -newDNSName $newDNSName
    }
    if ($ou.Links) {
        foreach ($link in $ou.Links) {
            if ($null -ne $link.DisplayName) {
                $link.DisplayName = Replace-DomainNames -inputString $link.DisplayName -oldNetBIOSName $oldNetBIOSName -newNetBIOSName $newNetBIOSName -oldDNSName $oldDNSName -newDNSName $newDNSName
            }
        }
    }
}

# Replace domain names in Groups
foreach ($group in $groupsJson) {
    if ($null -ne $group.DistinguishedName) {
        $group.DistinguishedName = Replace-DomainNames -inputString $group.DistinguishedName -oldNetBIOSName $oldNetBIOSName -newNetBIOSName $newNetBIOSName -oldDNSName $oldDNSName -newDNSName $newDNSName
    }
    if ($group.Members -is [System.Collections.IEnumerable]) {
        foreach ($member in $group.Members) {
            if ($null -ne $member.DistinguishedName) {
                $member.DistinguishedName = Replace-DomainNames -inputString $member.DistinguishedName -oldNetBIOSName $oldNetBIOSName -newNetBIOSName $newNetBIOSName -oldDNSName $oldDNSName -newDNSName $newDNSName
            }
        }
    } elseif ($null -ne $group.Members -and $null -ne $group.Members.DistinguishedName) {
        $group.Members.DistinguishedName = Replace-DomainNames -inputString $group.Members.DistinguishedName -oldNetBIOSName $oldNetBIOSName -newNetBIOSName $newNetBIOSName -oldDNSName $oldDNSName -newDNSName $newDNSName
    }
}

# Replace domain names in GPOs
foreach ($gpo in $gposJson) {
    if ($null -ne $gpo.DistinguishedName) {
        $gpo.DistinguishedName = Replace-DomainNames -inputString $gpo.DistinguishedName -oldNetBIOSName $oldNetBIOSName -newNetBIOSName $newNetBIOSName -oldDNSName $oldDNSName -newDNSName $newDNSName
    }
    if ($null -ne $gpo.Owner) {
        $gpo.Owner = Replace-DomainNames -inputString $gpo.Owner -oldNetBIOSName $oldNetBIOSName -newNetBIOSName $newNetBIOSName -oldDNSName $oldDNSName -newDNSName $newDNSName
    }
    if ($null -ne $gpo.OwnerGroup) {
        $gpo.OwnerGroup = Replace-DomainNames -inputString $gpo.OwnerGroup -oldNetBIOSName $oldNetBIOSName -newNetBIOSName $newNetBIOSName -oldDNSName $oldDNSName -newDNSName $newDNSName
    }
    if ($gpo.Links) {
        foreach ($link in $gpo.Links) {
            if ($null -ne $link.DisplayName) {
                $link.DisplayName = Replace-DomainNames -inputString $link.DisplayName -oldNetBIOSName $oldNetBIOSName -newNetBIOSName $newNetBIOSName -oldDNSName $oldDNSName -newDNSName $newDNSName
            }
        }
    }
    if ($gpo.Permissions) {
        foreach ($permission in $gpo.Permissions) {
            if ($permission.Trustee -and $null -ne $permission.Trustee.Domain) {
                $permission.Trustee.Domain = Replace-DomainNames -inputString $permission.Trustee.Domain -oldNetBIOSName $oldNetBIOSName -newNetBIOSName $newNetBIOSName -oldDNSName $oldDNSName -newDNSName $newDNSName
            }
        }
    }
}

# Save modified JSON back to files
$ousJson | ConvertTo-Json -Depth 32 | Out-File -FilePath "$($config.Parameters.InputDirectory)\OUs.json" -Encoding UTF8
$groupsJson | ConvertTo-Json -Depth 32 | Out-File -FilePath "$($config.Parameters.InputDirectory)\Groups.json" -Encoding UTF8
$gposJson | ConvertTo-Json -Depth 32 | Out-File -FilePath "$($config.Parameters.InputDirectory)\GPOs.json" -Encoding UTF8

Write-Output "Domain names have been replaced successfully."
