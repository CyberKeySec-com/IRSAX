#region functions

# Function to increment the domain controller name
function Add-IncrementationDCName {
    param (
        [string]$DCName
    )
    if ($DCName -match '(\d+)$') {
        $number = [int]$matches[1] + 1
        $DCNameInc = $DCName -replace '\d+$', $number.ToString("D2")
    } else {
        Log-Message "No number found at the end of the domain controller name." "ERROR"
    }
    return $DCNameInc
}

# Function to validate password complexity
function Check-PasswordComplexity {
    param (
        [string]$password
    )
    if ($password.Length -ge 8 -and
        $password -match '[A-Z]' -and
        $password -match '[a-z]' -and
        $password -match '[0-9]' -and
        $password -match '[!@#$%^&*(),.?":{}|<>]') {
        return $true
    } else {
        return $false
    }
}

# Function to convert domain name to Distinguished Name
function Convert-DomainToDistinguishedName {
    param (
        [Parameter(Mandatory=$true)]
        [string]$DomainName
    )
    $components = $DomainName.Split('.')
    $dnParts = $components | ForEach-Object { "DC=$_"} 
    $distinguishedName = $dnParts -join ','
    return $distinguishedName
}

# Function to create a scheduled task to run the script at user login
function Create-ScheduledTask {
    param (
        [string]$taskName,
        [string]$scriptPath
    )
    try {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" # -WindowStyle Hidden
        $trigger = New-ScheduledTaskTrigger -AtLogon
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        Register-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -TaskName $taskName -Description "Resume AD deployment script" -Force
        Log-Message "Scheduled task '$taskName' created successfully"
    } catch {
        Handle-Error "Failed to create scheduled task: $_"
    }
}

# Function to decrypt data string 
function Decrypt-Data {
    param (
        [string]$encryptedText,
        [string]$keyFile = "aesKey.key",
        [string]$ivFile = "aesIV.iv"
    )
    
    # Lire la clé et l'IV depuis les fichiers
    $Key = [System.IO.File]::ReadAllBytes($keyFile)
    $IV = [System.IO.File]::ReadAllBytes($ivFile)
    
    # Convertir la chaîne chiffrée en bytes
    $encryptedBytes = [Convert]::FromBase64String($encryptedText)
    
    # Créer un objet AES
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $Key
    $aes.IV = $IV
    
    # Créer un decryptor
    $decryptor = $aes.CreateDecryptor($aes.Key, $aes.IV)
    
    # Déchiffrer les données
    $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
    $decryptedText = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
    
    return $decryptedText
}

# Function to replace domain names in JSON configuration files
function Edit-JSON {
    $config = Get-Config -ConfigPath "$PSScriptRoot\Input\config.json"    
    $ousJson = Get-Content -Raw -Path "$($config.Parameters.InputDirectory)\OUs.json" | ConvertFrom-Json
    $groupsJson = Get-Content -Raw -Path "$($config.Parameters.InputDirectory)\Groups.json" | ConvertFrom-Json
    $gposJson = Get-Content -Raw -Path "$($config.Parameters.InputDirectory)\GPOs.json" | ConvertFrom-Json

    $oldNetBIOSName = $config.DomainInfo.Old.NetBIOS
    $newNetBIOSName = $config.DomainInfo.New.NetBIOS
    $oldDNSName = $config.DomainInfo.Old.Name
    $newDNSName = $config.DomainInfo.New.Name

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
    $parentDomain = Get-ParentDomain -domain $oldDNSName

    foreach ($group in $groupsJson) {
        if ($null -ne $group.DistinguishedName) {
            $group.DistinguishedName = Replace-DomainNames -inputString $group.DistinguishedName -oldNetBIOSName $oldNetBIOSName -newNetBIOSName $newNetBIOSName -oldDNSName $oldDNSName -newDNSName $newDNSName -parentDomain $parentDomain
        }
        if ($null -ne $group.Name) {            
            $group.Name = Replace-DomainNames -inputString $group.Name -oldNetBIOSName $parentDomain -newNetBIOSName $newNetBIOSName -oldDNSName $oldDNSName -newDNSName $newDNSName -parentDomain $parentDomain
        }
        if ($group.Members -is [System.Collections.IEnumerable]) {
            foreach ($member in $group.Members) {
                if ($null -ne $member.DistinguishedName) {
                    $member.DistinguishedName = Replace-DomainNames -inputString $member.DistinguishedName -oldNetBIOSName $oldNetBIOSName -newNetBIOSName $newNetBIOSName -oldDNSName $oldDNSName -newDNSName $newDNSName -parentDomain $parentDomain
                }
                if ($null -ne $member.Name) {
                    $member.Name = Replace-DomainNames -inputString $member.Name -oldNetBIOSName $oldNetBIOSName -newNetBIOSName $newNetBIOSName -oldDNSName $oldDNSName -newDNSName $newDNSName -parentDomain $parentDomain
                }
            }
        } elseif ($null -ne $group.Members -and $null -ne $group.Members.DistinguishedName -and $null -ne $group.Members.Name) {
            $group.Members.DistinguishedName = Replace-DomainNames -inputString $group.Members.DistinguishedName -oldNetBIOSName $oldNetBIOSName -newNetBIOSName $newNetBIOSName -oldDNSName $oldDNSName -newDNSName $newDNSName -parentDomain $parentDomain
            $group.Members.Name = Replace-DomainNames -inputString $group.Members.Name -oldNetBIOSName $oldNetBIOSName -newNetBIOSName $newNetBIOSName -oldDNSName $oldDNSName -newDNSName $newDNSName -parentDomain $parentDomain
        }
    }

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

    $ousJson | ConvertTo-Json -Depth 32 | Out-File -FilePath "$($config.Parameters.InputDirectory)\OUs.json" -Encoding UTF8
    $groupsJson | ConvertTo-Json -Depth 32 | Out-File -FilePath "$($config.Parameters.InputDirectory)\Groups.json" -Encoding UTF8
    $gposJson | ConvertTo-Json -Depth 32 | Out-File -FilePath "$($config.Parameters.InputDirectory)\GPOs.json" -Encoding UTF8

    Write-Output "Domain names have been replaced successfully."
}

# Function to encrypt data string 
function Encrypt-Data {
    param (
        [string]$plainText,
        [string]$keyFile = "aesKey.key",
        [string]$ivFile = "aesIV.iv"
    )
    
    # Générer une clé et un IV (vecteur d'initialisation)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.GenerateKey()
    $aes.GenerateIV()
    $Key = $aes.Key
    $IV = $aes.IV
    
    # Exporter la clé et l'IV dans des fichiers
    [System.IO.File]::WriteAllBytes($keyFile, $Key)
    [System.IO.File]::WriteAllBytes($ivFile, $IV)
    
    # Convertir les données en bytes
    $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($plainText)
    
    # Créer un encryptor
    $encryptor = $aes.CreateEncryptor($Key, $IV)
    
    # Chiffrer les données
    $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
    $encryptedText = [Convert]::ToBase64String($encryptedBytes)
    
    return $encryptedText
}

# Function to load configuration from a JSON file
function Get-Config {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath
    )

    function Replace-VariablesInPath {
        param (
            [Parameter(Mandatory = $true)]
            [string]$Path
        )

        $Path = $Path -replace '\$PSScriptRoot', $PSScriptRoot
        $Path = $Path -replace '\$env:([^\\]*)', { param($matches) [System.Environment]::GetEnvironmentVariable($matches[1]) }
        return $Path
    }

    $config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json

    $config.Parameters.OutputDirectory = Replace-VariablesInPath -Path $config.Parameters.OutputDirectory
    $config.Parameters.InputDirectory  = Replace-VariablesInPath -Path $config.Parameters.InputDirectory
    $config.Parameters.LogFilePath     = Replace-VariablesInPath -Path $config.Parameters.LogFilePath

    return $config
}

# Function to get the parent domain from a given domain
function Get-ParentDomain {
    param (
        [string]$domain
    )

    $parts = $domain -split '\.'

    if ($parts.Count -ge 2) {
        $parentDomain = $parts[$parts.Count - 2].ToUpper()
        return $parentDomain
    } else {
        throw "Invalid domain format"
    }
}

# Function to handle errors
function Handle-Error {
    param (
        [string]$errorMessage
    )
    Log-Message $errorMessage "ERROR"
    exit 1
}

# Function to import groups into Active Directory
function Import-Groups {
    param ([array]$groups)
    foreach ($group in $groups) {
        $groupName = $group.Name        
        $groupDN = $group.DistinguishedName
        $firstCommaIndex = $groupDN.IndexOf(',')
        if ($firstCommaIndex -ne -1) {
            $parentDN = $groupDN.Substring($firstCommaIndex + 1).Trim()
        } else {
            $parentDN = $groupDN
        }
        $groupScope = $group.GroupScope
        $groupCategory = $group.GroupCategory
        if ($groupName -and $groupDN -and $groupScope -and $groupCategory) {
            Log-Message "Name: $groupName"
            Log-Message "DistinguishedName: $groupDN"
            Log-Message "Scope: $groupScope"
            Log-Message "Category: $groupCategory"
            if (-not (Get-ADGroup -Filter { Name -eq $groupName } -ErrorAction SilentlyContinue)) {
                try {
                    New-ADGroup -Name $groupName -GroupScope $groupScope -GroupCategory $groupCategory -Path $parentDN
                    Log-Message "Created Group: $($groupName)"
                } catch {
                    Log-Message "Failed to create Group: $($groupName) - $_" "ERROR"
                }
            } else {
                Log-Message "Group already exists: $($groupName)"
            }

            try {
                $currentMembers = Get-ADGroupMember -Identity $groupDN | Select-Object -ExpandProperty DistinguishedName
                $desiredMembers = $group.Members | ForEach-Object { $_.DistinguishedName }

                foreach ($member in $desiredMembers) {
                    if ($currentMembers -notcontains $member) {
                        try {
                            Add-ADGroupMember -Identity $groupDN -Members $member
                            Log-Message "Added member $member to group $($groupName)"
                        } catch {
                            Log-Message "Failed to add member $member to group $($groupName) - $_" "ERROR"
                        }
                    }
                }

                foreach ($member in $currentMembers) {
                    if ($desiredMembers -notcontains $member) {
                        try {
                            Remove-ADGroupMember -Identity $groupDN -Members $member -Confirm:$false
                            Log-Message "Removed member $member from group $($groupName)"
                        } catch {
                            Log-Message "Failed to remove member $member from group $($groupName) - $_" "ERROR"
                        }
                    }
                }
            } catch {
                Log-Message "Failed to manage members for Group: $($groupName) - $_" "ERROR"
            }
        } else {
            Log-Message "Missing properties for group: $group" "ERROR"
        }
    }
}

# Function to import GPOs into Active Directory
function Import-GPOs {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ImportPath
    )

    if (-not (Test-Path -Path $ImportPath)) {
        Log-Message "The specified import path does not exist: $ImportPath"
        exit 1
    }

    $GPOFolders = Get-ChildItem -Path $ImportPath -Directory

    foreach ($Folder in $GPOFolders) {
        $GPOName = $Folder.Name
        $GPOBackupPath = $Folder.FullName

        Log-Message "Importing GPO: $GPOName from $GPOBackupPath"

        $GPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue

        if ($null -ne $GPO) {
            Log-Message "GPO $GPOName already exists. Importing will overwrite the existing GPO."
            Import-GPO -BackupGpoName $GPOName -Path $GPOBackupPath -CreateIfNeeded -TargetName $GPOName | Out-Null
        } else {
            Import-GPO -BackupGpoName $GPOName -Path $GPOBackupPath -CreateIfNeeded -TargetName $GPOName | Out-Null
        }
    }

    Log-Message "GPO import completed successfully."
}

# Function to import organizational units (OUs) into Active Directory
function Import-OUs {
    param (
        $OUs
    )
    $RootDomain = $config.DomainInfo.New.Name

    function Ensure-OUExists {
        param (
            [string]$OUPath
        )

        $rootParts = $RootDomain.Split('.')

        $ouParts = $OUPath -split ','
        $containsOnlyDomainComponents = $true
        foreach ($part in $ouParts) {
            if ($part -match '^DC=') {
                if (-not ($rootParts -contains ($part.Substring(3)))) {
                    $containsOnlyDomainComponents = $false
                    break
                }
            } else {
                $containsOnlyDomainComponents = $false
                break
            }
        }

        if ($containsOnlyDomainComponents) {
            Log-Message "Skipping creation of domain component path: $OUPath"
            return
        }

        $existingOU = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$OUPath'" -ErrorAction SilentlyContinue
        if ($null -eq $existingOU) {
            Log-Message "OU does not exist: $OUPath"
            $ParentOU = $OUPath -replace '^OU=[^,]+,'
            if ($ParentOU -ne $OUPath) {
                Ensure-OUExists -OUPath $ParentOU
            }
            $ouName = ($OUPath -split ',')[0].Substring(3)
            Log-Message "Creating OU: $ouName under $ParentOU"
            New-ADOrganizationalUnit -Name $ouName -Path $ParentOU
        } else {
            Log-Message "OU already exists: $OUPath"
        }
    }

    foreach ($ou in $OUs) {
        $ouPath = $ou.DistinguishedName
        Log-Message "Processing OU: $ouPath"
        Ensure-OUExists -OUPath $ouPath
    }
}

# Function to link GPOs to OUs in Active Directory
function Link-GPOsToOUs {
    param ([array]$ous)

    foreach ($ou in $ous) {
        $ouDN = $ou.DistinguishedName
        if ($ou.Links) {
            foreach ($link in $ou.Links) {
                if ($link.DisplayName) {
                    try {
                        $gpo = Get-GPO -Name $link.DisplayName -ErrorAction SilentlyContinue
                        if ($null -ne $gpo) {
                            $existingLinks = Get-GPInheritance -Target $ouDN | Select-Object -ExpandProperty GpoLinks
                            $linkExists = $false
                            foreach ($existingLink in $existingLinks) {
                                if ($existingLink.DisplayName -eq $link.DisplayName) {
                                    $linkExists = $true
                                    break
                                }
                            }

                            if (-not $linkExists) {
                                $link.Enabled = $link.Enabled -replace "true", 'Yes'
                                $link.Enabled = $link.Enabled -replace "false", 'No'
                                $link.Enforced = $link.Enforced -replace "true", 'Yes'
                                $link.Enforced = $link.Enforced -replace "false", 'No'
                                New-GPLink -Name $link.DisplayName -Target $ouDN -LinkEnabled $link.Enabled -Enforced $link.Enforced
                                Log-Message "Linked GPO $($link.DisplayName) to OU $ouDN"
                            } else {
                                Log-Message "Link for GPO $($link.DisplayName) already exists on OU $ouDN"
                            }
                        } else {
                            Log-Message "GPO $($link.DisplayName) does not exist" "ERROR"
                        }
                    } catch {
                        Log-Message "Failed to link GPO $($link.DisplayName) to OU $ouDN - $_" "ERROR"
                    }
                } else {
                    Log-Message "Link GPOName is missing for OU $ouDN" "ERROR"
                }
            }
        } else {
            Log-Message "No links found for OU $ouDN"
        }
    }
}

# Function to log messages to a file
function Log-Message {
    param (
        [string]$message,
        [string]$type = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp [$type] - $message" | Out-File -Append -FilePath $logFilePath
}

# Function to create a new AD configuration
function New-ADConfiguration {
    $config = Get-Config -ConfigPath "$PSScriptRoot\Input\config.json"
    $newDomainName  = Read-Host "Enter the new domain name (e.g., new.com)"
    $newDomainDN    = Convert-DomainToDistinguishedName -DomainName $newDomainName
    $newNetBIOSName = Read-Host "Enter the new domain name (e.g., NEW)"
    $useAuto = Read-Host "Use the automatically retrieved domain master DC ($($config.DomainInfo.Old.MasterDC))? [Y/N] (default: Y)"

    if (-not $useAuto) { $useAuto = 'Y' }
    if ($useAuto -ieq 'Y') {
        $newMasterDC = $config.DomainInfo.Old.MasterDC
    } else {
        $newMasterDC = Read-Host "Enter the old master domain controller (e.g., SRVDC01)"
    }

    $newEntry = @{
        Name              = $newDomainName
        DistinguishedName = $newDomainDN
        NetBIOS           = $newNetBIOSName
        MasterDC          = $newMasterDC
    }

    $jsonContent = Get-Content -Path "$PSScriptRoot\Input\config.json" -Raw | ConvertFrom-Json
    if (-not ($jsonContent.DomainInfo.New)) {
        $jsonContent.DomainInfo | Add-Member -MemberType NoteProperty -Name New -Value $newEntry
    }

    $jsonContent | ConvertTo-Json -Depth 10 | Set-Content -Path "$PSScriptRoot\Input\config.json" -Encoding UTF8

    Write-Output "Configuration file 'config.json' created successfully."
}

# Function to replace domain names in a string
function Replace-DomainNames {
    param (
        [string]$inputString,
        [string]$oldNetBIOSName,
        [string]$newNetBIOSName,
        [string]$oldDNSName,
        [string]$newDNSName,
        [Parameter(Mandatory=$false)]
        [string]$parentDomain
    )

    $inputString = $inputString -replace "DC=$($oldDNSName -replace '\.',',DC=')", "DC=$($newDNSName -replace '\.',',DC=')"    
    $inputString = $inputString -replace [regex]::Escape($oldDNSName), $newDNSName    
    $inputString = $inputString -replace [regex]::Escape($oldNetBIOSName), $newNetBIOSName
    if ($parentDomain) {
        $inputString = $inputString -replace [regex]::Escape($parentDomain), $newNetBIOSName
    }

    return $inputString
}

# Function to remove the scheduled task
function Remove-ScheduledTask {
    param (
        [string]$taskName
    )

    try {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Log-Message "Scheduled task '$taskName' removed successfully"
    } catch {
        Handle-Error "Failed to remove scheduled task: $_"
    }
}

# Function to update the state of script
function Update-State {
    param (
        [string]$step
    )
    $scriptState.$step = $true
    $scriptState | ConvertTo-Json | Set-Content -Path $stateFilePath
    Log-Message "Completed $step"
}

# Function to validate IP address format
function Validate-IPAddress {
    param (
        [string]$IPAddress
    )
    if ($IPAddress -match '^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$') {
        return $true
    } else {
        return $false
    }
}

# Function to validate subnet mask value
function Validate-SubnetMask {
    param (
        [int]$SubnetMask
    )
    if ($SubnetMask -ge 1 -and $SubnetMask -le 32) {
        return $true
    } else {
        return $false
    }
}

# Function to verify if the server is a domain controller and promote if necessary
function Verify-And-Promote-DomainController {
    try {
        $dcInfo = Get-ADDomainController -ErrorAction Stop
        if ($dcInfo -ne $null) {
            Log-Message "Server is promoted as a domain controller."
            return $true
        } else {
            Handle-Error "Server is not promoted as a domain controller."
        }
    } catch {
        Log-Message "Server is not promoted as a domain controller. Attempting promotion..."
        try {
            $securePassword = Get-Content -Path "$PSScriptRoot\Output\securePassword.txt" | ConvertTo-SecureString
            $result = Install-ADDSDomainController -DomainName $config.DomainInfo.New.Name `
                                        -SafeModeAdministratorPassword $securePassword `
                                        -InstallDns `
                                        -CreateDnsDelegation:$false `
                                        -DatabasePath "C:\Windows\NTDS" `
                                        -LogPath "C:\Windows\NTDS" `
                                        -SysvolPath "C:\Windows\SYSVOL" `
                                        -Force:$true
            Log-Message "Domain controller promotion initiated"

            if ($result.RebootRequired) {
                Restart-Computer
                exit
            } else {
                return $true
            }
        } catch {
            Handle-Error "Failed to promote the server to a domain controller: $_"
        }
    }
}
#endregion functions

#region main
Clear-Host
$ConfirmPreference = 'None'

# Load configuration
$config = Get-Config -ConfigPath "$PSScriptRoot\Input\config.json"
$stateFilePath = "$PSScriptRoot\Output\ScriptState.json"

# Create the scheduled task to run the script at user login
$logFilePath = $config.Parameters.LogFilePath
if (-not (Test-Path $logFilePath)) {
    New-Item -Path $logFilePath -ItemType File -Force | Out-Null
}

$taskName = "ResumeADDeploymentScript"
$scriptPath = (Get-Item -Path $MyInvocation.MyCommand.Definition).FullName
Create-ScheduledTask -taskName $taskName -scriptPath $scriptPath | Out-Null

# Initialize or read state
if (Test-Path $stateFilePath) {
    $scriptState = Get-Content -Path $stateFilePath | ConvertFrom-Json
} else {
    $scriptState = [ordered]@{
        Step0_Completed = $false
        Step1_Completed = $false
        Step2_Completed = $false
        Step3_Completed = $false
        Step4_Completed = $false
        Step5_Completed = $false
        Step6_Completed = $false
        Step7_Completed = $false
        Step8_Completed = $false
        Step9_Completed = $false
    }
}

# Step 0: New Active Directory configuration
if (-not ($scriptState.Step0_Completed -and (-not ($null -eq $config.DomainInfo.New)))) {
    try {
        $adCONFIG = Read-Host "Create new Active Directory configuration ? [Y/N] (default: Y)"
        if (-not $adCONFIG) { $adCONFIG = 'Y' }
        if ($adCONFIG -ieq 'Y') {
            New-ADConfiguration
            Update-State -step "Step0_Completed"
        }
    } catch {
        Write-Output "Failed to create new configuration: $_"
        exit 1
    }
}

# Step 1: Edit JSON file from new Active Directory
if (-not $scriptState.Step1_Completed) {
    try {
        $editJSON = Read-Host "Edit JSON file with new Active Directory configuration ? [Y/N] (default: Y)"
        if (-not $editJSON) { $editJSON = 'Y' }
        if ($editJSON -ieq 'Y') {
            Edit-JSON
            Update-State -step "Step1_Completed"
        }
    } catch {
        Write-Output "Failed to edit JSON file with new configuration: $_"
        exit 1
    }
}

# Reload config after create
if (Test-Path "$PSScriptRoot\Input\config.json") {
    $config = Get-Config -ConfigPath "$PSScriptRoot\Input\config.json"
}

# Step 2: Configure IP/Network and DNS settings
if (-not $scriptState.Step2_Completed) {
    try {
        function Set-NetworkConfiguration {
            param (
                [string]$IPAddress,
                [int]$SubnetMask,
                [string]$Gateway,
                [string]$PrimaryDNSServer,
                [string]$SecondaryDNSServer
            )
        
            # Get the network adapter
            $adapter = Get-NetAdapter -ErrorAction SilentlyContinue| Where-Object { $_.Status -eq 'Up' }
            if (-not $adapter) {
                Handle-Error "No active network adapter found."
                return
            }
        
            # Remove existing IP configuration
            $currentIPConfig = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
            foreach ($ip in $currentIPConfig) {
                Remove-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -IPAddress $ip.IPAddress -Confirm:$false
            }
        
            # Remove existing gateway configuration
            $currentGateway = Get-NetRoute -InterfaceIndex $adapter.InterfaceIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue
            if ($currentGateway) {
                Remove-NetRoute -InterfaceIndex $adapter.InterfaceIndex -DestinationPrefix "0.0.0.0/0" -NextHop $currentGateway.NextHop -Confirm:$false
            }
        
            # Set new IP configuration
            if ($Gateway) {
                New-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -IPAddress $IPAddress -PrefixLength $SubnetMask -DefaultGateway $Gateway | Out-Null
            } else {
                New-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -IPAddress $IPAddress -PrefixLength $SubnetMask | Out-Null
            }
            Log-Message "IP configuration set to IP: $IPAddress, Subnet: $SubnetMask, Gateway: $Gateway"
        
            # Remove existing DNS configuration
            Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ResetServerAddresses
        
            # Set new DNS configuration
            $newDNSConfig = @($PrimaryDNSServer, $SecondaryDNSServer) #| Where-Object { $_ -ne $PrimaryDNSServer }
            Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses $newDNSConfig | Out-Null
            Log-Message "DNS configuration set to Primary: $PrimaryDNSServer, Secondary: $SecondaryDNSServer"
        }  
        
        $IPAddress = Read-Host "Enter IP Address"
        do {
            if (-not (Validate-IPAddress -IPAddress $IPAddress)) {
                Write-Host "Invalid IP address format. Please enter a valid IPv4 address."
            }
        } until (Validate-IPAddress -IPAddress $IPAddress)

        $SubnetMask = [int](Read-Host "Enter Subnet Mask (1-32)")
        do {
            if (-not (Validate-SubnetMask -SubnetMask $SubnetMask)) {
                Write-Host "Invalid subnet mask. Please enter a value between 1 and 32."
            }
        } until (Validate-SubnetMask -SubnetMask $SubnetMask)

        $Gateway = Read-Host "Enter Default Gateway"
        do {
            if (-not (Validate-IPAddress -IPAddress $Gateway)) {
                Write-Host "Invalid Gateway address format. Please enter a valid IPv4 address."
            }
        } until (Validate-IPAddress -IPAddress $Gateway)

        $SecondaryDNSServer = Read-Host "Enter Secondary DNS Server"
        do {
            if (-not (Validate-IPAddress -IPAddress $SecondaryDNSServer)) {
                Write-Host "Invalid DNS Server address format. Please enter a valid IPv4 address."
            }
        } until (Validate-IPAddress -IPAddress $SecondaryDNSServer)

        $securePasswordPath = "$PSScriptRoot\Output\securePassword.txt"
        $securePasswordPath2 = "$PSScriptRoot\Output\securePassword2.txt"
        $password = Read-Host -Prompt "Enter the password for the forest configuration" -AsSecureString
        do {
            if (-not (Check-PasswordComplexity -password ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))))) {
                Write-Host "Password does not meet complexity requirements. Please try again."
            }
        } until (Check-PasswordComplexity -password ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))))        
        $password | ConvertFrom-SecureString | Set-Content -Path $securePasswordPath
        $password=Encrypt-Data -plainText ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))) -keyFile "$($config.Parameters.OutputDirectory)\aesKey.key" -ivFile "$($config.Parameters.OutputDirectory)\aesIV.iv"
        $password | Set-Content -Path "$securePasswordPath2"        
        $actualConfig  = Get-Content -Path "$PSScriptRoot\Input\config.json" -Raw | ConvertFrom-Json
        $config_secondary = @{
            Parameters = @{
                OutputDirectory = $actualConfig.Parameters.OutputDirectory
                InputDirectory  = $actualConfig.Parameters.InputDirectory
                LogFilePath     = ($actualConfig.Parameters.LogFilePath).replace("Scriptfile.txt", "Scriptfile-secondary.txt")
            }
            DomainInfo = @{
                Name              = $config.DomainInfo.New.Name                    
                DistinguishedName = $config.DomainInfo.New.DistinguishedName
                NetBIOS           = $config.DomainInfo.New.NetBIOS
                SecondaryDC       = (Add-IncrementationDCName -DCName ($config.DomainInfo.New.MasterDC))
            }
            Network = @{
                IPv4              = $SecondaryDNSServer
                Mask              = $SubnetMask
                Gateway           = $Gateway
                PrimaryDNS        = $IPAddress
                SecondaryDNS      = "127.0.0.1"
            }
        }

        $config_secondary | ConvertTo-Json -Depth 10 | Set-Content -Path "$PSScriptRoot\Output\config-secondary.json" -Force
        Set-NetworkConfiguration -IPAddress $IPAddress -SubnetMask $SubnetMask -Gateway $Gateway -PrimaryDNSServer "127.0.0.1" -SecondaryDNSServer $SecondaryDNSServer
        Update-State -step "Step2_Completed"
    } catch {
        Handle-Error "Failed to configure network settings: $_"
    }
}

# Step 3: Rename the network adapter
if (-not $scriptState.Step3_Completed) {
    try {
        $adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
        if ($adapter.Name -ne "LAN (T0)") {
            Rename-NetAdapter -Name $adapter.Name -NewName "LAN (T0)"
            Log-Message "Network adapter renamed to 'LAN (T0)'"
        } else {
            Log-Message "Network adapter is already named 'LAN (T0)'"
        }
        Update-State -step "Step3_Completed"
    } catch {
        Handle-Error "Failed to rename the network adapter: $_"
    }
}

# Step 4: Rename the PC
if (-not $scriptState.Step4_Completed) {
    try {
        $currentName = (Get-WmiObject Win32_ComputerSystem).Name
        $newMasterDC = $config.DomainInfo.New.MasterDC
        if ($currentName -ne $newMasterDC) {
            Rename-Computer -NewName $newMasterDC -Restart
            Update-State -step "Step4_Completed"
            exit
        } else {
            Log-Message "Computer name is already set to $newMasterDC"
            Update-State -step "Step4_Completed"
        }        
    } catch {
        Handle-Error "Failed to rename the computer: $_"
    }
}

# Reload state after restart
if (Test-Path $stateFilePath) {
    $scriptState = Get-Content -Path $stateFilePath | ConvertFrom-Json
}

# Step 5: Prompt for the password for the forest configuration
if (-not $scriptState.Step5_Completed) {
    try {
        $securePasswordPath = "$PSScriptRoot\Output\securePassword.txt"
        if (-not (Test-Path $securePasswordPath)) {
            Log-Message "Forest configuration password saved"
        } else {
            Log-Message "Forest configuration password is already set"
        }
        Update-State -step "Step5_Completed"
    } catch {
        Handle-Error "Failed to prompt for the forest configuration password: $_"
    }
}

# Step 6: Install necessary features
if (-not $scriptState.Step6_Completed) {
    try {
        Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
        Log-Message "AD-Domain-Services feature installed"
        Update-State -step "Step6_Completed"
    } catch {
        Handle-Error "Failed to install necessary features: $_"
    }
}

# Step 7: Install the ADDSDeployment module
if (-not $scriptState.Step7_Completed) {
    try {
        Import-Module ADDSDeployment
        Log-Message "ADDSDeployment module imported"
        Update-State -step "Step7_Completed"
    } catch {
        Handle-Error "Failed to install the ADDSDeployment module: $_"
    }
}

# Reload config after create
if (Test-Path "$PSScriptRoot\Input\config.json") {
    $config = Get-Config -ConfigPath "$PSScriptRoot\Input\config.json"
}

# Step 8: Install the AD forest and promote to domain controller
if (-not $scriptState.Step8_Completed) {
    try {
        $securePassword = Get-Content -Path "$PSScriptRoot\Output\securePassword.txt" | ConvertTo-SecureString
        #$securePassword = Decrypt-Data -encryptedText (Get-Content -Path "$PSScriptRoot\Output\securePassword.txt") -keyFile "$($config.Parameters.OutputDirectory)\aesKey.key" -ivFile "$($config.Parameters.OutputDirectory)\aesIV.iv" | ConvertTo-SecureString
        $result = Install-ADDSForest `
                -SafeModeAdministratorPassword $securePassword `
                -DomainName $config.DomainInfo.New.Name `
                -DomainNetBiosName $config.DomainInfo.New.NetBIOS `
                -InstallDns:$true `
                -DatabasePath "C:\Windows\NTDS" `
                -LogPath "C:\Windows\NTDS" `
                -SysvolPath "C:\Windows\SYSVOL" `
                -NoRebootOnCompletion:$false `
                -Force:$true `
                -Confirm:$false `
                -WarningAction SilentlyContinue
        Log-Message "ADDS forest installation initiated"
        Update-State -step "Step8_Completed"
        if ($result.RebootRequired) {
            Restart-Computer
        }
        exit
    } catch {
        Handle-Error "Failed to install the AD forest: $_"
    }
}

# Reload state after restart
if (Test-Path $stateFilePath) {
    $scriptState = Get-Content -Path $stateFilePath | ConvertFrom-Json
}

# Step 9: Import OUs, GPOs, and Groups into Active Directory
if (-not $scriptState.Step9_Completed) {
    Start-Sleep -Seconds 15
    while (-not (Get-ADDomainController -Identity $env:COMPUTERNAME)) {
        Start-Sleep -Seconds 5
    }      
    Import-Module -Name ActiveDirectory
    if (Verify-And-Promote-DomainController) {
        try {
            $ous = Get-Content -Path "$($config.Parameters.InputDirectory)\OUs.json" | ConvertFrom-Json
            $groups = Get-Content -Path "$($config.Parameters.InputDirectory)\Groups.json" | ConvertFrom-Json

            Import-OUs -ous $ous
            Import-Groups -groups $groups
            Import-GPOs -ImportPath "$($config.Parameters.InputDirectory)\GPO_Report"
            Link-GPOsToOUs -ous $ous

            Update-State -step "Step9_Completed"        
        } catch {
            Handle-Error "Failed to import OUs, GPOs, or Groups: $_"
        }
    }
}

Log-Message "Active Directory setup is complete!"

# Display completion message
Add-Type -AssemblyName PresentationFramework
#[System.Windows.MessageBox]::Show("Active Directory setup is complete", "Information", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
[System.Windows.MessageBox]::Show("Active Directory exported is complete. Check Scriptfile.txt for any error")
# Remove the scheduled task after the script completes
Remove-ScheduledTask -taskName $taskName
#endregion main
exit