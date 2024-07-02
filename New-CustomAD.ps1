# Function to import OUs
function Import-OUs {
    param ([array]$ous)

    # Function to check if an OU exists
    function OU-Exists {
        param ([string]$DN)
        return [bool](Get-ADOrganizationalUnit -Filter { DistinguishedName -eq $DN } -ErrorAction SilentlyContinue)
    }

    # Function to create parent OUs if they do not exist
    function Ensure-ParentOUs {
        param ([string]$DN)
        $ouPathParts = $DN -split ','
        $currentPath = ""

        for ($i = $ouPathParts.Length - 1; $i -gt 0; $i--) {
            $currentPath = ($ouPathParts[$i..($ouPathParts.Length - 1)] -join ',')
            if (-not (OU-Exists -DN $currentPath)) {
                try {
                    $parentPath = ($ouPathParts[($i + 1)..($ouPathParts.Length - 1)] -join ',')
                    New-ADOrganizationalUnit -Name $ouPathParts[$i] -Path $parentPath
                    Log-Message "Created Parent OU: $($ouPathParts[$i]) at path $parentPath"
                } catch {
                    Log-Message "Failed to create Parent OU: $($ouPathParts[$i]) - $_" "ERROR"
                }
            }
        }
    }

    foreach ($ou in $ous) {
        $ouName          = $ou.Name
        $ouDN            = $ou.DistinguishedName
        $firstCommaIndex = $ouDN.IndexOf(',')
        if ($firstCommaIndex -ne -1) {
            $DN = $ouDN.Substring($firstCommaIndex + 1).Trim()
        } else {
            $DN = $ouDN
        }
        $ouDescription = $ou.Description
        Log-Message "Name: $ouName"
        Log-Message "DistinguishedName: $DN"
        Log-Message "Description: $ouDescription"

        if (-not (OU-Exists -DN $ouDN)) {
            try {
                # Ensure all parent OUs are created
                Ensure-ParentOUs -DN $ouDN
                # Create the target OU
                if ($ouDescription) {
                    New-ADOrganizationalUnit -Name $ouName -Path $DN -Description $ouDescription
                } else {
                    New-ADOrganizationalUnit -Name $ouName -Path $DN
                }          
                Log-Message "Created OU: $($ouName)"
            } catch {
                Log-Message "Failed to create OU: $($ouName) - $_" "ERROR"
            }
        } else {
            Log-Message "OU already exists: $($ouName)"
        }
    }
}

# Function to import Groups
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
                #Write-Output "Members of `"$groupName`":`n$currentMembers"
                $desiredMembers = $group.Members | ForEach-Object { $_.DistinguishedName }

                # Add members that are not in the current group
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

                # Remove members that are not in the desired list
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

# Function to import GPOs
function Import-GPOs {
    param ([array]$gpos)

    foreach ($gpo in $gpos) {
        $gpoName        = $gpo.DisplayName
        $gpoDescription = $gpo.Description
        Log-Message "Name: $gpoName"
        Log-Message "Description: $gpoDescription"
        if (-not (Get-GPO -Name $gpoName -ErrorAction SilentlyContinue)) {
            try {
                $newGPO = New-GPO -Name $gpoName -Comment $gpoDescription
                foreach ($link in $gpo.Links) {
                    New-GPLink -Name $newGPO.DisplayName -Target $link.Target -LinkEnabled $link.Enabled -Enforced $link.Enforced
                }
                Log-Message "Created GPO: $($gpoName)"
            } catch {
                Log-Message "Failed to create GPO: $($gpoName) - $_" "ERROR"
            }
        } else {
            Log-Message "GPO already exists: $($gpoName)"
        }
    }
}

function Link-GPOsToOUs {
    param ([array]$ous)

    foreach ($ou in $ous) {
        $ouDN = $ou.DistinguishedName
        if ($ou.Links) {
            foreach ($link in $ou.Links) {
                if ($link.GPOName) {
                    try {
                        # Check if GPO exists
                        $gpo = Get-GPO -Name $link.GPOName -ErrorAction SilentlyContinue
                        if ($null -ne $gpo) {
                            # Check if link already exists
                            $existingLinks = Get-GPInheritance -Target $ouDN | Select-Object -ExpandProperty GpoLinks
                            $linkExists = $false
                            foreach ($existingLink in $existingLinks) {
                                if ($existingLink.DisplayName -eq $link.GPOName) {
                                    $linkExists = $true
                                    break
                                }
                            }

                            if (-not $linkExists) {
                                New-GPLink -Name $link.GPOName -Target $ouDN -LinkEnabled $link.Enabled -Enforced $link.Enforced
                                Log-Message "Linked GPO $($link.GPOName) to OU $ouDN"
                            } else {
                                Log-Message "Link for GPO $($link.GPOName) already exists on OU $ouDN"
                            }
                        } else {
                            Log-Message "GPO $($link.GPOName) does not exist" "ERROR"
                        }
                    } catch {
                        Log-Message "Failed to link GPO $($link.GPOName) to OU $ouDN - $_" "ERROR"
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
# Complete script with steps

# Define state file path
$stateFilePath = "$PSScriptRoot\Output\ScriptState.json"

# Define function to read and process the config.json file
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
    $config.Parameters.InputDirectory  = Replace-VariablesInPath -Path $config.Parameters.InputDirectory
    $config.Parameters.LogFilePath     = Replace-VariablesInPath -Path $config.Parameters.LogFilePath

    # Return the updated config object
    return $config
}

# Method for calling the function and reading the config.json file
$config = Get-Config -ConfigPath "$PSScriptRoot\Input\config.json"

# Initialize or read state
if (Test-Path $stateFilePath) {
    $scriptState = Get-Content -Path $stateFilePath | ConvertFrom-Json
} else {
    $scriptState = [ordered]@{
        Step1_Completed = $false
        Step2_Completed = $false
        Step3_Completed = $false
        Step4_Completed = $false
        Step5_Completed = $false
        Step6_Completed = $false
        Step7_Completed = $false
        Step8_Completed = $false
    }
}

# Initialize log file
$logFilePath = $config.Parameters.LogFilePath
if (-not (Test-Path $logFilePath)) {
    New-Item -Path $logFilePath -ItemType File -Force
}

function Log-Message {
    param (
        [string]$message,
        [string]$type = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp [$type] - $message" | Out-File -Append -FilePath $logFilePath
}

function Update-State {
    param (
        [string]$step
    )
    $scriptState.$step = $true
    $scriptState | ConvertTo-Json | Set-Content -Path $stateFilePath
    Log-Message "Completed $step"
}

function Handle-Error {
    param (
        [string]$errorMessage
    )
    Log-Message $errorMessage "ERROR"
    exit 1
}

# Function to create a scheduled task to run the script at user login
function Create-ScheduledTask {
    param (
        [string]$taskName,
        [string]$scriptPath
    )

    try {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
        $trigger  = New-ScheduledTaskTrigger -AtLogon
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

        Register-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -TaskName $taskName -Description "Resume AD deployment script" -Force
        Log-Message "Scheduled task '$taskName' created successfully"
    } catch {
        Handle-Error "Failed to create scheduled task: $_"
    }
}

# Remove the scheduled task
function Remove-ScheduledTask {
    param (
        [string]$taskName
    )

    try {
        Unregister-ScheduledTask -TaskName $taskName -Confirm: $false
        Log-Message "Scheduled task '$taskName' removed successfully"
    } catch {
        Handle-Error "Failed to remove scheduled task: $_"
    }
}

# Create the scheduled task to run the script at user login
$taskName   = "ResumeADDeploymentScript"
$scriptPath = (Get-Item -Path $MyInvocation.MyCommand.Definition).FullName
Create-ScheduledTask -taskName $taskName -scriptPath $scriptPath

# Function to check password complexity
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

# Function to validate IP address
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

# Function to validate subnet mask
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

# Step 1: Rename the PC
if (-not $scriptState.Step1_Completed) {
    try {
        $currentName = (Get-WmiObject Win32_ComputerSystem).Name
        $newMasterDC = $config.DomainInfo.New.MasterDC
        if ($currentName -ne $newMasterDC) {
            Rename-Computer -NewName $newMasterDC -Restart
            Update-State -step "Step1_Completed"
            exit
        } else {
            Log-Message "Computer name is already set to $newMasterDC"
            Update-State -step "Step1_Completed"
        }
    } catch {
        Handle-Error "Failed to rename the computer: $_"
    }
}

# Reload state after restart
if (Test-Path $stateFilePath) {
    $scriptState = Get-Content -Path $stateFilePath | ConvertFrom-Json
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

            $adapter         = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
            $currentIPConfig = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex | Where-Object { $_.AddressFamily -eq 'IPv4' }

            # Check if the IP configuration needs to be updated
            if ($currentIPConfig.IPAddress -ne $IPAddress -or $currentIPConfig.PrefixLength -ne $SubnetMask) {
                New-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -IPAddress $IPAddress -PrefixLength $SubnetMask -DefaultGateway $Gateway
                Log-Message "IP configuration set to IP: $IPAddress, Subnet: $SubnetMask, Gateway: $Gateway"
            } else {
                Log-Message "IP configuration is already set to IP: $IPAddress, Subnet: $SubnetMask, Gateway: $Gateway"
            }

            $currentDNSConfig = Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex

            # Check if the DNS configuration needs to be updated
            $newDNSConfig = @("127.0.0.1", $PrimaryDNSServer, $SecondaryDNSServer | Where-Object { $_ -ne "127.0.0.1" -and $_ -ne $PrimaryDNSServer })
            if ($currentDNSConfig.ServerAddresses -ne $newDNSConfig) {
                Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses $newDNSConfig
                Log-Message "DNS configuration set to Primary: 127.0.0.1, Secondary: $PrimaryDNSServer"
            } else {
                Log-Message "DNS configuration is already set to Primary: 127.0.0.1, Secondary: $PrimaryDNSServer"
            }
        }

        # Get user input for network configuration with validation
        do {
            $IPAddress = Read-Host "Enter IP Address"
            if (-not (Validate-IPAddress -IPAddress $IPAddress)) {
                Write-Host "Invalid IP address format. Please enter a valid IPv4 address."
            }
        } until (Validate-IPAddress -IPAddress $IPAddress)

        do {
            $SubnetMask = [int](Read-Host "Enter Subnet Mask (1-32)")
            if (-not (Validate-SubnetMask -SubnetMask $SubnetMask)) {
                Write-Host "Invalid subnet mask. Please enter a value between 1 and 32."
            }
        } until (Validate-SubnetMask -SubnetMask $SubnetMask)

        do {
            $Gateway = Read-Host "Enter Default Gateway"
            if (-not (Validate-IPAddress -IPAddress $Gateway)) {
                Write-Host "Invalid Gateway address format. Please enter a valid IPv4 address."
            }
        } until (Validate-IPAddress -IPAddress $Gateway)

        do {
            $PrimaryDNSServer = Read-Host "Enter Primary DNS Server"
            if (-not (Validate-IPAddress -IPAddress $PrimaryDNSServer)) {
                Write-Host "Invalid DNS Server address format. Please enter a valid IPv4 address."
            }
        } until (Validate-IPAddress -IPAddress $PrimaryDNSServer)

        Set-NetworkConfiguration -IPAddress $IPAddress -SubnetMask $SubnetMask -Gateway $Gateway -PrimaryDNSServer $PrimaryDNSServer -SecondaryDNSServer "127.0.0.1"
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

# Step 4: Prompt for the password for the forest configuration
if (-not $scriptState.Step4_Completed) {
    try {
        $securePasswordPath = "$PSScriptRoot\Output\securePassword.txt"
        if (-not (Test-Path $securePasswordPath)) {
            do {
                $password = Read-Host -Prompt "Enter the password for the forest configuration"
                if (-not (Check-PasswordComplexity -password $password)) {
                    Write-Host "Password does not meet complexity requirements. Please try again."
                }
            } until (Check-PasswordComplexity -password $password)
            $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
            $securePassword | ConvertFrom-SecureString | Set-Content -Path $securePasswordPath
            Log-Message "Forest configuration password saved"
        } else {
            Log-Message "Forest configuration password is already set"
        }
        Update-State -step "Step4_Completed"
    } catch {
        Handle-Error "Failed to prompt for the forest configuration password: $_"
    }
}

# Step 5: Install necessary features
if (-not $scriptState.Step5_Completed) {
    try {
        Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
        Log-Message "AD-Domain-Services feature installed"
        Update-State -step "Step5_Completed"
    } catch {
        Handle-Error "Failed to install necessary features: $_"
    }
}

# Step 6: Install the ADDSDeployment module
if (-not $scriptState.Step6_Completed) {
    try {
        Import-Module ADDSDeployment
        Log-Message "ADDSDeployment module imported"
        Update-State -step "Step6_Completed"
    } catch {
        Handle-Error "Failed to install the ADDSDeployment module: $_"
    }
}

# Step 7: Install the AD forest and promote to domain controller
if (-not $scriptState.Step7_Completed) {
    try {
        $securePassword = Get-Content -Path "$PSScriptRoot\Output\securePassword.txt" | ConvertTo-SecureString
        $result         = Install-ADDSForest -DomainName $config.DomainInfo.New.Name `
                           -SafeModeAdministratorPassword $securePassword `
                           -InstallDns `
                           -CreateDnsDelegation:$false `
                           -DatabasePath "C:\Windows\NTDS" `
                           -LogPath "C:\Windows\NTDS" `
                           -SysvolPath "C:\Windows\SYSVOL" `
                           -Force: $true
        Log-Message "ADDS forest installation initiated"
        Update-State -step "Step7_Completed"

        if ($result.RebootRequired) {
            Restart-Computer
            exit
        }
    } catch {
        Handle-Error "Failed to install the AD forest: $_"
    }
}

# Reload state after restart
if (Test-Path $stateFilePath) {
    $scriptState = Get-Content -Path $stateFilePath | ConvertFrom-Json
}

# Verify if the server is promoted as a domain controller, and promote if necessary
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
            $result         = Install-ADDSDomainController -DomainName $config.DomainInfo.New.Name `
                                         -SafeModeAdministratorPassword $securePassword `
                                         -InstallDns `
                                         -CreateDnsDelegation:$false `
                                         -DatabasePath "C:\Windows\NTDS" `
                                         -LogPath "C:\Windows\NTDS" `
                                         -SysvolPath "C:\Windows\SYSVOL" `
                                         -Force: $true
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

if (-not $scriptState.Step8_Completed) {
    if (Verify-And-Promote-DomainController) {
        try {
            $ous    = Get-Content -Path "$PSScriptRoot\Input\OUs.json" | ConvertFrom-Json
            $gpos   = Get-Content -Path "$PSScriptRoot\Input\GPOs.json" | ConvertFrom-Json
            $groups = Get-Content -Path "$PSScriptRoot\Input\Groups.json" | ConvertFrom-Json

            Import-OUs -ous $ous
            Write-Output "OU fait"
            Import-Groups -groups $groups
            Write-Output "Groups fait"
            Import-GPOs -gpos $gpos
            Write-Output "GPO fait"
            Link-GPOsToOUs -ous $ous
            Write-Output "GPO Links fait"

            Update-State -step "Step8_Completed"
        } catch {
            Handle-Error "Failed to import OUs, GPOs, or Groups: $_"
        }
    }
}

Log-Message "Active Directory setup is complete!"

# Remove the scheduled task after the script completes
Remove-ScheduledTask -taskName $taskName