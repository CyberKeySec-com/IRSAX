#region Functions

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

    try {
        $config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
    } catch {
        Handle-Error "Failed to load or parse configuration file: $_"
    }

    try {
        $config.Parameters.OutputDirectory = Replace-VariablesInPath -Path $config.Parameters.OutputDirectory
        $config.Parameters.InputDirectory  = Replace-VariablesInPath -Path $config.Parameters.InputDirectory
        $config.Parameters.LogFilePath     = Replace-VariablesInPath -Path $config.Parameters.LogFilePath
    } catch {
        Handle-Error "Failed to replace variables in configuration paths: $_"
    }

    return $config
}

# Function to handle errors
function Handle-Error {
    param (
        [string]$errorMessage
    )
    Log-Message $errorMessage "ERROR"
    exit 1
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
            $securePassword = Get-Content -Path "$PSScriptRoot\Output\securePassword3.txt" | ConvertTo-SecureString
            $result = Install-ADDSDomainController -DomainName $config.DomainInfo.Name `
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

#endregion Functions

#region Main Script
Clear-Host
$ConfirmPreference = 'None'
# $ErrorActionPreference = 'SilentlyContinue'

# Load configuration
$config = Get-Config -ConfigPath "$PSScriptRoot\Output\config-secondary.json"
$stateFilePath = "$PSScriptRoot\Output\ScriptState-secondary.json"

# Create the scheduled task to run the script at user login
$logFilePath = ($config.Parameters.LogFilePath)
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

# Step 1: Configure IP/Network and DNS settings
if (-not $scriptState.Step1_Completed) {
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

        # Load configuration
        $config = Get-Config -ConfigPath "$PSScriptRoot\Output\config-secondary.json"
        $IPAddress = $config.Network.IPv4
        $SubnetMask = $config.Network.Mask
        $Gateway = $config.Network.Gateway
        $PrimaryDNSServer = $config.Network.PrimaryDNS
        $SecondaryDNSServer = $config.Network.SecondaryDNS        
        #$password = Decrypt-Data -encryptedText (Get-Content -Path "$($config.Parameters.OutputDirectory)\securePassword2.txt") -keyFile (Get-Content -Path "$($config.Parameters.OutputDirectory)\aesKey.key") -ivFile (Get-Content -Path "$($config.Parameters.OutputDirectory)\aesIV.iv")
        $encryptedText=(Get-Content -Path "$PSScriptRoot\Output\securePassword2.txt")        
        $keyFile="$($config.Parameters.OutputDirectory)\aesKey.key"
        $ivFile="$($config.Parameters.OutputDirectory)\aesIV.iv"                
        $password = Decrypt-Data -encryptedText $encryptedText -keyFile $keyFile -ivFile $ivFile
        if (-not (Check-PasswordComplexity -password $password)) {
            Handle-Error "Password does not meet complexity requirements."
        }
        $password | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Set-Content -Path "$($config.Parameters.OutputDirectory)\securePassword3.txt"
        Set-NetworkConfiguration -IPAddress $IPAddress -SubnetMask $SubnetMask -Gateway $Gateway -PrimaryDNSServer $PrimaryDNSServer -SecondaryDNSServer $SecondaryDNSServer
        Update-State -step "Step1_Completed"
    } catch {
        Handle-Error "Failed to configure network settings: $_"
    }
}

# Step 2: Rename the network adapter
if (-not $scriptState.Step2_Completed) {
    try {
        $adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
        if ($adapter.Name -ne "LAN (T0)") {
            Rename-NetAdapter -Name $adapter.Name -NewName "LAN (T0)"
            Log-Message "Network adapter renamed to 'LAN (T0)'"
        } else {
            Log-Message "Network adapter is already named 'LAN (T0)'"
        }
        Update-State -step "Step2_Completed"
    } catch {
        Handle-Error "Failed to rename the network adapter: $_"
    }
}

# Step 3: Rename the PC
if (-not $scriptState.Step3_Completed) {
    try {
        $currentName = (Get-WmiObject Win32_ComputerSystem).Name
        $newMasterDC = $config.DomainInfo.SecondaryDC
        if ($currentName -ne $newMasterDC) {            
            Rename-Computer -NewName $newMasterDC -Restart
            Update-State -step "Step3_Completed"
            exit
        } else {
            Log-Message "Computer name is already set to $newMasterDC"
            Update-State -step "Step3_Completed"
        }        
    } catch {
        Handle-Error "Failed to rename the computer: $_"
    }
}

# Reload state after restart
if (Test-Path $stateFilePath) {
    $scriptState = Get-Content -Path $stateFilePath | ConvertFrom-Json
}

# Step 4: Install necessary features
if (-not $scriptState.Step4_Completed) {
    try {
        Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
        Log-Message "AD-Domain-Services feature installed"
        Update-State -step "Step4_Completed"
    } catch {
        Handle-Error "Failed to install necessary features: $_"
    }
}

# Step 5: Install the ADDSDeployment module
if (-not $scriptState.Step5_Completed) {
    try {
        Import-Module ADDSDeployment
        Log-Message "ADDSDeployment module imported"
        Update-State -step "Step5_Completed"
    } catch {
        Handle-Error "Failed to install the ADDSDeployment module: $_"
    }
}

# Step 6: Test network connectivity and DNS resolution
if (-not $scriptState.Step6_Completed) {
    try {        
        $pingResult=Test-Connection -ComputerName $config.Network.PrimaryDNS -Count 2 -Quiet        
        if($pingResult){
            Update-State -step "Step6_Completed"
        }
        else{
            Handle-Error "Failed network connectivity or DNS resolution tests: $pingResult"
        }
    } catch {
        Handle-Error "Failed network connectivity or DNS resolution tests: $_"
    }
}

# Step 7: Install the AD domain controller and promote to secondary domain controller
if (-not $scriptState.Step7_Completed) {
    $securePassword = Get-Content -Path "$PSScriptRoot\Output\securePassword3.txt" | ConvertTo-SecureString
    # $username="$($config.DomainInfo.NetBIOS)\$env:USERNAME"
    # $credential = New-Object System.Management.Automation.PSCredential($env:USERNAME, $securePassword)
    try {        
        $result = Install-ADDSDomainController `
                -SafeModeAdministratorPassword $securePassword `
                -DomainName $config.DomainInfo.Name `
                -DatabasePath "C:\Windows\NTDS" `
                -LogPath "C:\Windows\NTDS" `
                -SysvolPath "C:\Windows\SYSVOL" `
                -InstallDns `
                -Credential (Get-Credential -Message "Admin AD account" -UserName "$($config.DomainInfo.NetBIOS)\$env:USERNAME") `
                -SiteName "Default-First-Site-Name" `
                -Force `
                -NoRebootOnCompletion:$true `
                -WarningAction SilentlyContinue

        Log-Message "ADDS domain controller installation initiated"
        Update-State -step "Step7_Completed"
        if ($result.RebootRequired) {
            Restart-Computer
            exit
        }
    } catch {
        Handle-Error "Failed to install the AD domain controller: $_"
    }
}

# Reload state after restart
if (Test-Path $stateFilePath) {
    $scriptState = Get-Content -Path $stateFilePath | ConvertFrom-Json
}

# Step 8: Verify if the server is a domain controller and promote if necessary
if (-not $scriptState.Step8_Completed) {
    try {
        Verify-And-Promote-DomainController
        Update-State -step "Step8_Completed"
    } catch {
        Handle-Error "Failed to verify or promote the server to a domain controller: $_"
    }
}

while (-not (Get-ADDomainController -Identity $env:COMPUTERNAME -ErrorAction SilentlyContinue)) {
    Start-Sleep -Seconds 5
}

Log-Message "Active Directory setup is complete!"

# Display completion message
Add-Type -AssemblyName PresentationFramework
#[System.Windows.MessageBox]::Show("Active Directory setup is complete", "Information", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
[System.Windows.MessageBox]::Show("Active Directory exported is complete. Check Scriptfile-secondary.txt for any error")
# Step 9: Remove the scheduled task after the script completes
Remove-ScheduledTask -taskName $taskName
#endregion Main Script
exit