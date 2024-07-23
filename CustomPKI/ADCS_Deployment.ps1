$ErrorActionPreference = "SilentlyContinue"

Clear-Host
Write-Host "###########################################################################"
Write-Host "################ Installation et configuration de RootCA ##################"
Write-Host "###########################################################################"`n

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
        Register-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -TaskName $taskName -Description "Resume ADCS deployment script" -Force
        Write-Output "Scheduled task '$taskName' created successfully"
    } catch {
        Write-Output "Failed to create scheduled task: $_"
    }
}

# Function to update the state of script
function Update-State {
    param (
        [string]$step
    )
    $scriptState.$step = $true
    $scriptState | ConvertTo-Json | Set-Content -Path $stateFilePath
    Write-Output "Completed $step"
}

# Fonction pour obtenir le nom de l'autorité de certification
function Get-CAName {
    #$CAName = certutil | Select-String -Pattern "^ Nom :" | ForEach-Object { $_.ToString().Split(":")[1].Trim() }
    $pattern = 'Nom\s+:\s+(.+)'

    # Utilisation de Select-String pour appliquer le pattern regex
    $CAName = (certutil | Select-String -Pattern $pattern).Matches.Groups[1].Value | Foreach-Object {$_ -replace '"', ''}
    #$CAName = $CAName.
    return $CAName
}

############### Create the scheduled task to run the script at user login ###################

$taskName = "ResumeADCSDeploymentScript"
$scriptPath = (Get-Item -Path $MyInvocation.MyCommand.Definition).FullName
Create-ScheduledTask -taskName $taskName -scriptPath $scriptPath | Out-Null
$stateFilePath = "$PSScriptRoot\OutputScriptState.json"

# Initialize or read state
if (Test-Path $stateFilePath) {
    $scriptState = Get-Content -Path $stateFilePath | ConvertFrom-Json
} else {
    $scriptState = [ordered]@{
        Step0_Completed = $false
        Step1_Completed = $false
        Step2_Completed = $false
        Step3_Completed = $false
    }
}

############### Renommer le serveur ###################

if (-not $scriptState.Step0_Completed) {
    # Initialisation de la variable de confirmation
    $confirmRename = 'N'

    # Boucle pour demander le nom du serveur jusqu'à ce que l'utilisateur confirme
    while ($confirmRename -ne 'O') {
        # Demander à l'utilisateur de saisir le nom du serveur
        $newServerName = Read-Host -Prompt "Entrez le nom souhaite pour le serveur de certificat"
        Write-Output "Le nom du serveur est : $newServerName"

        # Demander confirmation à l'utilisateur pour le renommage
        $confirmRename = Read-Host -Prompt "Voulez-vous renommer le serveur avec ce nouveau nom ? (O/N)"
    }

    # Renommer le serveur avec le nouveau nom
    Rename-Computer -NewName $newServerName -Force

    Update-State -step "Step0_Completed"

    # Redémarrer la machine
    Write-Output "Attente de 5 secondes avant le redémarrage..."
    Start-Sleep -Seconds 5
    Restart-Computer -Force
}

############### Installation du service avec parametres ###################

if (-not $scriptState.Step1_Completed) {
    # Verifier si le role AD CS est deja installe
    $adcsFeature = Get-WindowsFeature -Name AD-Certificate

    if ($adcsFeature.Installed) {
        Write-Output "Le service AD CS est deja installe."
        $confirmReinstall = Read-Host -Prompt "Voulez-vous reinstaller le service AD CS ? (O/N)"
    
        if ($confirmReinstall -eq 'N') {
            Write-Output "Reinstallation annulee. Le script va maintenant s'arreter."
            exit
        } else {
            Write-Output "Reinstallation du service AD CS..."
            # Desinstaller le role AD CS
            Uninstall-AdcsCertificationAuthority -Force -WhatIf
            Remove-WindowsFeature -Name AD-Certificate
        }
    } else {
        Write-Output "Le service AD CS n'est pas installe. Le script va maintenant continuer."
    }

    # Demander a l'utilisateur de saisir le nom commun de l'autorite de certification
    $caCommonName = Read-Host "Entrez le nom commun pour l'autorite de certification (ex: TestStandaloneCA)"

    # Installation du role AD CS
    $params = @{
        CACommonName        = $caCommonName
        CAType              = "StandaloneRootCA"
        CryptoProviderName  = "RSA#Microsoft Software Key Storage Provider"
        KeyLength           = 2048
        HashAlgorithmName   = "SHA256"
        ValidityPeriod      = "Years"
        ValidityPeriodUnits = 1
    }

    try {
        # Installer les fonctionnalites necessaires
        Install-WindowsFeature AD-Certificate -IncludeManagementTools

        # Installer et configurer le CA autonome
        Install-AdcsCertificationAuthority @params

        # Demarrer le service AD CS
        Start-Service CertSvc

        # Verifier l'installation
        $adcsFeature = Get-WindowsFeature | Where-Object { $_.Name -eq "AD-Certificate" }
        if ($adcsFeature.Installed) {
            Write-Output "Installation reussie de l'autorite de certification autonome."
        } else {
            Write-Error "L'installation de AD CS a echoue."
        }
    } catch {
        Write-Error "Erreur lors de l'installation de AD CS : $_"
    }

    # Demarrer le service
    try {
        Start-Service certsvc
        Write-Output "Service certsvc demarre."
    } catch {
        Write-Error "Erreur lors du demarrage du service certsvc : $_"
        pause
        exit
    }

    Update-State -step "Step1_Completed"

    # Redemarrer la machine
    Write-Output "Attente de 5 secondes avant le redemarrage..."
    Start-Sleep -Seconds 5
    Restart-Computer -Force
}

##################### Stocker les certificats sur le controleur de domaine #########################

if (-not $scriptState.Step2_Completed) {
    function Convert-DomainToDistinguishedName {
        param (
            [Parameter(Mandatory=$true)]
            [string]$DomainName
        )    
    
        $components = $DomainName.Split('.')    
        # La première partie doit être convertie en DC, pas en CN
        $dnParts = $components | ForEach-Object { "DC=$_"}     
        $distinguishedName = $dnParts -join ','

        return $distinguishedName
    }

    # Fonction pour demander à l'utilisateur de saisir un FQDN
    function Get-UserFQDN {
        param (
            [string]$prompt = "Saisissez le nom de domaine complet (FQDN) distant"
        )

        $fqdn = Read-Host -Prompt $prompt
        return $fqdn
    }

    # Demander à l'utilisateur de saisir le FQDN
    $fqdn = Get-UserFQDN

    # Utiliser le FQDN saisi pour le traitement ultérieur
    if ($fqdn) {
        Write-Output "FQDN saisi : $fqdn"
    
        # Convertir le FQDN en DN
        $distinguishedName = Convert-DomainToDistinguishedName $fqdn

        # Configuration de la CA
        certutil -setreg CA\DSConfigDN "CN=Configuration,$($distinguishedName)"
        net stop certsvc 
        net start certsvc
        certutil -getreg CA\DSConfigDN
    } else {
        Write-Output "No FQDN entered."
    }


    # Charger l'assembly necessaire
    Add-Type -AssemblyName System.DirectoryServices.Protocols
    Clear-Host

    Update-State -step "Step2_Completed"
}

##################### Modifier l'emplacement de publication de RootCA #########################


# Obtenir le nom de l'autorité de certification

if (-not $scriptState.Step3_Completed) {
    $CAName = Get-CAName
    $CAName


    [String[]]$Objectif1 = "65:C:\Windows\system32\CertSrv\CertEnroll%3%8%9.crl","10:ldap:///CN=%7%8,CN=%2,CN=CDP,CN=Public Key Services,CN=Services,%6%10","0:http://%1/CertEnroll/%3%8%9.crl","0:file://%1/CertEnroll/%3%8%9.crl"
    [String[]]$Objectif2 = "10:ldap:///CN=%7%8,CN=%2,CN=CDP,CN=Public Key Services,CN=Services,%6%10"
    [String[]]$Objectif3 = "0:http://%1/CertEnroll/%3%8%9.crl"
    [String[]]$Objectif4 = "0:file://%1/CertEnroll/%3%8%9.crl"

    $CurrentValue = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$($CAName)" -Name CRLPublicationURLs

    if ($Objectif -ne $CurrentValue) {
        Write-Host "Registry needs to be updated..." -ForegroundColor Yellow
    
        # Mettre à jour la valeur de CRLPublicationURLs avec $Objectif
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$($CAName)" -Name CRLPublicationURLs -Value $Objectif1 
    
        Write-Host "Registry updated successfully!" -ForegroundColor Green
    } else {
        Write-Host "Registry is already up to date." -ForegroundColor Green
}


    Update-State -step "Step3_Completed"

    # Redemarrer la machine
    Write-Output "Attente de 5 secondes avant le redemarrage..."
    Start-Sleep -Seconds 5
    Restart-Computer -Force
}


##################### Générer une nouvelle liste de révocation des certificats #########################

# Fonction pour vérifier et démarrer les services nécessaires
function Start-RequiredServices {
    $services = @("RpcSs", "CertSvc")
    foreach ($service in $services) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne 'Running') {
            Write-Host "Starting service: $service"
            Start-Service -Name $service
        }
    }
}

# Fonction pour publier la CRL
function Publish-CRL {
    param (
        [string]$CAName
    )

    try {
        # Vérifier et démarrer les services nécessaires
        Start-RequiredServices

        # Générer la CRL
        Write-Host "Generating CRL for CA: $CAName"
        $certutilOutput = & certutil -crl 2>&1
        $exitCode = $LASTEXITCODE

        # Vérifier si la CRL est générée correctement
        if ($exitCode -ne 0) {
            Write-Error "Échec de la génération de la CRL. Code de sortie : $exitCode"
            Write-Error "Détails de l'erreur : $certutilOutput"
            return
        }

        Write-Host "Nouvelle liste de révocation des certificats publiée avec succès."
    } catch {
        Write-Error "Erreur lors de la publication de la CRL : $_"
    }
}

# Fonction pour obtenir le nom de la CA
function Get-CAName {
    $pattern = 'Nom\s+:\s+(.+)'
    $CAName = (certutil | Select-String -Pattern $pattern).Matches.Groups[1].Value.Trim()
    return $CAName
}

# Exécuter les étapes
$CAName = Get-CAName

if ($CAName) {
    Write-Host "Configuration des extensions pour l'autorité de certification : $CAName"
    # Ajoutez ici la configuration spécifique des extensions si nécessaire

    # Publier une nouvelle liste de révocation des certificats
    Publish-CRL -CAName $CAName
} else {
    Write-Error "Impossible de récupérer le nom de l'autorité de certification."
}

############### Deplacement des fichiers ###################

# Demander le nom de la machine cible à l'utilisateur
$targetMachine = Read-Host "Entrez le nom de machine Active Directory distante (ex: ADDS)"

# Demander les informations d'identification à l'utilisateur
$credential = Get-Credential

# Définir les chemins source et destination
$sourcePath = "C:\Windows\System32\CertSrv\CertEnroll"
$destinationUNC = "\\$targetMachine\c$"

# Créer un lecteur réseau temporaire avec les informations d'identification
New-PSDrive -Name Z -PSProvider FileSystem -Root $destinationUNC -Credential $credential

# Copier le contenu du dossier source vers le lecteur réseau temporaire
Copy-Item -Path $sourcePath\* -Destination Z:\ -Recurse

# Supprimer le lecteur réseau temporaire après la copie
Remove-PSDrive -Name Z


############### Publication des certificats ###################

# Demander le nom de la machine cible à l'utilisateur
$targetMachine = $targetMachine

# Demander les informations d'identification à l'utilisateur
$credential = $credential

# Spécifier le répertoire sur l'AD distant où les fichiers .crt et .crl sont stockés
$remoteDirectory = "C:\"

# Détecter et publier les fichiers .crt et .crl sur la machine cible
Invoke-Command -ComputerName $targetMachine -Credential $credential -ScriptBlock {
    param ($remoteDirectory)

    # Trouver tous les fichiers .crt et .crl dans le répertoire spécifié
    $certFiles = Get-ChildItem -Path $remoteDirectory -Filter *.crt
    $crlFiles = Get-ChildItem -Path $remoteDirectory -Filter *.crl

    # Publier chaque certificat .crt
    foreach ($certFile in $certFiles) {
        Write-Output "Publication du certificat: $($certFile.FullName)"
        try {
            certutil -dspublish -f $certFile.FullName rootca
        } catch {
            Write-Output "Erreur lors de la publication du certificat: $_"
        }
    }

    # Publier chaque fichier .crl
    foreach ($crlFile in $crlFiles) {
        Write-Output "Publication de la CRL: $($crlFile.FullName)"
        try {
            certutil -dspublish -f $crlFile.FullName
        } catch {
            Write-Output "Erreur lors de la publication de la CRL: $_"
        }
    }
} -ArgumentList $remoteDirectory

Clear-Host
Write-Host "####################################################################################"
Write-Host "################ Installation et configuration de RootCA complete ! ################"
Write-Host "####################################################################################"`n
pause