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

# Utilisation des paramètres dans le script
$outputDirectory = $config.Parameters.OutputDirectory
$inputDirectory = $config.Parameters.InputDirectory
$logFilePath = $config.Parameters.LogFilePath
$oldDomainName = $config.DomainInfo.OldDomainName
$newDomainName = $config.DomainInfo.NewDomainName
$domainController = $config.DomainInfo.DomainController

Write-Output "Output Directory: $outputDirectory"
Write-Output "Input Directory: $inputDirectory"
Write-Output "Log File Path: $logFilePath"
Write-Output "Old Domain Name: $oldDomainName"
Write-Output "New Domain Name: $newDomainName"
Write-Output "Domain Controller: $domainController"
