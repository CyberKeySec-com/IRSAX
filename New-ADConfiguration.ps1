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

$jsonContent = Get-Content -Path "$PSScriptRoot\Source\config.json" -Raw | ConvertFrom-Json
$jsonContent.DomainInfo | Add-Member -MemberType NoteProperty -Name New -Value $newEntry

# Convertir l'objet de configuration en JSON et sauvegarder dans un fichier
$jsonContent | ConvertTo-Json -Depth 10 | Set-Content -Path "$PSScriptRoot\Source\config.json" -Encoding UTF8

Write-Output "Configuration file 'config.json' created successfully."