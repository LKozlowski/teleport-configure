$ErrorActionPreference = "Stop"

$domain = 'example.com'
$netbiosDomain = ($domain -split '\.')[0].ToUpperInvariant()

$SecureDomainPassword = ConvertTo-SecureString "Qwer1234!" -AsPlainText -Force

echo 'Installing the AD services and administration tools...'
Install-WindowsFeature AD-Domain-Services,RSAT-AD-AdminCenter,RSAT-ADDS-Tools

echo 'Installing AD DS (be patient, this may take a while to install)...'
Import-Module ADDSDeployment
Install-ADDSForest `
    -InstallDns `
    -CreateDnsDelegation:$false `
    -ForestMode 'Win2012R2' `
    -DomainMode 'Win2012R2' `
    -DomainName $domain `
    -DomainNetbiosName $netbiosDomain `
    -SafeModeAdministratorPassword (ConvertTo-SecureString "Qwer1234!" -AsPlainText -Force)`
    -NoRebootOnCompletion `
    -Force

Restart-Computer -Force