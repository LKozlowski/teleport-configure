

$Name="Teleport Service Account"
$SamAccountName="svc-teleport"

$DomainDN=$((Get-ADDomain).DistinguishedName)

$BlockGPOName="Block teleport-svc Interactive Login"
$BlockPolicyGuid=(Get-GPO -Name $BlockGPOName).Id.Guid
Remove-GPLink -Guid $BlockPolicyGuid -Target $DomainDN
Remove-GPO -Guid $BlockPolicyGuid


$AccessGPOName="Teleport Access Policy"
$AccessGPOGuid=(Get-GPO -Name $AccessGPOName).Id.Guid
Remove-GPLink -Guid $AccessGPOGuid -Target $DomainDN
Remove-GPO -Guid $AccessGPOGuid


Remove-ADObject -Identity "CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,$DomainDN" -Recursive
Remove-ADUser -Identity $SamAccountName

gpupdate.exe /force
