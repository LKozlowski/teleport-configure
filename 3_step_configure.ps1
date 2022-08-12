

# Step 1/7. Create a restrictive service account 

$Name="Teleport Service Account"
$SamAccountName="svc-teleport"

$DomainDN=$((Get-ADDomain).DistinguishedName)

# Generate a random password that meets the "Password must meet complexity requirements" security policy setting.
# Note: if the minimum complexity requirements have been changed from the Windows default, this part of the script may need to be modified.
Add-Type -AssemblyName 'System.Web'
do {
   $Password=[System.Web.Security.Membership]::GeneratePassword(15,1)
} until ($Password -match '\d')
$SecureStringPassword=ConvertTo-SecureString $Password -AsPlainText -Force

New-ADUser `
  -Name $Name `
  -SamAccountName $SamAccountName `
  -AccountPassword $SecureStringPassword `
  -Enabled $true


# Create the CDP/Teleport container.
# If the command fails with "New-ADObject : An attempt was made to add an object to the directory with a name that is already in use",
# it means the object already exists and you can move on to the next step.
New-ADObject -Name "Teleport" -Type "container" -Path "CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,$DomainDN"

# Gives Teleport the ability to create LDAP containers in the CDP container.
dsacls "CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,$DomainDN" /I:T /G "$($SamAccountName):CC;container;"
# Gives Teleport the ability to create and delete cRLDistributionPoint objects in the CDP/Teleport container.
dsacls "CN=Teleport,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,$DomainDN" /I:T /G "$($SamAccountName):CCDC;cRLDistributionPoint;"
# Gives Teleport the ability to write the certificateRevocationList property in the CDP/Teleport container.
dsacls "CN=Teleport,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,$DomainDN " /I:T /G "$($SamAccountName):WP;certificateRevocationList;"
# Gives Teleport the ability to create and delete certificationAuthority objects in the NTAuthCertificates container.
dsacls "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,$DomainDN" /I:T /G "$($SamAccountName):CCDC;certificationAuthority;"
# Gives Teleport the ability to write the cACertificate property in the NTAuthCertificates container.
dsacls "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,$DomainDN" /I:T /G "$($SamAccountName):WP;cACertificate;"

$SamAccountSID=(Get-ADUser -Identity $SamAccountName).SID.Value


# Step 2/7. Prevent the service account from performing interactive logins

$BlockGPOName="Block teleport-svc Interactive Login"
New-GPO -Name $BlockGPOName | New-GPLink -Target $DomainDN

$DenySecurityTemplate=@'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
[Privilege Rights]
SeDenyRemoteInteractiveLogonRight=*{0}
SeDenyInteractiveLogonRight=*{0}
'@ -f $SamAccountSID


$BlockPolicyGuid=((Get-GPO -Name $BlockGPOName).Id.Guid).ToUpper()
$BlockGPOPath="$env:SystemRoot\SYSVOL\sysvol\example.com\Policies\{$BlockPolicyGuid}\Machine\Microsoft\Windows NT\SecEdit"
New-Item -Type Directory -Path $BlockGPOPath
New-Item -Path $BlockGPOPath -Name "GptTmpl.inf" -ItemType "file" -Value $DenySecurityTemplate


# Step 3/7. Configure a GPO to allow Teleport connections 
$AccessGPOName="Teleport Access Policy"
New-GPO -Name $AccessGPOName | New-GPLink -Target $DomainDN

# Import certificate Trusted Root Certification Authority
# For now it is using the generated blob, but we can easily change it so e.g we generate that powershell script to already include that
# blob inside this script
$CERTIFICATE_ID = (Get-Item .\*.blob |Select-Object).BaseName
$CERT = Get-Content -Path ".\$CERTIFICATE_ID.blob" -Encoding Byte -Raw
Set-GPRegistryValue -Name $AccessGPOName -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\SystemCertificates\Root\Certificates\$CERTIFICATE_ID" -ValueName "Blob" -Type Binary -Value $CERT


$UserCACertName = "user-ca.cer"
certutil -dspublish -f $UserCACertName RootCA
certutil -dspublish -f $UserCACertName NTAuthCA
certutil -pulse

$AccessSecurityTemplate=@'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
[Service General Setting]
"SCardSvr",2,""
'@ -f $SamAccountSID

$commentXML=@'
<?xml version='1.0' encoding='utf-8'?>
<policyComments xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" revision="1.0" schemaVersion="1.0" xmlns="http://www.microsoft.com/GroupPolicy/CommentDefinitions">
  <policyNamespaces>
    <using prefix="ns0" namespace="Microsoft.Policies.TerminalServer"></using>
  </policyNamespaces>
  <comments>
    <admTemplate></admTemplate>
  </comments>
  <resources minRequiredRevision="1.0">
    <stringTable></stringTable>
  </resources>
</policyComments>
'@


$AccessPolicyGuid=((Get-GPO -Name $AccessGPOName).Id.Guid).ToUpper()
$AccessGPOPath="$env:SystemRoot\SYSVOL\sysvol\example.com\Policies\{$AccessPolicyGuid}\Machine\Microsoft\Windows NT\SecEdit"
New-Item -Type Directory -Path $AccessGPOPath
New-Item -Path $AccessGPOPath -Name "GptTmpl.inf" -ItemType "file" -Value $AccessSecurityTemplate
New-Item -Path "$env:SystemRoot\SYSVOL\sysvol\example.com\Policies\{$Policy}\Machine" -Name "comment.cmtx" -ItemType "file" -Value $commentXML

# Firewall
$FirewallUserModeInTCP = "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=3389|App=%SystemRoot%\system32\svchost.exe|Svc=termservice|Name=@FirewallAPI.dll,-28775|Desc=@FirewallAPI.dll,-28756|EmbedCtxt=@FirewallAPI.dll,-28752|"
Set-GPRegistryValue -Name $AccessGPOName -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall" -ValueName "PolicyVersion" -Type DWORD -Value 543
Set-GPRegistryValue -Name $AccessGPOName -Type String -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsFirewall\FirewallRules" -ValueName "RemoteDesktop-UserMode-In-TCP" -Value $FirewallUserModeInTCP


# Allow remote RDP connections 
Set-GPRegistryValue -Name $AccessGPOName -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "fDenyTSConnections" -Type DWORD -Value 0
Set-GPRegistryValue -Name $AccessGPOName -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "UserAuthentication" -Type DWORD -Value 0


# # Step 5/7. Export your LDAP CA certificate 
certutil "-ca.cert" .\server-ca.der


gpupdate.exe /force
