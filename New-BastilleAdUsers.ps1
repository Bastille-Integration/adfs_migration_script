# Version: 1.0
# Requires: Run as Administrator on a domain controller (ActiveDirectory + ADFS modules)
# Purpose: Create the Bastille OU/group/user structure and bind ADFS Web API
#          applications to the appropriate access-control groups.

$DomainDN = (Get-ADDomain).DistinguishedName
$DomainForest = (Get-ADDomain).Forest
New-ADOrganizationalUnit -Name "Bastille" -Path "$DomainDN"
New-ADOrganizationalUnit -Name "Groups" -Path "OU=Bastille,$DomainDN"
New-ADOrganizationalUnit -Name "Users" -Path "OU=Bastille,$DomainDN"
New-ADOrganizationalUnit -Name "Admins" -Path "OU=Users,OU=Bastille,$DomainDN"
New-ADOrganizationalUnit -Name "Operators" -Path "OU=Users,OU=Bastille,$DomainDN"
New-ADOrganizationalUnit -Name "Viewers" -Path "OU=Users,OU=Bastille,$DomainDN"
New-ADGroup -GroupScope Global -Name "BNAdmin" -Path "OU=Groups,OU=Bastille,$DomainDN"
New-ADGroup -GroupScope Global -Name "DVROps" -Path "OU=Groups,OU=Bastille,$DomainDN"
New-ADGroup -GroupScope Global -Name "DVRViewer" -Path "OU=Groups,OU=Bastille,$DomainDN"
New-ADGroup -GroupScope Global -Name "ADAMOps" -Path "OU=Groups,OU=Bastille,$DomainDN"
New-ADGroup -GroupScope Global -Name "ADAMViewer" -Path "OU=Groups,OU=Bastille,$DomainDN"
Add-ADGroupMember -Members "BN Test" -Identity "BNAdmin"
New-ADUser -Name "BN Viewer" -GivenName "BN" -Surname "Viewer" -UserPrincipalName "bn-viewer@$DomainForest" -PasswordNeverExpires $true -AccountPassword (ConvertTo-SecureString "bastille#123" -AsPlainText -Force) -Enabled $true -Path "OU=Viewers,OU=Users,OU=Bastille,$DomainDN"
New-ADUser -Name "BN Ops" -GivenName "BN" -Surname "Ops" -UserPrincipalName "bn-ops@$DomainForest" -PasswordNeverExpires $true -AccountPassword (ConvertTo-SecureString "bastille#123" -AsPlainText -Force) -Enabled $true -Path "OU=Operators,OU=Users,OU=Bastille,$DomainDN"
Add-ADGroupMember -Members "BN Viewer" -Identity "DVRViewer"
Add-ADGroupMember -Members "BN Viewer" -Identity "ADAMViewer"
Add-ADGroupMember -Members "BN Ops" -Identity "DVROps"
Add-ADGroupMember -Members "BN Ops" -Identity "ADAMOps"
Set-AdfsWebApiApplication -TargetName "Bastille Admin - Web application" -AccessControlPolicyName "Permit specific group" -AccessControlPolicyParameters BNAdmin
Set-AdfsWebApiApplication -TargetName "Bastille DVR and Device - Web application" -AccessControlPolicyName "Permit specific group" -AccessControlPolicyParameters BNAdmin, DVROps, DVRViewer
Set-AdfsWebApiApplication -TargetName "Bastille Lighthouse - Web application" -AccessControlPolicyName "Permit specific group" -AccessControlPolicyParameters BNAdmin, ADAMOps, ADAMViewer
