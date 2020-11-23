      
        ##    \ \_____
      ####### [==_____> Setup Space Domain Controller >
        ##    /_/

#Initializing variables from automation account
$SubscriptionId = Get-AutomationVariable -Name 'subscriptionid'
$ResourceGroupName = Get-AutomationVariable -Name 'ResourceGroupName'
$fileURI = Get-AutomationVariable -Name 'fileURI'
$principalId = Get-AutomationVariable -Name 'principalId'
$orgName = Get-AutomationVariable -Name 'orgName'
$projectName = Get-AutomationVariable -Name 'projectName'
$location = Get-AutomationVariable -Name 'location'
$adminUsername = Get-AutomationVariable -Name 'adminUsername'
# $domainName = Get-AutomationVariable -Name 'domainName'
$keyvaultName = Get-AutomationVariable -Name 'keyvaultName'
$wvdAssetsStorage = Get-AutomationVariable -Name 'assetsName'
$profilesStorageAccountName = Get-AutomationVariable -Name 'profilesName'
$ObjectId = Get-AutomationVariable -Name 'ObjectId'
$existingVnetName = Get-AutomationVariable -Name 'existingVnetName'
$existingSubnetName = Get-AutomationVariable -Name 'existingSubnetName'
$virtualNetworkResourceGroupName = Get-AutomationVariable -Name 'ResourceGroupName'
$targetGroup = Get-AutomationVariable -Name 'targetGroup'
$AutomationAccountName = Get-AutomationVariable -Name 'AccountName'
$identityApproach = Get-AutomationVariable -Name 'identityApproach'
$notificationEmail = Get-AutomationVariable -Name 'notificationEmail'

write-output "Starting 45 minutes of sleep to allow for domain to start running, which typically takes 30-40 minutes."
start-sleep -Seconds 2700

# Download files required for this script from github ARMRunbookScripts/static folder
$FileNames = "msft-wvd-saas-api.zip,msft-wvd-saas-web.zip,AzureModules.zip"
$SplitFilenames = $FileNames.split(",")
foreach($Filename in $SplitFilenames){
Invoke-WebRequest -Uri "$fileURI/ARMRunbookScripts/static/$Filename" -OutFile "C:\$Filename"
}

#New-Item -Path "C:\msft-wvd-saas-offering" -ItemType directory -Force -ErrorAction SilentlyContinue
Expand-Archive "C:\AzureModules.zip" -DestinationPath 'C:\Modules\Global' -ErrorAction SilentlyContinue

# Install required Az modules and AzureAD
Import-Module Az.Accounts -Global
Import-Module Az.Resources -Global
Import-Module Az.Websites -Global
Import-Module Az.Automation -Global
Import-Module Az.Managedserviceidentity -Global
Import-Module Az.Keyvault -Global
Import-Module Az.Compute -Global
Import-Module AzureAD -Global

Set-ExecutionPolicy -ExecutionPolicy Undefined -Scope Process -Force -Confirm:$false
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine -Force -Confirm:$false
Get-ExecutionPolicy -List


#The name of the Automation Credential Asset this runbook will use to authenticate to Azure.
$AzCredentialsAsset = 'AzureCredentials'
$AzCredentials = Get-AutomationPSCredential -Name $AzCredentialsAsset
$AzCredentials.password.MakeReadOnly()

#Authenticate Azure
#Get the credential with the above name from the Automation Asset store
Connect-AzAccount -Environment 'AzureCloud' -Credential $AzCredentials
Connect-AzureAD -AzureEnvironmentName 'AzureCloud' -Credential $AzCredentials
Select-AzSubscription -SubscriptionId $SubscriptionId

#Set vnet DNS settings to "custom"
$vnet = Get-AzVirtualNetwork -ResourceGroupName $virtualNetworkResourceGroupName -name $existingVnetName
$vnet.DhcpOptions.DnsServers = "10.0.0.4"
Set-AzVirtualNetwork -VirtualNetwork $vnet

# Create admin user for domain join
$PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AzCredentials.password)
$UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
$PasswordProfile.Password = $UnsecurePassword
$PasswordProfile.ForceChangePasswordNextLogin = $False
$domainName = $AzCredentials.userName
$domainName = $domainName.split('@')[1]
$domainJoinUPN = $adminUsername + '@' + $domainName

New-AzureADUser -DisplayName $adminUsername -PasswordProfile $PasswordProfile -UserPrincipalName $domainJoinUPN -AccountEnabled $true -MailNickName $adminUsername

$domainUser = Get-AzureADUser -Filter "UserPrincipalName eq '$($domainJoinUPN)'" | Select-Object ObjectId
# Fetch user to assign to role
$roleMember = Get-AzureADUser -ObjectId $domainUser.ObjectId

# Fetch User Account Administrator role instance
$role = Get-AzureADDirectoryRole | Where-Object {$_.displayName -eq 'Company Administrator'}
# If role instance does not exist, instantiate it based on the role template
if ($role -eq $null) {
    # Instantiate an instance of the role template
    $roleTemplate = Get-AzureADDirectoryRoleTemplate | Where-Object {$_.displayName -eq 'Company Administrator'}
    Enable-AzureADDirectoryRole -RoleTemplateId $roleTemplate.ObjectId
    # Fetch User Account Administrator role instance again
    $role = Get-AzureADDirectoryRole | Where-Object {$_.displayName -eq 'Company Administrator'}
}
# Add user to role
Add-AzureADDirectoryRoleMember -ObjectId $role.ObjectId -RefObjectId $roleMember.ObjectId
# Fetch role membership for role to confirm
Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId | Get-AzureADUser

# First, retrieve the object ID of the newly created 'AAD DC Administrators' group.
$GroupObjectId = Get-AzureADGroup -Filter "DisplayName eq 'AAD DC Administrators'" | Select-Object ObjectId

# Add the user to the 'AAD DC Administrators' group.
Add-AzureADGroupMember -ObjectId $GroupObjectId.ObjectId -RefObjectId $domainUser.ObjectId

# Get the context
$context = Get-AzContext
if ($context -eq $null)
{
	Write-Error "Please authenticate to Azure & Azure AD using Login-AzAccount and Connect-AzureAD cmdlets and then run this script"
	exit
}


# In case Azure AD DS is used, create a new user here, and assign it to the targetGroup. The principalID of this group will then be used.
if ($identityApproach -eq 'Azure AD DS') {
  $url = $($fileURI + "/Modules/ARM/UserCreation/Parameters/users.parameters.json")
  Invoke-WebRequest -Uri $url -OutFile "C:\users.parameters.json"
  $ConfigurationJson = Get-Content -Path "C:\users.parameters.json" -Raw -ErrorAction 'Stop'

  try { $UserConfig = $ConfigurationJson | ConvertFrom-Json -ErrorAction 'Stop' }
  catch {
    Write-Error "Configuration JSON content could not be converted to a PowerShell object" -ErrorAction 'Stop'
  }

  $userPassword = $orgName.substring(13) + '!'
  foreach ($config in $UserConfig.userconfig) {
    $userName = $config.userName
    $upn = $($userName + "@" + $domainName)
      if ($config.createGroup) { New-AzADGroup -DisplayName "$targetGroup" -MailNickname "$targetGroup" }
      if ($config.createUser) { New-AzADUser -UserPrincipalName $upn -DisplayName "$userName" -MailNickname $userName -Password (convertto-securestring $userPassword -AsPlainText -Force) }
      if ($config.assignUsers) { Add-AzADGroupMember -MemberUserPrincipalName  $upn -TargetGroupDisplayName $targetGroup }
      Start-Sleep -Seconds 1
  }
}

# In case of using AD, and ADSync didn't work in user creation, this block will allow for the regular sync cycle to sync the group to Azure instead
Write-Output "Fetching test user group $targetGroup. In case of using AD, this can take up to 30 minutes..."
$currentTry = 0
if ($identityApproach -eq "AD") {
  do {
      $principalIds = (Get-AzureADGroup -SearchString $targetGroup).objectId
      $currentTry++
      Start-Sleep -Seconds 10
  } while ($currentTry -le 180 -and ($principalIds -eq $null))
}

# In both AD and Azure AD DS case, the user group should now exist in Azure. Throw an error of the group is not found.
$principalIds = (Get-AzureADGroup -SearchString $targetGroup).objectId
if ($principalIds -eq $null) {
  Write-Error "Did not find user group $targetGroup. Please check if the user group creation completed successfully."
  throw "Did not find user group $targetGroup. Please check if the user group creation completed successfully."
}

# In case the above search finds multiple groups, pick the first PrincipalId. Template only works when one principalId is supplied, not for multiple.
$split = $principalIds.Split(' ')
$principalIds = $split[0]
Write-Output "Found user group $targetGroup with principal Id $principalIds"
