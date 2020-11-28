
$fileURI = Get-AutomationVariable -Name 'fileURI'

# Download files required for this script from github ARMRunbookScripts/static folder
$FileNames = "AzureModules.zip"
$SplitFilenames = $FileNames.split(",")
foreach($Filename in $SplitFilenames){
Invoke-WebRequest -Uri "$fileURI/ARMRunbookScripts/static/$Filename" -OutFile "C:\$Filename"
}

#New-Item -Path "C:\msft-wvd-saas-offering" -ItemType directory -Force -ErrorAction SilentlyContinue
Expand-Archive "C:\AzureModules.zip" -DestinationPath 'C:\Modules\Global' -ErrorAction SilentlyContinue

#The name of the Automation Credential Asset this runbook will use to authenticate to Azure.
$AzCredentialsAsset = 'AzureCredentials'
$AzCredentials = Get-AutomationPSCredential -Name $AzCredentialsAsset
$AzCredentials.password.MakeReadOnly()


#Authenticate Azure
#Get the credential with the above name from the Automation Asset store
Connect-AzAccount -Environment 'AzureCloud' -Credential $AzCredentials
Connect-AzureAD -AzureEnvironmentName 'AzureCloud' -Credential $AzCredentials
$SubscriptionId = Get-AutomationVariable -Name 'subscriptionid'
Select-AzSubscription -SubscriptionId $SubscriptionId

# Install required Az modules
Import-Module Az.Accounts -Global
Import-Module Az.Resources -Global
Import-Module Az.Compute -Global

Get-AzureVMAvailableExtension "spaceMsix"
# Remove-AzureVMCustomScriptExtension -VM "spaceMsix"


