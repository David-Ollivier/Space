
$SubscriptionId = Get-AutomationVariable -Name 'subscriptionid'

#The name of the Automation Credential Asset this runbook will use to authenticate to Azure.
$AzCredentialsAsset = 'AzureCredentials'
$AzCredentials = Get-AutomationPSCredential -Name $AzCredentialsAsset
$AzCredentials.password.MakeReadOnly()

#Authenticate Azure
#Get the credential with the above name from the Automation Asset store
Connect-AzAccount -Environment 'AzureCloud' -Credential $AzCredentials
Connect-AzureAD -AzureEnvironmentName 'AzureCloud' -Credential $AzCredentials
Select-AzSubscription -SubscriptionId $SubscriptionId

# Install required Az modules
Import-Module Az.Accounts -Global
Import-Module Az.Resources -Global
Import-Module Az.Compute -Global

Get-AzureVMAvailableExtension -VM "spaceMsix"
Remove-AzureVMCustomScriptExtension -VM "spaceMsix"


