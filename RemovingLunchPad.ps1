

        ##    \ \_____
      ####### [==_____> Removing launch pad > 
        ##    /_/


$fileURI = Get-AutomationVariable -Name 'fileURI'
$ResourceGroupName = Get-AutomationVariable -Name 'ResourceGroupName'

# Download files required for this script from github ARMRunbookScripts/static folder
$FileNames = "AzureModules.zip"
$SplitFilenames = $FileNames.split(",")
foreach($Filename in $SplitFilenames){
Invoke-WebRequest -Uri "$fileURI/ARMRunbookScripts/static/$Filename" -OutFile "C:\$Filename"}

Expand-Archive "C:\AzureModules.zip" -DestinationPath 'C:\Modules\Global' -ErrorAction SilentlyContinue

#The name of the Automation Credential Asset this runbook will use to authenticate to Azure.
$AzCredentialsAsset = 'AzureCredentials'
$AzCredentials = Get-AutomationPSCredential -Name $AzCredentialsAsset
$AzCredentials.password.MakeReadOnly()

#Authenticate Azure
Connect-AzAccount -Environment 'AzureCloud' -Credential $AzCredentials
Connect-AzureAD -AzureEnvironmentName 'AzureCloud' -Credential $AzCredentials
$SubscriptionId = Get-AutomationVariable -Name 'subscriptionid'
Select-AzSubscription -SubscriptionId $SubscriptionId

# Install required Az modules
Import-Module Az.Compute -Global

Remove-AzVM -ResourceGroupName $ResourceGroupName -VMName spaceMsix