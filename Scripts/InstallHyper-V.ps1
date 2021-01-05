
        ##    \ \_____
      ####### [==_____> Install Hyper-Virtualization Program > 
        ##    /_/


$fileURI = Get-AutomationVariable -Name 'fileURI'
$ResourceGroupName = Get-AutomationVariable -Name 'ResourceGroupName'
        

# Download files required for this script from github ARMRunbookScripts/static folder
$FileName = "AzureModules.zip"
Invoke-WebRequest -Uri "$fileURI/ARMRunbookScripts/static/$Filename" -OutFile "C:\$Filename"

#New-Item -Path "C:\msft-wvd-saas-offering" -ItemType directory -Force -ErrorAction SilentlyContinue
Expand-Archive "C:\AzureModules.zip" -DestinationPath 'C:\Modules\Global' -ErrorAction SilentlyContinue

#The name of the Automation Credential Asset this runbook will use to authenticate to Azure.
$AzCredentialsAsset = 'AzureCredentials'
$AzCredentials = Get-AutomationPSCredential -Name $AzCredentialsAsset
$AzCredentials.password.MakeReadOnly()

#Authenticate Azure
#Get the credential with the above name from the Automation Asset store
Connect-AzAccount -Environment 'AzureCloud' -Credential $AzCredentials
$SubscriptionId = Get-AutomationVariable -Name 'subscriptionid'
Select-AzSubscription -SubscriptionId $SubscriptionId
        
# Install required Az modules
Import-Module Az.Accounts -Global
Import-Module Az.Resources -Global
Import-Module Az.Compute -Global
        
$ps1 = @"
DISM /Online /Enable-Feature /All /FeatureName:Microsoft-Hyper-V /NoRestart
Restart-Computer -Force
"@ > "c:\hyper-v.ps1"

Invoke-AzureRmVMRunCommand `
        -CommandId "InstallHyper-V" `
        -ResourceGroupName 'ResourceGroupName' `
        -VMName "spaceMsix" `
        -ScriptPath "c:\hyper-v.ps1"

