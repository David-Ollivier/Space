param(
    [string] $SubscriptionId,
    [string] $resourceGroupName,
    [string] $hostpoolName,
    [string] $storage,
    [string] $sharename
)


# Getting Flying Modules
# $ErrorActionPreference = 'Stop'
Install-Module -Name Az.Accounts -AllowClobber -Force
Install-Module -Name Az.DesktopVirtualization -AllowClobber -Force
Install-Module -Name Az.Network -AllowClobber -Force
Install-Module -Name Az.Compute -AllowClobber -Force

@("Az.Accounts", "Az.DesktopVirtualization", "Az.Network", "Az.Compute") | % $_ { if (Get-Module -ListAvailable -Name $_) { update-module -name $_ -force } else { install-module -name $_ -skippublishercheck -force } }
Get-Command -Module Az.DesktopVirtualization | Where-Object { $_.Name -match "MSIX" }


# Connecting to the system
Connect-AzAccount -Identity
# Select-AzSubscription -SubscriptionId $SubscriptionId


# Creating Remoting Packages Container
New-AzWvdApplicationGroup -ResourceGroupName $resourcegroupName `
    -Name 'Space-Apps' `
    -Location 'eastus' `
    -FriendlyName 'Let the Space-Apps fly' `
    -HostPoolArmPath "/subscriptions/$SubscriptionId/resourcegroups/$resourcegroupName/providers/Microsoft.DesktopVirtualization/hostPools/$hostpoolName" `
    -ApplicationGroupType 'RemoteApp'


# Checking Apps Deployment Stat
$storageuser = $storage.split('.')[0]
$ctx = (Get-AzStorageAccount -ResourceGroupName $resourceGroupName -Name $storageuser).Context
$shareDir = Get-AZStorageFile -Context $ctx -ShareName $sharename

# Waiting spaceMsix to Finish Packaging Program
while ((Get-AZStorageFile -Context $ctx -ShareName $sharename).name -notcontains "appsIds.csv") 

{ 

Write-Output "Waiting for Apps.."
start-sleep 15 

}

($shareDir | Where-Object { $_.name -eq 'appsIds.csv' }) | Get-AzStorageFileContent
$applist = Import-Csv "appsIds.csv"
Write-Output $applist


# Installing Remote MSIX Packages
foreach ( $app in $applist ) {

    $appname = $app.app
    $vhdname = $appname + '.vhd'
    write-output $vhdname

    $uncPath = '\\' + $storage + '\' + $sharename + '\' + $vhdname
    $obj = Expand-AzWvdMsixImage -HostPoolName $hostpoolName -ResourceGroupName $resourcegroupName -SubscriptionId $SubscriptionId -Uri $uncPath
    New-AzWvdMsixPackage -HostPoolName $hostpoolName -ResourceGroupName $resourcegroupName -SubscriptionId $SubscriptionId -PackageAlias $obj.PackageAlias -DisplayName $appname -ImagePath $uncPath -IsActive:$true
    Get-AzWvdMsixPackage -HostPoolName $hostpoolName -ResourceGroupName $resourcegroupName -SubscriptionId $SubscriptionId | Where-Object { $_.PackageFamilyName -eq $obj.PackageFamilyName }


    New-AzWvdApplication -ResourceGroupName $resourcegroupName `
        -GroupName 'Space-Apps' `
        -Name $appname `
        -IconIndex 0 `
        -CommandLineSetting 'Allow' `
        -ShowInPortal:$true `
        -MsixPackageApplicationId $app.appId `
        -MsixPackageFamilyName "I never fly without my $appname"
        -ApplicationType 'MSIX'
}


# Shutdown Space Communication
$VMs = (Get-AzVM -ResourceGroupName $resourcegroupName).name
ForEach ( $vm in $VMs) {

    Stop-AzVM -ErrorAction Stop -ResourceGroupName $resourcegroupName -Name $vm -Force

}
