param(
    [string] $SubscriptionId,
    [string] $resourceGroupName,
    [string] $hostpoolName,
    [string] $storage,
    [string] $sharename,
    [string] $app1,
    [string] $app2,
    [string] $app3,
    [string] $app4,
    [string] $app5,
    [string] $app6,
    [string] $app7,
    [string] $app8
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


# Checking Apps
$applist = @($app1, $app2, $app3, $app4, $app5, $app6, $app7, $app8) | Where-Object { $_ -ne 'none' } 
Write-output $applist

$storageuser = $storage.split('.')[0]
$ctx = (Get-AzStorageAccount -ResourceGroupName $resourceGroupName -Name $storageuser).Context
$shareDir = Get-AZStorageFile -Context $ctx -ShareName $sharename
$deployedapps = ($shareDir | Where-Object { $_.name -like '*vhd' }).name
Write-Output $deployedapps


# Installing Remote MSIX Packages
foreach ( $app in $applist ) {
    write-output $app
    $appname = ($app.split(" ")[2]).split(".")[0]
    Write-Output $appname

    # App Name must have at least 3 chars
    $testlengh = $appname | Measure-Object -Character
    
    if ($testlengh.Characters -lt '3') {
        $appname = $app.split($separators)[2] + $app.split($separators)[3]
    }

    $vhdname = $appname + '.vhd'
    write-output $vhdname

    while ($deployedapps -notcontains $vhdname) { Start-sleep -s 15 } 

    $uncPath = '\\' + $storage + '\' + $sharename + '\' + $vhdname
    $obj = Expand-AzWvdMsixImage -HostPoolName $hostpoolName -ResourceGroupName $resourcegroupName -SubscriptionId $SubscriptionId -Uri $uncPath
    New-AzWvdMsixPackage -HostPoolName $hostpoolName -ResourceGroupName $resourcegroupName -SubscriptionId $SubscriptionId -PackageAlias $obj.PackageAlias -DisplayName $appname -ImagePath $uncPath -IsActive:$true
    Get-AzWvdMsixPackage -HostPoolName $hostpoolName -ResourceGroupName $resourcegroupName -SubscriptionId $SubscriptionId | Where-Object { $_.PackageFamilyName -eq $obj.PackageFamilyName }

    $appsIds = $null
    $appsIds = $shareDir | ? { $_.Name -eq 'appsIds.csv' } | Get-AzStorageFileContent
    $appId = $appsIds | ? { $_.appname -eq $appname }

    New-AzWvdApplication -ResourceGroupName $resourcegroupName `
        -GroupName 'Space-Apps' `
        -Name $appname `
        -IconIndex 0 `
        -CommandLineSetting 'Allow' `
        -ShowInPortal:$true `
        -MsixPackageApplicationId $appId.appId `
        -MsixPackageFamilyName "I never fly without my $appname"
        -ApplicationType 'MSIX'
}


# Shutdown Space Communication
# $VMs = (Get-AzVM -ResourceGroupName $resourcegroupName).name
ForEach ( $vm in $VMs) {

    Stop-AzVM -ErrorAction Stop -ResourceGroupName $resourcegroupName -Name $vm -Force

}
