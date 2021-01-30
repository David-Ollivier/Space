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

$SubscriptionId = "e9cd10be-26f3-4506-a930-63e53580065d"
$resourcegroupName = "wvdtest"
$hostpoolName = "Space-Pool"
$storage = "spaceshareg7zc.file.core.windows.net"
$sharename = "msix"
$app1 = "choco install vscode"
$app2 = "choco install paint.net"
$app3 = "none" 
$app4 = "none" 
$app5 = "none" 
$app6 = "none" 
$app7 = "none" 
$app8 = "none"

# $ErrorActionPreference = 'Stop'
Connect-AzAccount -Identity

# Import-module az.compute
# Import-module az.resources

if ($null -ne (get-module -name Az.DesktopVirtualization -ListAvailable -ErrorAction SilentlyContinue)) {
    Import-module -name Az.DesktopVirtualization
}
else {
    Install-module -name Az.DesktopVirtualization -force
}


# Checking Apps
$applist = @($app1, $app2, $app3, $app4, $app5, $app6, $app7, $app8) | Where-Object { $_ -ne 'none' } 
Write-output $applist

$storageuser = $storage.split('.')[0]
$ctx=(Get-AzStorageAccount -ResourceGroupName $resourceGroupName -Name $storageuser).Context
$deployedapps=Get-AZStorageFile -Context $ctx -ShareName $sharename
$deployedapps = $deployedapps.name


foreach ( $app in $applist )
{
    write-output $app
    $separators = (" ", ".")
    $appname = $app.split($separators)[2]
    Write-Output $appname

    # App Name must have at least 3 chars
    $testlengh = $appname | Measure-Object -Character
    
    if ($testlengh.Characters -lt '3') {
        $appname = $app.split($separators)[2] + $app.split($separators)[3]
    }

    $vhdname = $appname + '.vhd'
    write-output $vhdname

    while ($deployedapps -notcontains $vhdname) { Start-sleep -s 15 } 

    $uncPath = $fullstorage + '\' + $vhdname
    $obj = Expand-AzWvdMsixImage -HostPoolName $hostpoolName -ResourceGroupName $resourcegroupName -SubscriptionId $SubscriptionId -Uri $uncPath
    New-AzWvdMsixPackage -HostPoolName $hostpoolName -ResourceGroupName $resourcegroupName -SubscriptionId $SubscriptionId -PackageAlias $obj.PackageAlias -DisplayName $appname -ImagePath $uncPath -IsActive:$true
    Get-AzWvdMsixPackage -HostPoolName $hostpoolName -ResourceGroupName $resourcegroupName -SubscriptionId $SubscriptionId | Where-Object { $_.PackageFamilyName -eq $obj.PackageFamilyName }
}

Write-Output $resourcegroupName

# Shutdown Space Communication
$VMs = get-azvm -ResourceGroupName $resourcegroupName
$VMs.Name | ForEach-Object -ThrottleLimit 100 -Parallel {
        
    Stop-AzVM -ResourceGroupName $resourcegroupName -Name $_. -force

}

ForEach ( $vm in $VMs)
{
    Stop-AzVM -ErrorAction Stop -ResourceGroupName $resourcegroupName -Name $vm -Force

}
