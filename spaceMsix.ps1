Param(
    $geturi,
    $share,
    $azureshare,
    $azureshareuser,
    $azuresharepass
)

        ##    \ \_____
      ####### [==_____> Space Application Containerization Program > 
        ##    /_/

& reg add HKLM\Software\Policies\Microsoft\WindowsStore /v AutoDownload /t REG_DWORD /d 0 /f
& Schtasks /Change /Tn "\Microsoft\Windows\WindowsUpdate\Automatic app update" /Disable
& Schtasks /Change /Tn "\Microsoft\Windows\WindowsUpdate\Scheduled Start" /Disable
& reg add HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v PreInstalledAppsEnabled /t REG_DWORD /d 0 /f
& reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Debug /v ContentDeliveryAllowedOverride /t REG_DWORD /d 0x2 /f
& Set-Content config wuauserv start=disabled


$share = "fslogix"
$azureshare = "stgeduwvdhostpool.file.core.windows.net"
$azureshareuser = "Azure\stgeduwvdhostpool"
$azuresharepass = "DsxzSTRkdECb98/qrApoTSlTqRlTZP9W65A/QkvtxjC1+k3BGWUwuUUKWWbY9uZ6joWo0gEXwf1dPrzN/anuIg=="


# Manage Space Shares & Folders
$spacefolder = "c:\space\"
new-item -path "c:\space\msix" -ItemType Directory
new-item -path "C:\space\vhd" -ItemType Directory

$fullazureshare = '\\' + $azureshare + '\' + $share
cmd.exe /C "cmdkey /add:$azureshare /user:$azureshareuser /pass:$azuresharepass"
New-PSDrive -Name Z -PSProvider FileSystem -Root $fullazureshare


# spaceTools
$toolsURL = 'https://spacevhd.blob.core.windows.net/rocket/spaceTools.zip'
$toolsZip = "spaceTools.zip"
Invoke-WebRequest -Uri $toolsURL -OutFile "$spacefolder$toolsZip"
Expand-Archive -LiteralPath "C:\space\spaceTools.zip" -DestinationPath $spacefolder -Force -Verbose


# Flying Certificate
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("C:\space\spaceTools\cert\cert.pfx","space")
$rootStore = Get-Item cert:\LocalMachine\Root
$rootStore.Open("ReadWrite")
$rootStore.Add($cert)
$rootStore.Close()


# Prepare Space Packets Managers
$DesktopAppInstallerURL = 'https://github.com/microsoft/winget-cli/releases/download/v0.2.2941-preview/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.appxbundle'
$DesktopAppInstaller = "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.appxbundle"
$DesktopAppInstallerPath =  "c:\space\spaceTools\" + $DesktopAppInstaller
Invoke-WebRequest -Uri $DesktopAppInstallerURL -OutFile $DesktopAppInstallerPath
set-location C:\space\spaceTools\msixmgr\
Add-AppxPackage "C:\space\spaceTools\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.appxbundle"
# Add-AppxPackage "c:\space\spaceTools\Microsoft.VCLibs.140.00_14.0.29231.0.Appx"
# Add-AppxPackage "c:\space\spaceTools\Microsoft.VCLibs.140.00.UWPDesktop_14.0.29231.0.Appx"
# Add-AppxPackage "c:\space\spaceTools\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.appxbundle"
Add-AppxPackage "c:\space\spaceTools\Microsoft.MsixPackagingTool_2020.1006.2137.Msix"
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
choco feature enable -n allowGlobalConfirmation
choco feature disable -n checksumFiles


# Getting Space Apps
$applisturi = 'https://spacevhd.blob.core.windows.net/rocket/applist.csv'
Invoke-WebRequest -Uri $applisturi -OutFile C:\space\msix\applist.csv



        ##    \ \_____
      ####### [==_____> Space MSIX > 
        ##    /_/


Set-Location -Path "c:\space\msix"
$applist = import-csv applist.csv
foreach($geturi in $applist.apps)
{
    $separators = (" ",".")
    $appname = $geturi.split($separators)[2]

    '<MsixPackagingToolTemplate
    xmlns="http://schemas.microsoft.com/appx/msixpackagingtool/template/2018"
    xmlns:mptv2="http://schemas.microsoft.com/msix/msixpackagingtool/template/1904">
    <Installer Path="C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" Arguments="' + $geturi + '"/>
    <SaveLocation PackagePath="C:\space\msix"/>
    <PackageInformation
    PackageName="' + $appname + '"
    PackageDisplayName="' + $appname + '"
    PublisherName="CN=Space"
    PublisherDisplayName="' + $appname + '"
    Version="1.0.0.0">
    </PackageInformation>
    </MsixPackagingToolTemplate>' > manifest.xml

    MsixPackagingTool.exe create-package --template manifest.xml -v
}


# Signing Space MSIX Containers
$allmsix = Get-ChildItem -Path C:\space\msix -Filter *.msix | Select-object -ExpandProperty Name 
foreach($msixName in $allmsix)
{
    $pfxFilePath = "C:\space\spaceTools\cert\cert.pfx"
    $msixPath = "C:\space\msix\" + $msixName
    & "C:\space\spaceTools\signtool.exe" sign /f $pfxFilePath /t http://timestamp.globalsign.com/scripts/timstamp.dll /p space /fd SHA256 $msixPath


# Create Space App Attach
    $parentFolder = $msixName.split('_')[0]
    $vhdName = $parentFolder + '.vhd'

# Create vhd
    New-VHD -SizeBytes 1000MB -Path C:\space\vhd\$vhdName -Dynamic -Confirm:$false
    $vhdObject = Mount-DiskImage C:\space\vhd\$vhdName -Passthru
    $disk = Initialize-Disk -Passthru -Number $vhdObject.Number
    $partition = New-Partition -AssignDriveLetter -UseMaximumSize -DiskNumber $disk.Number
    Format-Volume -FileSystem NTFS -Confirm:$false -DriveLetter $partition.DriveLetter -Force

# Transfering data
    $driveletter = $partition.DriveLetter
    $fullvhdappfolder = $driveletter + ':\' + $parentFolder
    mkdir $fullvhdappfolder

    set-location C:\space\spaceTools\msixmgr
    .\msixmgr.exe -Unpack -packagePath C:\space\msix\$msixName -destination $fullvhdappfolder -applyacls

# Gettings vhd's informations
    $vhdSrc="C:\space\vhd\$vhdName"
    $packageName = (Get-ChildItem -path $fullvhdappfolder).name
    $parentFolder = "\" + $parentFolder + "\"
    $volumeGuid = (((get-volume -DriveLetter $driveletter).UniqueId).split('{')[1]).split('}')[0]

    Dismount-DiskImage -Imagepath $vhdSrc
    xcopy.exe C:\space\vhd\$vhdName $fullazureshare

    New-Object -TypeName PSCustomObject -Property @{
        vhdSrc = $vhdSrc
        packageName = $packageName
        parentFolder = $parentFolder
        volumeGuid = $volumeGuid
        msixJunction = "C:\Program Files\SpaceApps"
        } | Export-Csv -Path C:\space\vhd\vhdInfo.csv -NoTypeInformation -Append
}

xcopy.exe C:\space\vhd\vhdInfo.csv $fullazureshare
