Param(
    $projectName,
    $projectLocation
 )
 

        ##    \ \_____
      ####### [==_____> Initialise Launcher >
        ##    /_/


Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force 

# dev mode
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Value "1" -Type Dword -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -Value "0" -Type Dword -Force


# manage folders
mkdir C:\MSIX
mkdir C:\MSIX\Apps
mkdir C:\MSIXprogram
$msixfolder = "C:\MSIX\"
$appfolder = ""


# spaceTools
$toolsURL = 'https://aka.ms/downloadazcopy-v10-windows'
$toolsZip = "spaceTools.zip"
Invoke-WebRequest -Uri $toolsURL -OutFile "$msixfolder$azCopyZip"

Expand-Archive -LiteralPath "C:\MSIX\spaceTools.zip" -DestinationPath $msixfolder -Force -Verbose
Set-Location -Path C:\MSIX\

# install MsixPackagingTool
Add-AppxPackage -Path $msixfolder'Microsoft.MsixPackagingTool_2020.1006.2137.Msix'


# certificat 

# New-SelfSignedCertificate -Type Custom -Subject "CN=Space" -KeyUsage DigitalSignature -FriendlyName "Space" -CertStoreLocation "Cert:\CurrentUser\my" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}") -NotAfter (Get-Date).AddMonths(242)
# $password = ConvertTo-SecureString -String space -Force -AsPlainText
# Set-Location Cert:\CurrentUser\my
# $certThmb = ( Get-ChildItem | Where-Object{$_.Subject -eq 'CN=Space'} ).Thumbprint
# Export-PfxCertificate -cert "Cert:\CurrentUser\my\$certThmb" -FilePath C:\MSIX\cert.pfx -Password $password

$goodcert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("C:\MSIX\cert.pfx","space")
$rootStore = Get-Item cert:\LocalMachine\Root
$rootStore.Open("ReadWrite")
$rootStore.Add($goodcert)
$rootStore.Close()


# Check Apps and cert
$appinfo = import-csv -path .\Apps\appArg.csv # $apps = Get-ChildItem -Path $appfolder -File | Where-Object {$_.Name -match 'exe$'}

if ($findcert = Get-ChildItem -Path $appfolder -File | Where-Object {$_.Name -match 'pfx$'})
    {
        $cert = $findcert.name
    }
else {
    {
        $cert = $msixfolder + 'cert\' + 'cert.pfx'
    }
}


# Create Packages

foreach ($appName in $appinfo.appName)
{
    # check format
    $format = $fullAppName.Split('.')[-1]
    $AppName = $fullAppName.Split('.')[0]
    # if ($AppName.length < 2) { add '00'}

    if ($format -eq 'exe')

    {
        $Length = $app.Length

        $json = '<?xml version="1.0"?>
        <MsixPackagingToolTemplate xmlns="http://schemas.microsoft.com/appx/msixpackagingtool/template/2018">
        <Settings AllowTelemetry="false" ApplyAllPrepareComputerFixes="false" GenerateCommandLineFile="true" AllowPromptForPassword="false" p4:EnforceMicrosoftStoreRequirements="false" p5:ServerPortNumber="1599" p6:AddPackageIntegrity="false" p7:SupportedWindowsVersionForMsixCore="None"
            xmlns:p7="http://schemas.microsoft.com/msix/msixpackagingtool/template/2004"
            xmlns:p6="http://schemas.microsoft.com/msix/msixpackagingtool/template/2001"
            xmlns:p5="http://schemas.microsoft.com/msix/msixpackagingtool/template/1904"
            xmlns:p4="http://schemas.microsoft.com/msix/msixpackagingtool/template/2007" />
        <PrepareComputer DisableWindowsSearchService="true" DisableWindowsUpdateService="true" />
        <SaveLocation PackagePath="' + $appfolder + $AppName + '.msix" TemplatePath="' + $msixfolder + $AppName + '.xml" />
        <Installer Path="' + $appfolder + $fullAppName + '" InstallLocation="C:\MSIXprogram" Arguments="' + $exearg + '" />
        <PackageInformation PackageName="' + $AppName + '" PackageDisplayName="' + $AppName + '" PublisherName="CN=Space" PublisherDisplayName="Space" Version="1.0.0.0" p4:PackageDescription="Space"
            xmlns:p4="http://schemas.microsoft.com/msix/msixpackagingtool/template/1910">
            <Capabilities>
            <Capability Name="runFullTrust" />
            </Capabilities>
        </PackageInformation>
        </MsixPackagingToolTemplate>'
        
        $jsonfile = [string]$AppName + ".xml"
        $json | out-file $msixfolder$jsonfile

        $xml = "$appfolder$AppName" + '.xml'
        $msix = "$appfolder$AppName" + '.msix'
        MsixPackagingTool.exe create-package --template $xml -v
        C:\MSIX\SignTool.exe sign /fd SHA256 /a /f $cert /p space $msix

        # if { $AppName + .msix < $AppName.length} 
        # $exearg = '/q'
        # return
    }
}



foreach 

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force  
.\Create-vhd.ps1 -WindowsVersion 2004 -Verbose

$vhdSrc="C:\space\vlc.vhd"
$packageName = "7z1900-x64_1.0.0.0_x64__kh9sn31mw6sx6" 
$parentFolder = "F:\vlc.msix"
$parentFolder = "\" + $parentFolder + "\"
$volumeGuid = "8e67f761-7035-4bd0-92b1-9849f056848f"
$msixJunction = "C:\space\" 