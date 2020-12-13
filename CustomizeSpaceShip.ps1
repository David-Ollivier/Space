param(
    $storage,
    $storagepass
)


New-Item -Path C:\ -Name Reports -ItemType Directory -ErrorAction SilentlyContinue
Start-Transcript -path c:\Reports\Retranscriptions.txt



        ##    \ \_____
      ####### [==_____> Bypass Security Verification Controls >
        ##    /_/

 
$ErrorActionPreference = 'silentlycontinue'
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force 
Set-MpPreference -DisableRealtimeMonitoring $true



        ##    \ \_____
      ####### [==_____> Install Flying Super Logix Cosmonaut Data Containerization Program >
        ##    /_/


$client = New-Object System.Net.WebClient
$url = "https://aka.ms/fslogix_download"
$client.DownloadFile($url, "$PSScriptRoot\fslogix.zip")

Expand-Archive -LiteralPath "$PSScriptRoot\fslogix.zip" -DestinationPath $PSScriptRoot\fslogix
Start-Process -FilePath "$PSScriptRoot\fslogix\x64\Release\FSLogixAppsSetup.exe" -ArgumentList ("/install /quiet /norestart") -Wait

REG ADD "HKLM\SOFTWARE\FSlogix\Profiles" /f
REG ADD "HKLM\SOFTWARE\FSlogix\Profiles" /v AccessNetworkAsComputerObject /T REG_DWORD /D 1 /f
REG ADD "HKLM\SOFTWARE\FSlogix\Profiles" /v Enabled /T REG_DWORD /D 1 /f
REG ADD "HKLM\SOFTWARE\FSlogix\Profiles" /v DeleteLocalProfileWhenVHDShouldApply /T REG_DWORD /D 1 /f
REG ADD "HKLM\SOFTWARE\FSlogix\Profiles" /v FlipFlopProfileDirectoryName /T REG_DWORD /D 1 /f
REG ADD "HKLM\SOFTWARE\FSlogix\Profiles" /v SizeInMBs /T REG_DWORD /D 30000 /f
REG ADD "HKLM\SOFTWARE\FSlogix\Profiles" /v IsDynamic /T REG_DWORD /D 1 /f
REG ADD "HKLM\SOFTWARE\FSlogix\Profiles" /v VolumeType /T REG_SZ /D "vhdx" /f
REG ADD "HKLM\SOFTWARE\FSLogix\Logging" /v LogFileKeepingPeriod /T REG_DWORD /D 7 /f
REG ADD "HKLM\SOFTWARE\FSlogix\Profiles" /v VHDLocations /T REG_MULTI_SZ /D \\$storage\fslogix\%username%\VHD /f




        ##    \ \_____
      ####### [==_____> Install Space Share Data Translation >
        ##    /_/


New-Item -Path C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup\ -ItemType Directory -Force
$storageuser = $storage.split('.')[0]
$storagescript = "cmdkey /add:$storage /user:Azure\$storageuser /pass:$storagepass"
Set-Content C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup\mountspaceshare.ps1 $storagescript

New-Item -Path C:\Windows\System32\GroupPolicy\User\Scripts\Logon\ -ItemType Directory -Force
$storageapp = $storage.split('.')[0]
$storagescript = "cmdkey /add:$storage /user:Azure\$storageapp /pass:$storagepass"
Set-Content C:\Windows\System32\GroupPolicy\User\Scripts\Logon\mountspaceshare.ps1 $storagescript




        ##    \ \_____
      ####### [==_____> Space MSIX Program Initialization >
        ##    /_/


$TaskAction1 = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup\AppAttach.ps1 -ConfigFile \\$storage\msix\AppAttach.json -Mode VmStart"
$TaskTrigger = New-ScheduledTaskTrigger -AtStartup
$TaskPrincipal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -Action $TaskAction1 -Trigger $TaskTrigger -Principal $TaskPrincipal -TaskName "AppAttachProgram"


$client = New-Object System.Net.WebClient
$url = "https://download.sysinternals.com/files/PSTools.zip"
$client.DownloadFile($url, "$PSScriptRoot\PSTools.zip")
Expand-Archive -LiteralPath "$PSScriptRoot\PSTools.zip" -DestinationPath "C:\Windows\System32"

$client = New-Object System.Net.WebClient
$url = "https://raw.githubusercontent.com/SpaceWVD/Space/master/AppAttach.ps1"
$client.DownloadFile($url, "C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup\AppAttach.ps1")

$client = New-Object System.Net.WebClient
$url = "https://raw.githubusercontent.com/SpaceWVD/Space/master/AppAttachVmStart.ps1"
$client.DownloadFile($url, "C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup\AppAttachVmStart.ps1")


$psscriptsmachine = @"
 
[Shutdown]
0CmdLine=C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup\AppAttach.ps1
0Parameters=-ConfigFile \\$storage\fslogix\msix\AppAttach.json -Mode VmShutdown
[Startup]
0CmdLine=C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup\mountspaceshare.ps1
0Parameters=
"@
$psscriptsmachine | Out-file C:\Windows\System32\GroupPolicy\Machine\Scripts\psscripts.ini -Force


$psscriptsuser = @"
 
[Logoff]
0CmdLine=C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup\AppAttach.ps1
0Parameters=-ConfigFile \\$storage\fslogix\msix\AppAttach.json -Mode UserLoff
[Logon]
0CmdLine=C:\Windows\System32\GroupPolicy\User\Scripts\Logon\mountspaceshare.ps1
0Parameters=
1CmdLine=C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup\AppAttach.ps1
1Parameters=-ConfigFile \\$storage\fslogix\msix\AppAttach.json -Mode UserLogon
"@
$psscriptsuser | Out-file C:\Windows\System32\GroupPolicy\User\Scripts\psscripts.ini -Force

$gpt = @"
[General]
gPCMachineExtensionNames=[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{DF3DC19F-F72C-4030-940E-4C2A65A6B612}][{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]
Version=327692
gPCUserExtensionNames=[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{DF3DC19F-F72C-4030-940E-4C2A65A6B612}][{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B66650-4972-11D1-A7CA-0000F87571E3}]
"@ 

$gpt | Out-file C:\Windows\System32\GroupPolicy\GPT.INI -Force


reg load HKU\TempDefault C:\Users\Default\NTUSER.DAT
$storage="stgeduwvdhostpool.file.core.windows.net"
$appreg = @"
Windows Registry Editor Version 5.00
 
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup]
 
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0]
"GPO-ID"="LocalGPO"
"SOM-ID"="Local"
"FileSysPath"="C:\\Windows\\System32\\GroupPolicy\\Machine"
"DisplayName"="AppAttach Startup"
"GPOName"="AppAttach Startup"
"PSScriptOrder"=dword:00000001
 
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\0]
"Script"="C:\\Windows\\System32\\GroupPolicy\\Machine\\Scripts\\Startup\\mountspaceshare.ps1"
"Parameters"=""
"IsPowershell"=dword:00000001
"ExecTime"=hex(b):00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
 
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\1]
"Script"="C:\\Windows\\System32\\GroupPolicy\\Machine\\Scripts\\Startup\\AppAttach.ps1"
"Parameters"="-ConfigFile \\\\$storage\\msix\\AppAttach.json -Mode VmStart"
"IsPowershell"=dword:00000001
"ExecTime"=hex(b):00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
 
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup]
 
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0]
"GPO-ID"="LocalGPO"
"SOM-ID"="Local"
"FileSysPath"="C:\\Windows\\System32\\GroupPolicy\\Machine"
"DisplayName"="AppAttach Startup"
"GPOName"="AppAttach Startup"
"PSScriptOrder"=dword:00000001
 
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0\0]
"Script"="C:\\Windows\\System32\\GroupPolicy\\Machine\\Scripts\\Startup\\mountspaceshare.ps1"
"Parameters"=""
"ExecTime"=hex(b):00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
 
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown]
 
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown\0]
"GPO-ID"="LocalGPO"
"SOM-ID"="Local"
"FileSysPath"="C:\\Windows\\System32\\GroupPolicy\\Machine"
"DisplayName"="AppAttach Shutdown"
"GPOName"="AppAttach Shutdown"
"PSScriptOrder"=dword:00000001
 
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown\0\0]
"Script"="C:\\Windows\\System32\\GroupPolicy\\Machine\\Scripts\\Shutdown\\AppAttach.ps1"
"Parameters"="-ConfigFile \\\\$storage\\msix\\AppAttach.json -Mode VmShutdown"
"IsPowershell"=dword:00000001
"ExecTime"=hex(b):00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
 
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Shutdown]
 
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Shutdown\0]
"GPO-ID"="LocalGPO"
"SOM-ID"="Local"
"FileSysPath"="C:\\Windows\\System32\\GroupPolicy\\Machine"
"DisplayName"="AppAttach Shutdown"
"GPOName"="AppAttach Shutdown"
"PSScriptOrder"=dword:00000001
 
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Shutdown\0\0]
"Script"="C:\\Windows\\System32\\GroupPolicy\\Machine\\Scripts\\Shutdown\\AppAttach.ps1"
"Parameters"="-ConfigFile \\\\$storage\\msix\\AppAttach.json -Mode VmShutdown"
"ExecTime"=hex(b):00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
 
[HKU\TempDefault\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon]
 
[HKU\TempDefault\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon\0]
"GPO-ID"="LocalGPO"
"SOM-ID"="Local"
"FileSysPath"="C:\\Windows\\System32\\GroupPolicy\\User"
"DisplayName"="AppAttach User Startup"
"GPOName"="AppAttach User Startup"
"PSScriptOrder"=dword:00000001
 
[HKU\TempDefault\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon\0\0]
"Script"="C:\\Windows\\System32\\GroupPolicy\\User\\Scripts\\Startup\\AppAttach.ps1"
"Parameters"="-ConfigFile \\\\$storage\\msix\\AppAttach.json -Mode UserLogon"
"IsPowershell"=dword:00000001
"ExecTime"=hex(b):00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
 
[HKU\TempDefault\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff]
 
[HKU\TempDefault\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff\0]
"GPO-ID"="LocalGPO"
"SOM-ID"="Local"
"FileSysPath"="C:\\Windows\\System32\\GroupPolicy\\User"
"DisplayName"="AppAttach User Shutdown"
"GPOName"="AppAttach User Shutdown"
"PSScriptOrder"=dword:00000001
 
[HKU\TempDefault\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff\0\0]
"Script"="C:\\Windows\\System32\\GroupPolicy\\User\\Scripts\\Startup\\AppAttach.ps1"
"Parameters"="-ConfigFile \\\\$storage\\msix\\AppAttach.json -Mode UserLogoff"
"IsPowershell"=dword:00000001
"ExecTime"=hex(b):00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00

"@
New-Item -Path c:\temp -ItemType Directory -Force
$appreg | Out-file c:\temp\AppAttach.reg -Force
reg import c:\temp\AppAttach.reg



        ##    \ \_____
      ####### [==_____> Install International Space Program >
        ##    /_/

# if ($language -ne "en-us")
# {
#     $fullazureshare = '\\' + $storage + '\' + "msix"
#     cmd.exe /C "cmdkey /add:$storage /user:Azure\$storageuser /pass:$storagepass"
#     New-PSDrive -Name Z -PSProvider FileSystem -Root $fullazureshare

#     [string]$LIPContent = "z:\language\"
#     Set-Location $LIPContent
#     Get-ChildItem -path .\

#     Foreach ($cab in $languagepack)
#     {
#         Add-WindowsPackage -Online -PackagePath $_.name
#     }

#     $LanguageExperiencePack = "$LIPContent\ExperiencePack\LanguageExperiencePack." + $language + ".Neutral.appx -LicensePath $LIPContent\ExperiencePack\License.xml"
#     Add-AppProvisionedPackage -Online -PackagePath $LanguageExperiencePack
#     $LanguageList = Get-WinUserLanguageList
#     $LanguageList.Add("$language")
#     Set-WinUserLanguageList $LanguageList -force
#     Remove-Item "z:\language" -Recurse -force
# }



        ##    \ \_____
      ####### [==_____> Office Compatibility Program Initialization >
        ##    /_/

  

reg add "HKU\TempDefault\SOFTWARE\Policies\Microsoft\office\16.0\common" /v InsiderSlabBehavior /t REG_DWORD /d 2 /f
reg add "HKU\TempDefault\software\policies\microsoft\office\16.0\outlook\cached mode" /v enable /t REG_DWORD /d 1 /f
reg add "HKU\TempDefault\software\policies\microsoft\office\16.0\outlook\cached mode" /v syncwindowsetting /t REG_DWORD /d 1 /f
reg add "HKU\TempDefault\software\policies\microsoft\office\16.0\outlook\cached mode" /v CalendarSyncWindowSetting /t REG_DWORD /d 1 /f
reg add "HKU\TempDefault\software\policies\microsoft\office\16.0\outlook\cached mode" /v CalendarSyncWindowSettingMonths  /t REG_DWORD /d 1 /f
reg add "HKU\TempDefault\software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 01 /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate" /v hideupdatenotifications /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate" /v hideenabledisableupdates /t REG_DWORD /d 1 /f



        ##    \ \_____
      ####### [==_____> Bypass Windows Defender >
        ##    /_/

 
Add-MpPreference -ExclusionPath "%ProgramFiles%\FSLogix\Apps\frxccd.exe"
Add-MpPreference -ExclusionPath "%ProgramFiles%\FSLogix\Apps\frxccds.exe"
Add-MpPreference -ExclusionPath "%ProgramFiles%\FSLogix\Apps\frxsvc.exe"
Add-MpPreference -ExclusionExtension "%ProgramFiles%\FSLogix\Apps\frxdrv.sys"
Add-MpPreference -ExclusionExtension "%ProgramFiles%\FSLogix\Apps\frxdrvvt.sys"
Add-MpPreference -ExclusionExtension "%ProgramFiles%\FSLogix\Apps\frxccd.sys"
Add-MpPreference -ExclusionExtension "%TEMP%*.VHDX"
Add-MpPreference -ExclusionExtension "%Windir%\TEMP*.VHDX"
Add-MpPreference -ExclusionExtension "\\$storage\fslogix\*.VHDX"




        ##    \ \_____
      ####### [==_____> Micro Soft Flying Recommandations >
        ##    /_/


$NoPDF = "HKCR:\.pdf"
$NoProgids = "HKCR:\.pdf\OpenWithProgids"
$NoWithList = "HKCR:\.pdf\OpenWithList" 
If (!(Get-ItemProperty $NoPDF  NoOpenWith)) {
    New-ItemProperty $NoPDF NoOpenWith 
}        
If (!(Get-ItemProperty $NoPDF  NoStaticDefaultVerb)) {
    New-ItemProperty $NoPDF  NoStaticDefaultVerb 
}        
If (!(Get-ItemProperty $NoProgids  NoOpenWith)) {
    New-ItemProperty $NoProgids  NoOpenWith 
}        
If (!(Get-ItemProperty $NoProgids  NoStaticDefaultVerb)) {
    New-ItemProperty $NoProgids  NoStaticDefaultVerb 
}        
If (!(Get-ItemProperty $NoWithList  NoOpenWith)) {
    New-ItemProperty $NoWithList  NoOpenWith
}        
If (!(Get-ItemProperty $NoWithList  NoStaticDefaultVerb)) {
    New-ItemProperty $NoWithList  NoStaticDefaultVerb 
}
        
$Edge = "HKCR:\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_"
If (Test-Path $Edge) {
    Set-Item $Edge AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_ 
}
Write-Host "Disabling Background application access..."
Get-ChildItem -Path "HKU\TempDefault\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude "Microsoft.Windows.Cortana*" | ForEach-Object {
  Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1
  Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1
}

  Write-Host "Disabling Cortana..."
If (!(Test-Path "HKU\TempDefault\SOFTWARE\Microsoft\Personalization\Settings")) {
  New-Item -Path "HKU\TempDefault\SOFTWARE\Microsoft\Personalization\Settings" -Force
}
Set-ItemProperty -Path "HKU\TempDefault\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
If (!(Test-Path "HKU\TempDefault\SOFTWARE\Microsoft\InputPersonalization")) {
  New-Item -Path "HKU\TempDefault\SOFTWARE\Microsoft\InputPersonalization" -Force
}
Set-ItemProperty -Path "HKU\TempDefault\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
Set-ItemProperty -Path "HKU\TempDefault\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
If (!(Test-Path "HKU\TempDefault\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
  New-Item -Path "HKU\TempDefault\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force
}
Set-ItemProperty -Path "HKU\TempDefault\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
  New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
Set-ItemProperty -Path "HKU\TempDefault\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name AppsUseLightTheme -Value 0

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "MaxDisconnectionTime" /t "REG_DWORD" /d 300000 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "MaxIdleTime" /t "REG_DWORD" /d 300000 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" /v "ShutdownReasonOn" /t "REG_DWORD" /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" /v "ShutdownReasonUI" /t "REG_DWORD" /d 0 /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDrives /t "REG_DWORD" /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEnableTimeZoneRedirection /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 3 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MaxMonitors /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MaxXResolution /t REG_DWORD /d 5120 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MaxYResolution /t REG_DWORD /d 2880 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs" /v MaxMonitors /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs" /v MaxXResolution /t REG_DWORD /d 5120 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs" /v MaxYResolution /t REG_DWORD /d 2880 /f
reg unload HKU\TempDefault



        ##    \ \_____
      ####### [==_____> Install Multilanguage Impute Keyboards Layout >
        ##    /_/


New-Item -Path C:\ -Name appleKeyboard -ItemType Directory -ErrorAction SilentlyContinue
$Localfolder = "c:\appleKeyboard\"
$appleURL = 'https://github.com/Altux/azure-devtestlab/blob/master/Artifacts/windows-AppleKeyboardLayout/AppleKeyboard.zip'
$applezip = "AppleKeyboard.zip"
Invoke-WebRequest -Uri $appleURL -OutFile "$Localfolder$applezip"
Add-Type -AssemblyName System.IO.Compression.FileSystem
function unzip {
	param( [string]$ziparchive, [string]$extractpath )
	[System.IO.Compression.ZipFile]::ExtractToDirectory( $ziparchive, $extractpath )
}

unzip "C:\appleKeyboard\AppleKeyboard.zip" "C:\windows\system32"

Write-output "Merging Registry entry for the keyboards Layouts..."
$keyreg = @"
Windows Registry Editor Version 5.00
 
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layouts]
 
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\a0000405]
"Layout Text"="Czech (Apple)"
"Layout File"="CzechA.dll"
"Layout Id"="00d4"
"Layout Component ID"="0C8DA389245B4792B4960E336F62AC3E"
 
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\a0000406]
"Layout Text"="Danish (Apple)"
"Layout File"="DanishA.dll"
"Layout Id"="00cc"
"Layout Component ID"="C3996498F423440FB9CE2732A821E7D9"
 
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\a0000407]
"Layout Text"="German (Apple)"
"Layout File"="GermanA.dll"
"Layout Id"="00c3"
"Layout Component ID"="B616E2191BF048D4A554E5C6BE224AB4"
 
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\a0000409]
"Layout Text"="United States (Apple)"
"Layout File"="USA.dll"
"Layout Id"="00d1"
"Layout Component ID"="B422390FE3C04f3a917D15AD1ACD710F"
 
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\a000040a]
"Layout Text"="Spanish (Apple)"
"Layout File"="SpanishA.dll"
"Layout Id"="00c5"
"Layout Component ID"="C3364C7C44BC444A88A50459135D35B5"
 
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\a000040b]
"Layout Text"="Finnish (Apple)"
"Layout File"="FinnishA.dll"
"Layout Id"="00cb"
"Layout Component ID"="ECE9937799D242F5AE0CAA446EDEDC62"
 
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\a000040c]
"Layout Text"="French (Apple)"
"Layout File"="FrenchA.dll"
"Layout Id"="00c2"
"Layout Component ID"="2ECD3C77364749B18E910F9196B420FA"
 
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\a000040e]
"Layout Text"="Hungarian (Apple)"
"Layout File"="HungaryA.dll"
"Layout Id"="00d5"
"Layout Component ID"="725BE97D2AD14042BA539D96030F93AA"
 
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\a0000410]
"Layout Text"="Italian (Apple)"
"Layout File"="ItalianA.dll"
"Layout Id"="00c4"
"Layout Component ID"="6401AAA6058F431181B445C26BEF22D9"
 
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\a0000413]
"Layout Text"="Dutch (Apple)"
"Layout File"="DutchA.dll"
"Layout Id"="00c1"
"Layout Component ID"="3844B95343FB43D68E9695D6E88F016E"
 
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\a0000414]
"Layout Text"="Norwegian (Apple)"
"Layout File"="NorwayA.dll"
"Layout Id"="00c9"
"Layout Component ID"="74BE397ABD8143E4960D38111394D1A3"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\a0000415]
"Layout Text"="Polish (Apple)"
"Layout File"="PolishA.dll"
"Layout Id"="00cf"
"Layout Component ID"="D3D2841618E34D09ABBCA0DA34A60FAE"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\a0000416]
"Layout Text"="Portuguese (Apple)"
"Layout File"="PortuguA.dll"
"Layout Id"="00ce"
"Layout Component ID"="326773935C8C4597B0738FE2084D44AD"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\a0000419]
"Layout Text"="Russian (Apple)"
"Layout File"="RussianA.dll"
"Layout Id"="00c8"
"Layout Component ID"="B0F62A69BE9446488ED502E800DBC36C"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\a000041d]
"Layout Text"="Swedish (Apple)"
"Layout File"="SwedishA.dll"
"Layout Id"="00c7"
"Layout Component ID"="8CC8067A1BFF4A0FAD38708DE4CD4BF1"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\a000041f]
"Layout Text"="Turkish Q (Apple)"
"Layout File"="TurkeyQA.dll"
"Layout Id"="00d3"
"Layout Component ID"="2513D09A670B4d9bA8F1BDAAAA32176F"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\a0000809]
"Layout Text"="United Kingdom (Apple)"
"Layout File"="BritishA.dll"
"Layout Id"="00c0"
"Layout Component ID"="1A4D378083AD454BB4FE02F208614EB6"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\a0000813]
"Layout Text"="Belgian (Apple)"
"Layout File"="BelgiumA.dll"
"Layout Id"="00cd"
"Layout Component ID"="D70C1682E8F24ED4B5B70AAD37B1BA42"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\a0000c0c]
"Layout Text"="Canadian Multilingual (Apple)"
"Layout File"="CanadaA.dll"
"Layout Id"="00ca"
"Layout Component ID"="517A729DDEC543E3A7F392E3F130C25F"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\a000100c]
"Layout Text"="Swiss (Apple)"
"Layout File"="SwissA.dll"
"Layout Id"="00c6"
"Layout Component ID"="CE4C7E2419DE400B8A553E1A5C3DCD04"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\a0020409]
"Layout Text"="United States-International (Apple)"
"Layout File"="IntlEngA.dll"
"Layout Id"="00d0"
"Layout Component ID"="241A34D0-06DB-405e-8B4E-8CA2FC34D1C7"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\a100041f]
"Layout Text"="Turkish F (Apple)"
"Layout File"="TurkeyA.dll"
"Layout Id"="00d2"
"Layout Component ID"="D1502D2EF02F4e4b8D313D3C0B0457D0"

"@

$keyreg | Out-file c:\appleKeyboard\AppleKeyboard.reg
regedit /s c:\appleKeyboard\AppleKeyboard.reg



        ##    \ \_____
      ####### [==_____> Updating SpaceShip System Program >
        ##    /_/



Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Set-PSRepository -InstallationPolicy Trusted -Name PSGallery
Install-module -Name PSWindowsUpdate -Force
Import-module -Name PSWindowsUpdate
Get-WUInstall -MicrosoftUpdate -AcceptAll -Install -IgnoreUserInput -IgnoreReboot
Get-WUInstall -MicrosoftUpdate -AcceptAll -Install -IgnoreUserInput -IgnoreReboot



        ##    \ \_____
      ####### [==_____> Communication Latency Optimizer Program >
        ##    /_/

 
New-Item -Path C:\ -Name Optimize -ItemType Directory -ErrorAction SilentlyContinue
$LocalPath = "C:\Optimize\"
$WVDOptimizeURL = 'https://github.com/The-Virtual-Desktop-Team/Virtual-Desktop-Optimization-Tool/archive/master.zip'
$WVDOptimizeInstaller = "Windows_10_VDI_Optimize-master.zip"
Invoke-WebRequest -Uri $WVDOptimizeURL -OutFile "$Localpath$WVDOptimizeInstaller"
Expand-Archive -LiteralPath "C:\Optimize\Windows_10_VDI_Optimize-master.zip" -DestinationPath "$Localpath" -Force
$TaskAction2 = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File C:\Optimize\Virtual-Desktop-Optimization-Tool-master\Win10_VirtualDesktop_Optimize.ps1 -WindowsVersion 2004 -WindowsMediaPlayer -AppxPackages -ScheduledTasks -DefaultUserSettings -Autologgers -Services -NetworkOptimizations -DiskCleanup"
$TaskTrigger2 = New-ScheduledTaskTrigger -AtStartup
$TaskPrincipa2 = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -Action $TaskAction2 -Trigger $TaskTrigger2 -Principal $TaskPrincipa2 -TaskName "Optimize"

$task3 = @"
start-sleep 300
Unregister-ScheduledTask -TaskName Optimize -Confirm:$false
Unregister-ScheduledTask -TaskName Reboot -Confirm:$false
Remove-Item C:\Optimize -Recurse -Force

Remove-Item "C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup\Reboot.ps1" -Force
Restart-Computer -Force
"@

$task3 | Out-file C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup\Reboot.ps1
$TaskAction3 = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup\Reboot.ps1"
$TaskTrigger3 = New-ScheduledTaskTrigger -AtStartup
$TaskPrincipa3 = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -Action $TaskAction3 -Trigger $TaskTrigger3 -Principal $TaskPrincipa3 -TaskName "Reboot"



        ##    \ \_____
      ####### [==_____> Cleaning Program >
        ##    /_/

 
@(
    "$env:windir\\logs",
    "$env:windir\\winsxs\\manifestcache",
    "$env:windir\\Temp",
    "$env:TEMP",
    "c:\appleKeyboard",
    "$PSScriptRoot\PSTools.zip",
    "$PSScriptRoot\fslogix.zip",
    "$PSScriptRoot\fslogix"

) | ForEach-Object {
    if (Test-Path $_) {
        try {
            Takeown /d Y /R /f $_
            Icacls $_ /GRANT:r administrators:F /T /c /q  2>&1 | Out-Null
            Remove-Item $_ -Recurse -Force | Out-Null
        }
        catch { $global:error.RemoveAt(0) }
    }
}



        ##    \ \_____
      ####### [==_____> Closing Program Session >
        ##    /_/

 

Set-MpPreference -DisableRealtimeMonitoring $false
Stop-Transcript
& psexec /s cmd /accepteula
sc privs gpsvc SeManageVolumePrivilege/SeTcbPrivilege/SeTakeOwnershipPrivilege/SeIncreaseQuotaPrivilege/SeAssignPrimaryTokenPrivilege/SeSecurityPrivilege/SeChangeNotifyPrivilege/SeCreatePermanentPrivilege/SeShutdownPrivilege/SeLoadDriverPrivilege/SeRestorePrivilege/SeBackupPrivilege/SeCreatePagefilePrivilege
shutdown.exe /r /t 00
