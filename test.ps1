
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
