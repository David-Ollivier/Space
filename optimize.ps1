
################################
#    Download WVD Optimizer    #
################################
New-Item -Path C:\ -Name Optimize -ItemType Directory -ErrorAction SilentlyContinue
$LocalPath = "C:\Optimize\"
$WVDOptimizeURL = 'https://github.com/The-Virtual-Desktop-Team/Virtual-Desktop-Optimization-Tool/archive/master.zip'
$WVDOptimizeInstaller = "Windows_10_VDI_Optimize-master.zip"
Invoke-WebRequest `
    -Uri $WVDOptimizeURL `
    -OutFile "$Localpath$WVDOptimizeInstaller"


###############################
#    Prep for WVD Optimize    #
###############################
Expand-Archive `
    -LiteralPath "C:\Optimize\Windows_10_VDI_Optimize-master.zip" `
    -DestinationPath "$Localpath" `
    -Force `
    -Verbose
Set-Location -Path C:\Optimize\Virtual-Desktop-Optimization-Tool-master


#################################
#    Run WVD Optimize Script    #
#################################
New-Item -Path C:\Optimize\ -Name install.log -ItemType File -Force
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force -Verbose
add-content c:\Optimize\install.log "Starting Optimizations"  
.\Win10_VirtualDesktop_Optimize.ps1 -WindowsVersion 2004 -Restart -Verbose