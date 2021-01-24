Param(
    $projectname,
    $storage,
    $storagepass,
    $sharename,
    $adminPassword,
    $app1,
    $app2,
    $app3,
    $app4,
    $app5,
    $app6,
    $app7,
    $app8 
)

# $projectname = "space"
# $storage = "spaceshare0124t040533z.file.core.windows.net" 
# $storagepass = "83dqltwBa3yXbU3z8IwGErcNl7ouRW6TyEtKqbLMuYLSTV02EQLlYPEQTdBl/tD2wfI0Yne7IJllA/HT38mEZQ==" 
# $sharename = "msix" 
# $app1 = "choco install googlechrome" 
# $app2 = "choco install adobereader" 
# $app3 = "choco install firefox" 
# $app4 = "choco install notepadplusplus.install" 
# $app5 = "choco install python3" 
# $app6 = "choco install foxitreader" 
# $app7 = "none" 
# $app8 = "none"

# Hyper Space
DISM /Online /Enable-Feature /All /FeatureName:Microsoft-Hyper-V /NoRestart

# Getting spaceMsix
new-item -path "c:\space" -ItemType Directory
$spaceURL = 'https://raw.githubusercontent.com/SpaceWVD/Space/master/Scripts/spaceMsix.ps1'
Invoke-WebRequest -Uri $spaceURL -OutFile "c:\space\spaceMsix.ps1"

$TaskAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass c:\space\spaceMsix.ps1 -projectname $projectname -storage $storage -storagepass $storagepass -sharename $sharename -app1 `"'$app1'`" -app2 `"'$app2'`" -app3 `"'$app3'`" -app4 `"'$app4'`" -app5 `"'$app5'`" -app6 `"'$app6'`" -app7 `"'$app7'`" -app8 `"'$app8'`""
$TaskTrigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -Action $TaskAction -Trigger $TaskTrigger -user "spaceMsix\spaceMsix" -Password $adminPassword -TaskName "spaceMsix" -RunLevel Highest

Restart-Computer -Force