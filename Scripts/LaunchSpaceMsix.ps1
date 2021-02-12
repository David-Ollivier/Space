Param(
    $projectname,
    $storage,
    $storagepass,
    $sharename,
    $app1,
    $app2,
    $app3,
    $app4,
    $app5,
    $app6,
    $app7,
    $app8 
)

Start-Transcript c:\install.log

# Mount Sapce Share
$storageuser = $storage.split('.')[0]
$storageuser = "Azure\" + $storageuser
$fullazureshare = '\\' + $storage + '\' + $sharename
cmd.exe /C "cmdkey /add:$storage /user:$storageuser /pass:$storagepass"
New-PSDrive -Name Z -PSProvider FileSystem -Root $fullazureshare


# Fly Certificate Verification
new-item -path "c:\space\cert" -ItemType Directory
New-SelfSignedCertificate -Type Custom -Subject "CN=$projectname" -KeyUsage DigitalSignature -FriendlyName "$projectname" -CertStoreLocation "Cert:\CurrentUser\my" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}") -NotAfter (Get-Date).AddMonths(242)
$password = ConvertTo-SecureString -String space -Force -AsPlainText
Set-Location Cert:\CurrentUser\my
$certThmb = ( Get-ChildItem | Where-Object{$_.Subject -eq "CN=$projectname"} ).Thumbprint
Export-PfxCertificate -cert "Cert:\CurrentUser\my\$certThmb" -FilePath c:\space\cert\cert.pfx -Password $password

$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("c:\space\cert\cert.pfx","space")
$rootStore = Get-Item cert:\LocalMachine\Root
$rootStore.Open("ReadWrite")
$rootStore.Add($cert)
$rootStore.Close()

xcopy.exe "c:\space\cert\cert.pfx" $fullazureshare


# Sending MSIX Packages Informations
$applist = @($app1,$app2,$app3,$app4,$app5,$app6,$app7,$app8) | Where-Object { $_ -ne 'none' }
$applist | out-file "c:\space\apps.csv"
xcopy.exe "c:\space\apps.csv" $fullazureshare

# Hyper vSpace Program
DISM /Online /Enable-Feature /All /FeatureName:Microsoft-Hyper-V /NoRestart


# Getting spaceMsix
$spaceURL = 'https://raw.githubusercontent.com/David-Ollivier/Space/master/Scripts/spaceMsix.ps1'
Invoke-WebRequest -Uri $spaceURL -OutFile "c:\space\spaceMsix.ps1"

# $TaskAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass c:\space\spaceMsix.ps1 -projectname $projectname -storage $storage -storagepass $storagepass -sharename $sharename -app1 `"'$app1'`" -app2 `"'$app2'`" -app3 `"'$app3'`" -app4 `"'$app4'`" -app5 `"'$app5'`" -app6 `"'$app6'`" -app7 `"'$app7'`" -app8 `"'$app8'`""
# $TaskTrigger = New-ScheduledTaskTrigger -AtStartup
# Register-ScheduledTask -Action $TaskAction -Trigger $TaskTrigger -user "spaceMsix\spaceMsix" -Password $adminPassword -TaskName "spaceMsix" -RunLevel Highest

$action = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-ExecutionPolicy Bypass c:\space\spaceMsix.ps1 -projectname $projectname -storage $storage -storagepass $storagepass -sharename $sharename"
$TaskTrigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -User SYSTEM -Action $action -Trigger $TaskTrigger -TaskName "spaceMsix" -Description "spaceMsix" -Force

Stop-Transcript
Restart-Computer -Force