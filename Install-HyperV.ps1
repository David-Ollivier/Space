      
        ##    \ \_____
      ####### [==_____> Install Hyper-V >
        ##    /_/

Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart
Restart-Computer -Force 