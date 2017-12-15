## Getting started

Desired State Configuration skript pro vytvoření testovaciho prostredi pro Citrix
DSC automaticky provadi restarty v potrebnou dobu (nekolik restartu) nez je prostředí komplet naistalováno a nakonfigurováno

### Prerequisities

Windows PowerShell 5.1   
Windows Server 2016  
Naistalovany vsechny DSC moduly z adresáře Modules

### Usage

Příprava prostředí před spuštěním na serveru. Možno uložit do Vmware/Hyper-V template nebo použít Lability
```Powershell
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine -Force
Enable-PSRemoting -SkipNetworkProfileCheck -Force
Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 10000
Copy-Item -Path "$scriptpath\Modules\*"  -Destination 'C:\Program Files\WindowsPowerShell\Modules' -Recurse -Force
```

Vytvoření DSC konfiguračního dokumentu. Tam kde je dokument vytvářen, musí být také všechny moduly z adresáře modules
```Powershell
RUPS_DSC -configurationData $ConfigData -domainCred $dcred -safemodeAdministratorCred $dcred
```

Spuštění DSC konfigurace na serveru
```Powershell
Start-DscConfiguration -Wait -Force -Verbose -Path .\RUPS_DSC -ComputerName XXX
```

## Authors

* [Michal Caithaml](https://github.com/caithaml)



