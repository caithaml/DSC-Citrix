
@{
    AllNodes = @(
        @{
            Nodename                    = 'DC'
            ComputerName                = 'DC'
            Role                        = 'FirstDC', 'DHCP', 'FirstDNS', 'DFS', 'DC'
            Description                 = 'Domain Controller, DHCP, DNS, DFS'
            DomainName                  = 'Citrix.local'
            DomainShortName             = 'Citrix'
            DomainDistinguishedName     = 'dc=Citrix,dc=local'
            RetryCount                  = 50
            RetryIntervalSec            = 30
            Features                    = 'GPMC', 'RSAT-AD-Tools', 'Windows-Server-Backup', 'Windows-Defender-Features', 'RSAT-AD-AdminCenter'
            FeaturesRemove              = 'PowerShell-V2', 'FS-SMB1', 'Telnet-Client', 'WINS'
            IPv4                        = '192.168.100.100/24'
            DNS                         = '192.168.100.100', '192.168.100.101'
            Gateway                     = '192.168.100.1'
            DHCP                        = @(
                @{
                    DHCPScopeName  = 'DHCP Scope'
                    DHCPScopeID    = '192.168.100.0'
                    DHCPRangeStart = '192.168.100.10'
                    DHCPRangeEnd   = '192.168.100.50'
                    DHCPSubnet     = '255.255.255.0'
                    DHCPRouter     = '192.168.100.1'
                    DHCPDNS        = '192.168.100.100'
                }
               
            )
            DNSReverseZone              = '100.168.192.in-addr.arpa'
            WSH                         = $true
            DnsRecords                  = @(
                @{
                    Name   = 'time'
                    Target = '192.168.101.21'
                    Zone   = 'Citrix.local'
                    Type   = 'Arecord'
                    Ensure = 'Present'
                }
            )
            ScheduledTasks              = @(
                @{
                    TaskName         = 'Network Location Awareness restart'
                    TaskPath         = '\Citrix_Tasks'
                    ActionExecutable = 'C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe'
                    ActionArguments  = '-encodedCommand UgBlAHMAdABhAHIAdAAtAFMAZQByAHYAaQBjAGUAIABOAGwAYQBTAHYAYwAgAC0ARgBvAHIAYwBlAA=='
                    ScheduleType     = 'AtStartup'
                    Description      = 'Automaticky restart sluzby Network Location Awareness po startu serveru'
                    RunLevel         = 'Highest'
                    Ensure           = 'Present'
                }
            )
        },
        @{
            NodeName                    = 'Hyperv'
            ComputerName                = 'Hyperv'
            Role                        = 'Hyperv'
            Description                 = 'Hyperv'
            DomainJoin                  = $true
            DomainName                  = 'Citrix.local'
            DomainOUName                = 'OU=Servers,OU=101,dc=Citrix,dc=local'
            Features     = 'GPMC', 'RSAT-AD-Tools', 'hyper-v', 'Hyper-V-Tools', 'Hyper-V-PowerShell'
            FeaturesRemove              = 'PowerShell-V2', 'FS-SMB1', 'Telnet-Client'
            IPv4                        = '192.168.100.132/24'
            DNS                         = '192.168.100.100', '192.168.100.101'
            Gateway                     = '192.168.100.1'
            PSDscAllowPlainTextPassword = $true
            PSDscAllowDomainUser        = $true
            WSH                         = $true
        },
        @{
            NodeName                    = 'Citr'
            ComputerName                = 'Citr'
            Role                        = 'Citrix'
            Description                 = 'Citrix'
            DomainJoin                  = $true
            DomainName                  = 'Citrix.local'
            DomainOUName                = 'OU=Servers,OU=101,dc=Citrix,dc=local'
            Features                    = 'GPMC', 'RSAT-AD-Tools'
            FeaturesRemove              = 'PowerShell-V2', 'FS-SMB1', 'Telnet-Client'
            IPv4                        = '192.168.100.230/24'
            DNS                         = '192.168.100.100', '192.168.100.101'
            Gateway                     = '192.168.100.1'
            PSDscAllowPlainTextPassword = $true
            PSDscAllowDomainUser        = $true
            WSH                         = $true
        },
        @{
            NodeName                    = 'SQL'
            ComputerName                = 'SQL'
            Role                        = 'SQL','SQLManagement'
            Description                 = 'SQL Server'
            DomainJoin                  = $true
            DomainName                  = 'Citrix.local'
            DomainOUName                = 'OU=Servers,OU=101,dc=Citrix,dc=local'
            Features                    = 'GPMC', 'RSAT-AD-Tools', 'NET-Framework-45-Core'
            FeaturesRemove              = 'PowerShell-V2', 'FS-SMB1', 'Telnet-Client'
            IPv4                        = '192.168.100.106/24'
            DNS                         = '192.168.100.100', '192.168.100.101'
            Gateway                     = '192.168.100.1'
            PSDscAllowPlainTextPassword = $true
            PSDscAllowDomainUser        = $true
            WSH                         = $true
        },
        @{
            NodeName                    = 'VMM'
            ComputerName                = 'VMM'
            Role                        = 'VMM'
            Description                 = 'VMM Server'
            DomainJoin                  = $true
            DomainName                  = 'Citrix.local'
            DomainOUName                = 'OU=Servers,OU=101,dc=Citrix,dc=local'
            Features                    = 'GPMC', 'RSAT-AD-Tools', 'NET-Framework-45-Core'
            FeaturesRemove              = 'PowerShell-V2', 'FS-SMB1', 'Telnet-Client'
            IPv4                        = '192.168.100.110/24'
            DNS                         = '192.168.100.100', '192.168.100.101'
            Gateway                     = '192.168.100.1'
            PSDscAllowPlainTextPassword = $true
            PSDscAllowDomainUser        = $true
            WSH                         = $true
           },
        @{
            NodeName                    = '*'
            DomainName                  = 'Citrix.local'
           #EthernetName               = 'Ethernet0'  #Konfigurace pro Vmware kde je nazev prniho Ethernetu = Ethernet0
            EthernetName                = 'Ethernet' #Konfigurace pro Hyper-V kde je nazev prniho Ethernetu = Ethernet
            #Ethernet2Name              = 'Ethernet1'  #Konfigurace pro Vmware kde je nazev druheho Ethernetu = Ethernet1
            Ethernet2Name               = 'Ethernet 2' #Konfigurace pro Hyper-V kde je nazev druheho Ethernetu = Ethernet 2
            PSDscAllowPlainTextPassword = $true
            PSDscAllowDomainUser        = $true
            DomainAdminName             = 'Administrator' #Konfigurace pred aplikovanim NBU GP
            #DomainAdminName             = 'Master'
            Services   = @(
                @{
                    'Name'        = 'W32Time'
                    'StartupType' = 'Automatic'
                    'State'       = 'Running'
                }
            )
            Users                       = @(
                @{
                    'Ensure'      = 'Present'
                    'UserName'    = 'caithamlm'
                    'Surname'     = 'Michal'
                    'GivenName'   = 'Caithaml'
                    'DisplayName' = 'Michal Caithaml'
                    'Enabled'     = $true
                },
                @{
                    'Ensure'      = 'Present'
                    'UserName'    = 'kejrd'
                    'Surname'     = 'David'
                    'GivenName'   = 'Kejr'
                    'DisplayName' = 'David Kejr'
                    'Enabled'     = $true
                }

            )
            OtherUsers                  = @(
                @{
                    'Ensure'      = 'Present'
                    'UserName'    = 'DNSUpd'
                    'DisplayName' = 'DNS Upd'
                    'Enabled'     = $true
                },
                @{
                    'Ensure'      = 'Present'
                    'UserName'    = 'DomainJoin'
                    'DisplayName' = 'Domain Join'
                    'Enabled'     = $true
                },
                @{
                    'Ensure'      = 'Present'
                    'UserName'    = 'SQLCitrixService'
                    'DisplayName' = 'SQL Citrix Service'
                    'Enabled'     = $true
                }
            )
            WSAdmins                    = @(
                @{
                    'Ensure'      = 'Present'
                    'UserName'    = 'dake'
                    'Surname'     = 'David'
                    'GivenName'   = 'Kejr'
                    'DisplayName' = 'David Kejr'
                    'Enabled'     = $true
                },
                @{
                    'Ensure'      = 'Present'
                    'UserName'    = 'mica'
                    'Surname'     = 'Michal'
                    'GivenName'   = 'Caithaml'
                    'DisplayName' = 'Michal Caithaml'
                    'Enabled'     = $true
                },
                @{
                    'Ensure'      = 'Present'
                    'UserName'    = 'likr'
                    'Surname'     = 'Libor'
                    'GivenName'   = 'Kratochvil'
                    'DisplayName' = 'Libor Kratochvil'
                    'Enabled'     = $true
                },
                @{
                    'Ensure'      = 'Present'
                    'UserName'    = 'lich'
                    'Surname'     = 'Libor'
                    'GivenName'   = 'Charvat'
                    'DisplayName' = 'Libor Charvat'
                    'Enabled'     = $true
                }
            )
            DomainAdmins                = @(
                @{
                    'Ensure'      = 'Present'
                    'UserName'    = 'ADdake'
                    'Surname'     = 'David'
                    'GivenName'   = 'Kejr'
                    'DisplayName' = 'David Kejr'
                    'Enabled'     = $true
                },
                @{
                    'Ensure'      = 'Present'
                    'UserName'    = 'ADmica'
                    'Surname'     = 'Michal'
                    'GivenName'   = 'Caithaml'
                    'DisplayName' = 'Michal Caithaml'
                    'Enabled'     = $true
                },
                @{
                    'Ensure'      = 'Present'
                    'UserName'    = 'ADlich'
                    'Surname'     = 'Libor'
                    'GivenName'   = 'Charvat'
                    'DisplayName' = 'Libor Charvat'
                    'Enabled'     = $true
                }
            )
            BSAdmins                    = @(
                @{
                    'Ensure'      = 'Present'
                    'UserName'    = 'BSmipl'
                    'Surname'     = 'Michal'
                    'GivenName'   = 'Plasil'
                    'DisplayName' = 'Michal Plasil'
                    'Enabled'     = $true
                },
                @{
                    'Ensure'      = 'Present'
                    'UserName'    = 'BSvali'
                    'Surname'     = 'Vaclav'
                    'GivenName'   = 'Licibnerk'
                    'DisplayName' = 'Vaclav Licibnerk'
                    'Enabled'     = $true
                }
            )
        }
    )

    }