Clear-Host
configuration DSC-Citrix
{
  param
  (
    [Parameter(Mandatory)]
    [pscredential]$safemodeAdministratorCred,
    [Parameter(Mandatory)]
    [pscredential]$domainCred,
    [Parameter(Mandatory)]
    [pscredential]$defaultusercred,
    [Parameter(Mandatory)]
    [pscredential]$SqlCitrixCredential

  )
  Import-DscResource -ModuleName PSDesiredStateConfiguration
  Import-DscResource -ModuleName xPSDesiredStateConfiguration
  Import-DscResource -ModuleName xActiveDirectory
  Import-DscResource -ModuleName xNetworking
  Import-DscResource -ModuleName xDHCpServer
  Import-DscResource -ModuleName xComputerManagement
  Import-DscResource -ModuleName xSmbShare
  Import-DscResource -ModuleName xPendingReboot
  Import-DscResource -ModuleName xTimeZone
  Import-DscResource -ModuleName xRemoteDesktopAdmin
  Import-DscResource -ModuleName SystemLocaleDSC
  Import-DscResource -ModuleName xDnsServer
  Import-DscResource -ModuleName xDFS
  Import-DscResource -ModuleName cNtfsAccessControl
  Import-DscResource -ModuleName xAdcsDeployment
  Import-DscResource -ModuleName xWindowsEventForwarding
  Import-DscResource -ModuleName xSQLServer
  Import-DscResource -ModuleName xExchange
  Import-DscResource -ModuleName SharePointDSC
  Import-DscResource -ModuleName xFailOverCluster
  
  Node $AllNodes.NodeName
  {
    LocalConfigurationManager
    {
      ActionAfterReboot = 'ContinueConfiguration'
      ConfigurationMode = 'ApplyOnly'
      RebootNodeIfNeeded = $true
      AllowModuleOverwrite = $true
      ConfigurationModeFrequencyMins = 15
    }

    ###<WINrm max envelop size

    Script SetWINrm
    {
      SetScript =
      {
        Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 10000
      }

      TestScript = {
        if ((Get-Item -Path WSMan:\localhost\MaxEnvelopeSizekb).value -eq '10000')
        {
          return $true
        }
        else
        {
          return $false
        }
      }

      GetScript = {
        Return  @{
          Result = $((Get-Item -Path WSMan:\localhost\MaxEnvelopeSizekb).value)
        }
      }
    }
    ###>WINrm max envelop size


    ###<FEATURES AND SERVICES
    foreach($feature in $Node.Features)
    {
      WindowsFeature $feature
      {
        Name = $feature
        Ensure = 'Present'
      }
    }

    foreach($feature in $Node.FeaturesRemove)
    {
      WindowsFeature $feature
      {
        Name = $feature
        Ensure = 'Absent'
      }
    }

    foreach($Service in $Node.Services)
    {
      Service $($Service.Name)
      {
        Name = $($Service.Name)
        StartupType = $($Service.StartupType)
        State = $($Service.State)
      }
    }

    ###>FEATURES AND SERVICES

    ###<SYSTEM Config
    xtimezone 'Central Europe Standard Time' {

      IsSingleInstance = 'Yes'
      TimeZone = 'Central Europe Standard Time'
    }

    ##< RDP
    xRemoteDesktopAdmin RemoteDesktopSettings
    {
      Ensure = 'Present'
      UserAuthentication = 'Secure'
    }
    ##> RDP

    ##< IPv6 Disable


    ##> IPv6 Disable

    ##< IP konfigurace
    xIPAddress NewIPAddress
    {
      IPAddress      = $Node.IPv4
      InterfaceAlias = $Node.EthernetName
      AddressFamily  = 'IPV4'
    }

    xDnsServerAddress DnsServerAddress
    {
      Address        = $Node.DNS
      InterfaceAlias = $Node.EthernetName
      AddressFamily  = 'IPV4'
    }

    xDefaultGatewayAddress GatewayAddress
    {
      InterfaceAlias = $Node.EthernetName
      AddressFamily  = 'IPV4'
      Address = $Node.Gateway

    }
    xNetBIOS NetBIOS
    {
      InterfaceAlias = $Node.EthernetName
      Setting = 'Disable'
    }
    ##> IP konfigurace

    ##< Group Policy Debug
    File GPDebug
    {
      Ensure = 'Present'
      Type = 'Directory'
      DestinationPath = 'C:\Windows\debug\usermode'
    }

    Registry GPDebug
    {
      Ensure = 'Present'
      Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
      ValueName   = 'UserenvDebugLevel'
      ValueData   = '30002'
      Hex         = $true
      Force       = $true
      DependsOn = '[File]GPDebug'
      ValueType = 'Dword'
    }

    ##> Group Policy Debug

    ##< Enhanced Security IE disabled
    Registry EnhancedIESecDisabledAdmin
    {
      Ensure = 'Present'
      Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}'
      ValueName   = 'IsInstalled'
      ValueData   = '0'
      Force       = $true
      ValueType = 'Dword'
    }

    Registry EnhancedIESecDisabledUser
    {
      Ensure = 'Present'
      Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}'
      ValueName   = 'IsInstalled'
      ValueData   = '0'
      Force       = $true
      ValueType = 'Dword'
    }

    ##> Enhanced Security IE disabled
  }

  Node $AllNodes.Where{
    $_.Role -notcontains 'FirstDC'
  }.NodeName
  {
    ##< Time for Member Servers
    Script SetMemberTime
    {
      SetScript =
      {
        w32tm.exe /config /syncfromflags:DOMHIER
        Restart-Service -Name w32time
        w32tm.exe /resync
      }

      TestScript = {
        if($(Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters -Name 'Type') -ne 'NT5DS')
        {
          return $false
        }
        else
        {
          return $true
        }
      }

      GetScript = {
        return @{
          Result = [string]$(Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters -Name 'Type').Type
        }
      }
      DependsOn = '[Service]W32Time'
    }
    ##> Time for Member Servers
  }


  Node $AllNodes.Where{
    $_.Role -contains 'DC'
  }.NodeName
  {
    WindowsFeature ADDSInstall
    {
      Ensure = 'Present'
      Name = 'AD-Domain-Services'
    }
  }

  Node $AllNodes.Where{
    $_.Role -contains 'DFS'
  }.NodeName
  {
    ###<DFS
    WindowsFeature RSATDFSMgmtConInstall
    {
      Ensure = 'Present'
      Name = 'RSAT-DFS-Mgmt-Con'
    }

    {
      Ensure = 'Present'
      Name = 'RSAT-FSRM-Mgmt'
    }

    {
      Ensure = 'Present'
      Name = 'FS-Resource-Manager'
    }

    WindowsFeature DFS
    {
      Name = 'FS-DFS-Namespace'
      Ensure = 'Present'
    }

    ###>DFS
  }


    Node $AllNodes.Where{
        $_.Role -contains 'FirstDC'
    }.NodeName
    {
        ##< Time for PDC
        Script SetPDCTime {
            SetScript  =
            {
                w32tm.exe /config /update /manualpeerlist:'time.Citrix.local,0x1' /syncfromflags:manual /reliable:yes
                Restart-Service -Name w32time
                w32tm.exe /resync
            }

            TestScript = {
                if ($(Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters -Name 'Type') -ne 'NTP' -or $(Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters -Name 'NtpServer') -ne 'time.Citrix.local,0x1') {
                    return $false
                }
                else {
                    return $true
                }
            }

            GetScript  = {
                return @{
                    Result = [string]$(Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters -Name 'Type').Type
                }
            }
            DependsOn  = '[Service]W32Time'
        }

        ##> Time for PDC

        <#bookmark DC #>

        ###<AD

        xADDomain FirstDS {
            DomainName                    = $Node.DomainName
            DomainAdministratorCredential = $domainCred
            SafemodeAdministratorPassword = $safemodeAdministratorCred
            DependsOn                     = '[WindowsFeature]ADDSInstall'
            DomainNetBIOSName             = $Node.DomainShortName
        }

        xADRecycleBin RecycleBin {
            EnterpriseAdministratorCredential = $domainCred
            ForestFQDN                        = $Node.DomainName
            PsDscRunAsCredential              = $domainCred
        }

        xADOrganizationalUnit 101 {
            Name                            = '101'
            Path                            = "$($Node.DomainDistinguishedName)"
            ProtectedFromAccidentalDeletion = $true
            Description                     = 'Lokalita Praha'
            Ensure                          = 'Present'
        }

        xADOrganizationalUnit GlobalAccounts {
            Name                            = 'Global Accounts'
            Path                            = "$($Node.DomainDistinguishedName)"
            ProtectedFromAccidentalDeletion = $true
            Description                     = 'Servisni ucty domeny'
            Ensure                          = 'Present'
        }

        xADOrganizationalUnit GlobalGroups {
            Name                            = 'Global Groups'
            Path                            = "$($Node.DomainDistinguishedName)"
            ProtectedFromAccidentalDeletion = $true
            Description                     = 'Skupiny domény'
            Ensure                          = 'Present'
        }

        xADOrganizationalUnit DeletedObjects {
            Name                            = 'Deleted'
            Path                            = "$($Node.DomainDistinguishedName)"
            ProtectedFromAccidentalDeletion = $true
            Description                     = 'Vsechny objekty urcene ke smazani'
            Ensure                          = 'Present'
        }

         xADOrganizationalUnit WSInstall {
            Name                            = 'WS Install'
            Path                            = "$($Node.DomainDistinguishedName)"
            ProtectedFromAccidentalDeletion = $true
            Description                     = 'OU pro instalovane pocitace'
            Ensure                          = 'Present'
        }

        xADOrganizationalUnit Admins {
            Name                            = 'Admins'
            Path                            = "OU=101,$($Node.DomainDistinguishedName)"
            ProtectedFromAccidentalDeletion = $true
            Description                     = 'Vsichni Administratori IS'
            Ensure                          = 'Present'
            DependsOn                       = '[xADOrganizationalUnit]101'
        }

        xADOrganizationalUnit Servers {
            Name                            = 'Servers'
            Path                            = "OU=101,$($Node.DomainDistinguishedName)"
            ProtectedFromAccidentalDeletion = $true
            Description                     = 'Vsechny servery Praha'
            Ensure                          = 'Present'
            DependsOn                       = '[xADOrganizationalUnit]101'
        }

          xADOrganizationalUnit ThinClients {
            Name                            = 'Thin Clients'
            Path                            = "OU=101,$($Node.DomainDistinguishedName)"
            ProtectedFromAccidentalDeletion = $true
            Description                     = 'Vsechny stanice Tenky klient'
            Ensure                          = 'Present'
            DependsOn                       = '[xADOrganizationalUnit]101'
        }

        xADOrganizationalUnit Users {
            Name                            = 'Users'
            Path                            = "OU=101,$($Node.DomainDistinguishedName)"
            ProtectedFromAccidentalDeletion = $true
            Description                     = 'Vsichni uzivatele Praha'
            Ensure                          = 'Present'
            DependsOn                       = '[xADOrganizationalUnit]101'
        }

        xADOrganizationalUnit Workstations {
            Name                            = 'Workstations'
            Path                            = "OU=101,$($Node.DomainDistinguishedName)"
            ProtectedFromAccidentalDeletion = $true
            Description                     = 'Vsechny uzivatelske stanice Praha'
            Ensure                          = 'Present'
            DependsOn                       = '[xADOrganizationalUnit]101'
        }

        xADOrganizationalUnit Groups {
            Name                            = 'Groups'
            Path                            = "OU=101,$($Node.DomainDistinguishedName)"
            ProtectedFromAccidentalDeletion = $true
            Description                     = 'Vsechny utvary Praha'
            Ensure                          = 'Present'
            DependsOn                       = '[xADOrganizationalUnit]101'
        }

        xADOrganizationalUnit 3255 {
            Name                            = '3255'
            Path                            = "OU=Groups,OU=101,$($Node.DomainDistinguishedName)"
            ProtectedFromAccidentalDeletion = $true
            Description                     = 'Utvar 3255 Praha'
            Ensure                          = 'Present'
            DependsOn                       = '[xADOrganizationalUnit]Groups'
        }

        xADOrganizationalUnit 3255Distribution {
            Name                            = 'Distribution'
            Path                            = "OU=3255,OU=Groups,OU=101,$($Node.DomainDistinguishedName)"
            ProtectedFromAccidentalDeletion = $true
            Description                     = 'Distribucni skupiny utvaru 3255 Praha'
            Ensure                          = 'Present'
            DependsOn                       = '[xADOrganizationalUnit]3255'
        }

        xADOrganizationalUnit 3255Security {
            Name                            = 'Security'
            Path                            = "OU=3255,OU=Groups,OU=101,$($Node.DomainDistinguishedName)"
            ProtectedFromAccidentalDeletion = $true
            Description                     = 'Security skupiny utvaru 3255 Praha'
            Ensure                          = 'Present'
            DependsOn                       = '[xADOrganizationalUnit]3255'
        }

        xADOrganizationalUnit 1122 {
            Name                            = '1122'
            Path                            = "OU=Groups,OU=101,$($Node.DomainDistinguishedName)"
            ProtectedFromAccidentalDeletion = $true
            Description                     = 'Utvar 1122 Praha'
            Ensure                          = 'Present'
            DependsOn                       = '[xADOrganizationalUnit]Groups'
        }

        xADOrganizationalUnit 1122Distribution {
            Name                            = 'Distribution'
            Path                            = "OU=1122,OU=Groups,OU=101,$($Node.DomainDistinguishedName)"
            ProtectedFromAccidentalDeletion = $true
            Description                     = 'Distribucni skupiny utvaru 1122 Praha'
            Ensure                          = 'Present'
            DependsOn                       = '[xADOrganizationalUnit]1122'
        }

        xADOrganizationalUnit 1122Security {
            Name                            = 'Security'
            Path                            = "OU=1122,OU=Groups,OU=101,$($Node.DomainDistinguishedName)"
            ProtectedFromAccidentalDeletion = $true
            Description                     = 'Security skupiny utvaru 1122 Praha'
            Ensure                          = 'Present'
            DependsOn                       = '[xADOrganizationalUnit]1122'
        }


        #####>AD Users musi byt pred vytvarenim Groups
        foreach ($User in $Node.Users) {
            xADUser $($User.UserName) {
                DomainName             = $Node.DomainName
                UserName               = $($User.UserName)
                Ensure                 = $($User.Ensure)
                Surname                = $($User.Surname)
                GivenName              = $($User.GivenName)
                DisplayName            = $($User.DisplayName)
                Enabled                = $($User.Enabled)
                Description            = $($User.DisplayName)
                Password               = $defaultusercred
                UserPrincipalName      = $($User.UserName) + '@' + $Node.DomainName
                Path                   = "OU=Users,OU=101,$($Node.DomainDistinguishedName)"
                PasswordAuthentication = 'Negotiate'
                #ProfilePath            = '\\' + "$($Node.DomainName)" + '\dfs\Profile\' + $($User.UserName)
                HomeDirectory          = '\\' + "$($Node.DomainName)" + '\dfs\Home\' + $($User.UserName)
                HomeDrive              = 'H:'
                DependsOn              = "[xADOrganizationalUnit]Users"
            }
        }

        foreach ($User in $Node.OtherUsers) {
            xADUser $($User.UserName) {
                DomainName             = $Node.DomainName
                UserName               = $($User.UserName)
                Ensure                 = $($User.Ensure)
                DisplayName            = $($User.DisplayName)
                Enabled                = $($User.Enabled)
                Description            = $($User.DisplayName)
                Password               = $defaultusercred
                UserPrincipalName      = $($User.UserName) + '@' + $Node.DomainName
                PasswordNeverExpires = $true
                Path                   = "OU=Global Accounts,$($Node.DomainDistinguishedName)"
                PasswordAuthentication = 'Negotiate'
                DependsOn              = '[xADOrganizationalUnit]GlobalGroups'
            }
        }

        foreach ($User in $Node.WSAdmins) {
            xADUser $($User.UserName) {
                DomainName             = $Node.DomainName
                UserName               = $($User.UserName)
                Ensure                 = $($User.Ensure)
                Surname                = $($User.Surname)
                GivenName              = $($User.GivenName)
                DisplayName            = $($User.DisplayName)
                Enabled                = $($User.Enabled)
                Description            = $($User.DisplayName)
                Password               = $defaultusercred
                UserPrincipalName      = $($User.UserName) + '@' + $Node.DomainName
                Path                   = "OU=Admins,OU=101,$($Node.DomainDistinguishedName)"
                PasswordAuthentication = 'Negotiate'
                DependsOn              = '[xADOrganizationalUnit]Admins'
            }
        }

        foreach ($User in $Node.BSAdmins) {
            xADUser $($User.UserName) {
                DomainName             = $Node.DomainName
                UserName               = $($User.UserName)
                Ensure                 = $($User.Ensure)
                Surname                = $($User.Surname)
                GivenName              = $($User.GivenName)
                DisplayName            = $($User.DisplayName)
                Enabled                = $($User.Enabled)
                Description            = $($User.DisplayName)
                Password               = $defaultusercred
                UserPrincipalName      = $($User.UserName) + '@' + $Node.DomainName
                Path                   = "OU=Admins,OU=101,$($Node.DomainDistinguishedName)"
                PasswordAuthentication = 'Negotiate'
                DependsOn              = '[xADOrganizationalUnit]Admins'
            }
        }

        foreach ($User in $Node.DomainAdmins) {
            if ($($User.UserName) -eq 'Administrator') {
                continue
            }
            xADUser $($User.UserName) {
                DomainName             = $Node.DomainName
                UserName               = $($User.UserName)
                Ensure                 = $($User.Ensure)
                Surname                = $($User.Surname)
                GivenName              = $($User.GivenName)
                DisplayName            = $($User.DisplayName)
                Enabled                = $($User.Enabled)
                Description            = $($User.DisplayName)
                Password               = $defaultusercred
                UserPrincipalName      = $($User.UserName) + '@' + $Node.DomainName
                Path                   = "OU=Admins,OU=101,$($Node.DomainDistinguishedName)"
                PasswordAuthentication = 'Negotiate'
                DependsOn              = '[xADOrganizationalUnit]Admins'
            }
        }

        #####>AD Users   

         xADGroup SGSQLCitrix {
            GroupName   = 'SG SQL Citrix'
            GroupScope  = 'Global'
            Category    = 'Security'
            Description = 'Security skupina pro vsechny administratory SQL instance Citrix'
            Ensure      = 'Present'
            Credential  = $domainCred
            Path        = "OU=Global Groups,$($Node.DomainDistinguishedName)"
            Members = 'SQLCitrixService','Domain Admins'
            DependsOn   = '[xADOrganizationalUnit]GlobalGroups'
        }


        xADGroup All_Users {
            GroupName   = 'SG Users'
            GroupScope  = 'Global'
            Category    = 'Security'
            Description = 'Vsichni uzivatele domeny, kteri se mohou prihlasit ke stanicim tenky klient a k virtualizovanym stanicim'
            Ensure      = 'Present'
            Credential  = $domainCred
            Path        = "OU=Global Groups,$($Node.DomainDistinguishedName)"
            Members     = $Node.Users.UserName
            DependsOn   = '[xADOrganizationalUnit]GlobalGroups'
        }

        xADGroup DomainAdmins {
            GroupName  = 'Domain Admins'
            GroupScope = 'Global'
            Category   = 'Security'
            Ensure     = 'Present'
            Credential = $domainCred
            Members    = $($Node.DomainAdmins.UserName + $Node.DomainAdminName)
        }

        #xADGroup ProtectedUsers
        #{
        #  GroupName = 'Protected Users'
        #  GroupScope = 'Global'
        #  Category = 'Security'
        #  Ensure = 'Present'
        #  Credential = $domainCred
        #  Members = $($Node.DomainAdmins.UserName |Where-Object -FilterScript {
        #     $_ -ne 'Master'
        # })

        #}

        #  xADGroup Administrators
        #  {
        #  GroupName = 'Administrators'
        #  Ensure = "Present"
        #  Members = $('Domain Admins' + 'Enterprise Admins' + $Node.DomainAdminName)
        #  }

        xADGroup SchemaAdmins {
            GroupName  = 'Schema Admins'
            GroupScope = 'Universal'
            Category   = 'Security'
            Ensure     = 'Present'
            Credential = $domainCred
            Members    = $Node.DomainAdminName
        }

        xADGroup EnterpriseAdmins {
            GroupName  = 'Enterprise Admins'
            GroupScope = 'Universal'
            Category   = 'Security'
            Ensure     = 'Present'
            Credential = $domainCred
            Members    = $Node.DomainAdminName
        }


        #####>AD

        File PolicyDefinitions {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'C:\Windows\SYSVOL\domain\Policies\PolicyDefinitions'
            DependsOn       = '[xADDomain]FirstDS'
        }

        ##<DFS

        File DFSRoot {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'C:\DFSRoots\'
        }

        File DFS {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'C:\DFSRoots\DFS'
            DependsOn = '[File]DFSRoot'
        }
    
        xSmbShare DFSRoot {
            Ensure      = 'Present'
            Name        = 'DFS'
            Path        = 'C:\DFSRoots\DFS'
            Description = 'DFSRoot share'
            ReadAccess  = 'Authenticated Users'
            DependsOn   = '[File]DFSRoot'
        }
        
         xPendingReboot BeforeDFSInstall {
            Name      = "BeforeDFSInstall"
        }

        xDFSNamespaceServerConfiguration DFSNamespaceConfig {
            IsSingleInstance     = 'Yes'
            UseFQDN              = $true
            PsDscRunAsCredential = $domainCred
            DependsOn            = '[WindowsFeature]DFS','[xPendingReboot]BeforeDFSInstall'
        }
    
        xDFSNamespaceRoot DFSNamespaceRoot {
            Path                         = '\\Citrix.local\DFS'
            TargetPath                   = "\\$NodeName.Citrix.local\DFS"
            Ensure                       = 'Present'
            Type                         = 'DomainV2'
            Description                  = 'DFSRoot'
            PsDscRunAsCredential         = $domainCred
            DependsOn                    = '[xSmbShare]DFSRoot', '[xDFSNamespaceServerConfiguration]DFSNamespaceConfig'
            EnableAccessBasedEnumeration = $true
        }
    
       
        xDFSNamespaceFolder DFSNamespaceFolder_NetApps {
            Path                 = '\\Citrix.local\dfs\NetApps'
            TargetPath           = '\\DC.Citrix.local\NetApps$'
            Ensure               = 'Present'
            Description          = 'Adresar pro instalacni software'
            PsDscRunAsCredential = $domainCred
            DependsOn            = '[xDFSNamespaceRoot]DFSNamespaceRoot'
        }


        xDFSNamespaceFolder DFSNamespaceFolder_Utils {
            Path                 = '\\Citrix.local\dfs\Utils'
            TargetPath           = '\\DC.Citrix.local\Utils$' 
            Ensure               = 'Present'
            Description          = 'Adresar pro administratorske nastroje'
            PsDscRunAsCredential = $domainCred
            DependsOn            = '[xDFSNamespaceRoot]DFSNamespaceRoot'
        }

        xDFSNamespaceFolder DFSNamespaceFolder_Audits {
            Path                 = '\\Citrix.local\dfs\Audits'
            TargetPath           = '\\DC.Citrix.local\Audits$' 
            Ensure               = 'Present'
            Description          = 'Adresar pro logove a auditni zaznamy'
            PsDscRunAsCredential = $domainCred
            DependsOn            = '[xDFSNamespaceRoot]DFSNamespaceRoot'
        }

        xDFSNamespaceFolder DFSNamespaceFolder_Deployment {
            Path                 = '\\Citrix.local\dfs\Deployment'
            TargetPath           = '\\DC.Citrix.local\Deployment$' 
            Ensure               = 'Present'
            Description          = 'Deployment share'
            PsDscRunAsCredential = $domainCred
            DependsOn            = '[xDFSNamespaceRoot]DFSNamespaceRoot'
        }

         xDFSNamespaceFolder DFSNamespaceFolder_Home {
            Path                 = '\\Citrix.local\dfs\Home'
            TargetPath           = '\\DC.Citrix.local\Home$' 
            Ensure               = 'Present'
            Description          = 'Adresar pro home adresare uzivatelu'
            PsDscRunAsCredential = $domainCred
            DependsOn            = '[xDFSNamespaceRoot]DFSNamespaceRoot'
        }

         xDFSNamespaceFolder DFSNamespaceFolder_Profile {
            Path                 = '\\Citrix.local\dfs\Profile'
            TargetPath           = '\\DC.Citrix.local\Profile$' 
            Ensure               = 'Present'
            Description          = 'Adresar pro profilove adresare uzivatelu'
            PsDscRunAsCredential = $domainCred
            DependsOn            = '[xDFSNamespaceRoot]DFSNamespaceRoot'
        }

        ##>DFS
  }

Node $AllNodes.Where{$_.Role -eq "DC"}.Nodename
    {

        ##<Adresare

        File LAPS {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'D:\Netapps\LAPS'
            DependsOn       = '[File]Netapps'
        }

        File SQL_Management_Tools {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'D:\Netapps\SQL_Management_Tools'
            DependsOn       = '[File]Netapps'
        }

        File RSAT {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'D:\Netapps\RSAT'
            DependsOn       = '[File]Netapps'
        }

        File Office_2016 {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'D:\Netapps\Office_2016'
            DependsOn       = '[File]Netapps'
        }

        File localobat {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'D:\Netapps\localobat'
            DependsOn       = '[File]Netapps'
        }

         File UCMA {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'D:\Netapps\UCMA'
            DependsOn       = '[File]Netapps'
        }
       
         File SQL2016 {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'D:\Netapps\SQL2016'
            DependsOn       = '[File]Netapps'
        }

         File SharePoint {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'D:\Netapps\SharePoint'
            DependsOn       = '[File]Netapps'
        }

        File EX2016 {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'D:\Netapps\EX2016'
            DependsOn       = '[File]Netapps'
        }

        File Netapps {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'D:\Netapps'
        }

        File Deployment {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'D:\Deployment'
        }

        File Profile {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'D:\Profile'
        }

        File Win10-1607 {
            Type = 'Directory'
            Ensure = 'Present'
            DestinationPath = 'D:\Profile\Win10-1607'
            DependsOn = '[File]Profile'
        }


        xSmbShare Netapps {
            Ensure      = 'Present'
            Name        = 'Netapps$'
            Path        = 'D:\Netapps'
            Description = 'Share urceny pro instalacni soubory'
            ReadAccess  = 'Authenticated Users'
            DependsOn   = '[File]Netapps'
        }

        cNtfsPermissionsInheritance NetApps {
            Path              = 'D:\NetApps'
            Enabled           = $false
            PreserveInherited = $false
            DependsOn         = '[File]NetApps'
        }

        cNtfsPermissionEntry NetApps {
            Ensure                   = 'Present'
            Path                     = 'D:\NetApps'
            Principal                = 'NT AUTHORITY\Authenticated Users'
            #ItemType                 = 'Directory'
            AccessControlInformation = @(
                cNtfsAccessControlInformation {
                    AccessControlType  = 'Allow'
                    FileSystemRights   = 'ReadAndExecute'
                    Inheritance        = 'ThisFolderSubfoldersAndFiles'
                    NoPropagateInherit = $false
                }
                cNtfsAccessControlInformation {
                    AccessControlType  = 'Allow'
                    FileSystemRights   = 'ListDirectory'
                    Inheritance        = 'ThisFolderSubfoldersAndFiles'
                    NoPropagateInherit = $false
                }
            )
            DependsOn                = '[File]NetApps'
        }

        cNtfsPermissionEntry NetApps_DomainAdmins {
            Ensure                   = 'Present'
            Path                     = 'D:\NetApps'
            Principal                = 'Domain Admins'
            #ItemType                 = 'Directory'
            AccessControlInformation = @(
                cNtfsAccessControlInformation {
                    AccessControlType  = 'Allow'
                    FileSystemRights   = 'FullControl'
                    Inheritance        = 'ThisFolderSubfoldersAndFiles'
                    NoPropagateInherit = $false
                }
                cNtfsAccessControlInformation {
                    AccessControlType  = 'Allow'
                    FileSystemRights   = 'ListDirectory'
                    Inheritance        = 'ThisFolderSubfoldersAndFiles'
                    NoPropagateInherit = $false
                }
            )
            DependsOn                = '[File]NetApps'
        }

        File Utils {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'D:\Utils'
        }

        xSmbShare Utils {
            Ensure      = 'Present'
            Name        = 'Utils$'
            Path        = 'D:\Utils'
            Description = 'Share urceny pro administratorske nastroje'
            FullAccess  = 'Authenticated Users'
            DependsOn   = '[File]Utils'
        }

        cNtfsPermissionsInheritance Utils {
            Path              = 'D:\Utils'
            Enabled           = $false
            PreserveInherited = $false
            DependsOn         = '[File]Utils'
        }

        cNtfsPermissionEntry Utils {
            Ensure                   = 'Present'
            Path                     = 'D:\Utils'
            Principal                = 'NT AUTHORITY\Authenticated Users'
            #ItemType                 = 'Directory'
            AccessControlInformation = @(
                cNtfsAccessControlInformation {
                    AccessControlType  = 'Allow'
                    FileSystemRights   = 'ReadAndExecute'
                    Inheritance        = 'ThisFolderSubfoldersAndFiles'
                    NoPropagateInherit = $false
                }
                cNtfsAccessControlInformation {
                    AccessControlType  = 'Allow'
                    FileSystemRights   = 'ListDirectory'
                    Inheritance        = 'ThisFolderSubfoldersAndFiles'
                    NoPropagateInherit = $false
                }
            )
            DependsOn                = '[File]Utils'
        }

        cNtfsPermissionEntry Utils_DomainAdmins {
            Ensure                   = 'Present'
            Path                     = 'D:\Utils'
            Principal                = 'Domain Admins'
            #ItemType                 = 'Directory'
            AccessControlInformation = @(
                cNtfsAccessControlInformation {
                    AccessControlType  = 'Allow'
                    FileSystemRights   = 'FullControl'
                    Inheritance        = 'ThisFolderSubfoldersAndFiles'
                    NoPropagateInherit = $false
                }

            )
            DependsOn                = '[File]Utils'
        }

        cNtfsPermissionEntry Utils_WSAdmins {
            Ensure                   = 'Present'
            Path                     = 'D:\Utils'
            Principal                = 'SG Admins'
            #ItemType                 = 'Directory'
            AccessControlInformation = @(
                cNtfsAccessControlInformation {
                    AccessControlType  = 'Allow'
                    FileSystemRights   = 'FullControl'
                    Inheritance        = 'ThisFolderSubfoldersAndFiles'
                    NoPropagateInherit = $false
                }
            )
            DependsOn                = '[File]Utils'
        }

        File Audits {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'D:\Audits'
        }

        File ICWSC {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'D:\Audits\ICWSC'
            DependsOn       = '[File]Audits'
        }

        File GP {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'D:\Audits\GP'
            DependsOn       = '[File]Audits'
        }

        File PowerShell_Transcripts {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'D:\Audits\Transcripts'
            DependsOn       = '[File]Audits'
        }


        xSmbShare Audits {
            Ensure      = 'Present'
            Name        = 'Audits$'
            Path        = 'D:\Audits'
            Description = 'Share urceny pro logy a auditni informace'
            FullAccess  = 'Authenticated Users'
            DependsOn   = '[File]Audits'
        }

        cNtfsPermissionsInheritance Audits {
            Path              = 'D:\Audits'
            Enabled           = $false
            PreserveInherited = $false
            DependsOn         = '[File]Audits'
        }

        cNtfsPermissionEntry Audits {
            Ensure                   = 'Present'
            Path                     = 'D:\Audits'
            Principal                = 'NT AUTHORITY\Authenticated Users'
            #ItemType                 = 'Directory'
            AccessControlInformation = @(
                cNtfsAccessControlInformation {
                    AccessControlType  = 'Allow'
                    FileSystemRights   = 'Write'
                    Inheritance        = 'ThisFolderSubfoldersAndFiles'
                    NoPropagateInherit = $false
                }
            )
            DependsOn                = '[File]Audits'
        }

        cNtfsPermissionEntry Audits_DomainAdmins {
            Ensure                   = 'Present'
            Path                     = 'D:\Audits'
            Principal                = 'Domain Admins'
            #ItemType                 = 'Directory'
            AccessControlInformation = @(
                cNtfsAccessControlInformation {
                    AccessControlType  = 'Allow'
                    FileSystemRights   = 'FullControl'
                    Inheritance        = 'ThisFolderSubfoldersAndFiles'
                    NoPropagateInherit = $false
                }

            )
            DependsOn                = '[File]Audits'
        }

        cNtfsPermissionEntry Audits_WSAdmins {
            Ensure                   = 'Present'
            Path                     = 'D:\Audits'
            Principal                = 'SG Admins'
            #ItemType                 = 'Directory'
            AccessControlInformation = @(
                cNtfsAccessControlInformation {
                    AccessControlType  = 'Allow'
                    FileSystemRights   = 'FullControl'
                    Inheritance        = 'ThisFolderSubfoldersAndFiles'
                    NoPropagateInherit = $false
                }
            )
            DependsOn                = '[File]Audits'
        }

        ##<Adresare
    }


Node $AllNodes.Where{
    $_.DomainJoin
  }.NodeName
  {
    ##<Domain Join

    xWaitForADDomain WaitForDomain
    {
      DomainName = $Node.DomainName
      DomainUserCredential = $domainCred
      RetryCount = 600
      RetryIntervalSec = 30
      RebootRetryCount = 10
    }

    xComputer DomainJoin
    {
      Name          = $Node.ComputerName
      DomainName    = $Node.DomainName
      Credential    = $domainCred
      JoinOU = $Node.DomainOUName
      description = $Node.Description
      DependsOn = '[xWaitForADDomain]WaitForDomain', '[Service]W32Time'

    }

    ##>Domain Join
  }

  Node $AllNodes.Where{
    $_.Packages
  }.NodeName
  {
    ##<SW Install
    foreach($Package in $Node.Packages)
    {
      Package $($Package.Name)
      {
        Name = $($Package.Name)
        Ensure = $($Package.Ensure)
        Path = $($Package.Path)
       #Credential = $domainCred
        ProductId = $($Package.ProductId)
        DependsOn = '[xComputer]DomainJoin'
        PsDscRunAsCredential = $domainCred

      }
    }

    ##>SW Install
  }
  
  Node $AllNodes.Where{
    $_.Role -contains 'SQLManagement'
  }.NodeName
  {
    Script SQLManagement {
            SetScript = {
            write-verbose "Installing SQL Server Management Tools"
            write-verbose "Executing SSMS-Setup-ENU.exe /install /quiet /norestart"
            Start-Process -FilePath '\\Citrix.local\dfs\NetApps\SQL_Management_Tools\SSMS-Setup-ENU.exe' -ArgumentList "/install /passive /norestart" -Wait -NoNewWindow
        }

        TestScript = {
       if ($((Get-Package).name) -contains 'SQL Server Management Studio') {
         Write-Verbose "SQL Server Management Tools Installed"
         return $true
        }
        else
        {
        Write-Verbose "SQL Server Management Tools not Installed"
        return $false
        }
        }

        GetScript = {
        if ($((Get-Package).name) -contains 'SQL Server Management Studio') {

        Write-Verbose "SQL Server Management Tools Installed OK"
        }
        else
        {
        Write-Verbose "SQL Server Management Tools not Installed"
        }
        }
    }
  }


  Node $AllNodes.Where{
    $_.Role -contains 'SQL'
  }.NodeName
  {
    ##<SQL

        xSQLServerSetup 'InstallCitrixInstance'
        {
            InstanceName         = 'Citrix'
            Features             = 'SQLENGINE,AS'
            SQLCollation         = 'SQL_Latin1_General_CP1_CI_AS'
            SQLSvcAccount        = $SqlCitrixCredential
            AgtSvcAccount        = $SqlCitrixCredential
            ASSvcAccount         = $SqlCitrixCredential
            SQLSysAdminAccounts  = 'Citrix\SG SQL Citrix'
            ASSysAdminAccounts   = 'Citrix\SG SQL Citrix'
            InstallSharedDir     = 'C:\Program Files\Microsoft SQL Server'
            InstallSharedWOWDir  = 'C:\Program Files (x86)\Microsoft SQL Server'
            InstanceDir          = 'D:\Citrix'
            InstallSQLDataDir    = 'D:\Citrix\Data'
            SQLUserDBDir         = 'D:\Citrix\Data'
            SQLUserDBLogDir      = 'D:\Citrix\Data'
            SQLTempDBDir         = 'D:\Citrix\Data'
            SQLTempDBLogDir      = 'D:\Citrix\Data'
            SQLBackupDir         = 'D:\Citrix\Backup'
            ASConfigDir          = 'D:\Citrix\AS\Config'
            ASDataDir            = 'D:\Citrix\AS\Data'
            ASLogDir             = 'D:\Citrix\AS\Log'
            ASBackupDir          = 'D:\Citrix\AS\Backup'
            ASTempDir            = 'D:\Citrix\AS\Temp'
            SourcePath           = '\\Citrix.local\dfs\NetApps\SQL2016'
            UpdateEnabled        = 'False'
            ForceReboot          = $true
            PsDscRunAsCredential = $domaincred
            DependsOn = '[xComputer]DomainJoin'
        }

         xSQLServerFirewall FWDCitrix
        {
            Ensure           = 'Present'
            Features         = 'SQLENGINE'
            InstanceName     = 'Citrix'
            SourcePath       = '\\Citrix.local\dfs\NetApps\SQL2016'
            SourceCredential = $domaincred
        }

        xSQLServerSetup 'InstallVMMInstance'
        {
            InstanceName         = 'VMM'
            Features             = 'SQLENGINE,AS'
            SQLCollation         = 'SQL_Latin1_General_CP1_CI_AS'
            SQLSvcAccount        = $SqlCitrixCredential
            AgtSvcAccount        = $SqlCitrixCredential
            ASSvcAccount         = $SqlCitrixCredential
            SQLSysAdminAccounts  = 'Citrix\SG SQL Citrix'
            ASSysAdminAccounts   = 'Citrix\SG SQL Citrix'
            InstallSharedDir     = 'C:\Program Files\Microsoft SQL Server'
            InstallSharedWOWDir  = 'C:\Program Files (x86)\Microsoft SQL Server'
            InstanceDir          = 'D:\VMM'
            InstallSQLDataDir    = 'D:\VMM\Data'
            SQLUserDBDir         = 'D:\VMM\Data'
            SQLUserDBLogDir      = 'D:\VMM\Data'
            SQLTempDBDir         = 'D:\VMM\Data'
            SQLTempDBLogDir      = 'D:\VMM\Data'
            SQLBackupDir         = 'D:\VMM\Backup'
            ASConfigDir          = 'D:\VMM\AS\Config'
            ASDataDir            = 'D:\VMM\AS\Data'
            ASLogDir             = 'D:\VMM\AS\Log'
            ASBackupDir          = 'D:\VMM\AS\Backup'
            ASTempDir            = 'D:\VMM\AS\Temp'
            SourcePath           = '\\Citrix.local\dfs\NetApps\SQL2016'
            UpdateEnabled        = 'False'
            ForceReboot          = $true
            PsDscRunAsCredential = $domaincred
            DependsOn = '[xComputer]DomainJoin'
        }

         xSQLServerFirewall FWDVMM
        {
            Ensure           = 'Present'
            Features         = 'SQLENGINE'
            InstanceName     = 'VMM'
            SourcePath       = '\\Citrix.local\dfs\NetApps\SQL2016'
            SourceCredential = $domaincred
        }
    ##>SQL
  }


  Node $AllNodes.Where{
    $_.WSH -eq $true
  }.NodeName
  {
    ##< WSH enabled
    Registry WSHEnabled
    {
      Ensure = 'Present'
      Key         = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Script Host\Settings'
      ValueName   = 'Enabled'
      ValueData   = '1'
      Force       = $true
      ValueType = 'Dword'
    }

    ##> WSH enabled
  }

  Node $AllNodes.Where{
    $_.WSH -eq $false
  }.NodeName
  {
    ##< WSH disabled
    Registry WSHDisabled
    {
      Ensure = 'Present'
      Key         = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Script Host\Settings'
      ValueName   = 'Enabled'
      ValueData   = '0'
      Force       = $true
      ValueType = 'Dword'
    }

    ##> WSH disabled
  }

  Node $AllNodes.Where{
    $_.ScheduledTasks
  }.NodeName
  {
       ###<Scheduled Tasks
       foreach($Task in $Node.ScheduledTasks)
       {
        xScheduledTask $($Task.TaskName)
         {
           TaskName = $($Task.TaskName)
           Ensure = $($Task.Ensure)
           ActionExecutable = $($Task.ActionExecutable)
           ActionArguments = $($Task.ActionArguments)
           ScheduleType = $($Task.ScheduleType)
           Description = $($Task.Description)
           
         }
       }
    ###>Scheduled Tasks
    }

  Node $AllNodes.Where{
    $_.Role -contains 'DHCP'
  }.NodeName
  {
    ###<DHCP
    <#bookmark DHCP #>
    #Neni nastavena rezervace do DNS pod konkretnim uctem
    WindowsFeature DHCP {
      DependsOn = '[xIPAddress]NewIpAddress'
      Name = 'DHCP'
      Ensure = 'PRESENT'
      IncludeAllSubFeature = $true

    }

    WindowsFeature DHCPTools
    {
      DependsOn = '[WindowsFeature]DHCP'
      Ensure = 'Present'
      Name = 'RSAT-DHCP'
      IncludeAllSubFeature = $true
    }

    foreach($DHCP in $Node.DHCP)
    {
      xDhcpServerScope $($DHCP.DHCPScopeName)
      {

        Ensure = 'Present'
        IPEndRange = $DHCP.DHCPRangeEnd
        IPStartRange = $DHCP.DHCPRangeStart
        Name = $DHCP.DHCPScopeName
        SubnetMask = $DHCP.DHCPSubnet
        LeaseDuration = '04.00:00:00'
        State = 'Active'
        AddressFamily = 'IPv4'
        DependsOn = '[WindowsFeature]DHCP'
        PsDscRunAsCredential = $domainCred

      }

      xDhcpServerOption $($DHCP.DHCPScopeName)
      {
        Ensure = 'Present'
        ScopeID = $DHCP.DHCPScopeID
        DnsDomain = $DHCP.DomainName
        DnsServerIPAddress = $DHCP.DHCPDNS
        AddressFamily = 'IPv4'
        Router = $DHCP.DHCPRouter
        DependsOn = "[xDhcpServerScope]$($DHCP.DHCPScopeName)"
        PsDscRunAsCredential = $domainCred
      }
    }

    xDhcpServerAuthorization DHCPAuthorization
    {
      Ensure = 'Present'
      PsDscRunAsCredential = $domainCred
      DependsOn = '[WindowsFeature]DHCP'
    }
    ###>DHCP
  }


  Node $AllNodes.Where{
    $_.Role -contains 'FirstDNS'
  }.NodeName
  {
    ###<DNS

    <#bookmark DNS #>

    WindowsFeature DNS {

      Name = 'DNS'
      Ensure = 'PRESENT'
      IncludeAllSubFeature = $true
      DependsOn = '[WindowsFeature]ADDSInstall'
    }

    xDnsServerADZone addReverseADZone
    {
      Name = $Node.DNSReverseZone
      DynamicUpdate = 'Secure'
      ReplicationScope = 'Forest'
      Ensure = 'Present'
      PsDscRunAsCredential = $domainCred
      DependsOn = '[WindowsFeature]DNS'

    }

    #   xDnsServerADZone addRootZone
    # {
    #   Name = '.'
    #   DynamicUpdate = 'Secure'
    #   ReplicationScope = 'Forest'
    #   Ensure = 'Present'
    #   PsDscRunAsCredential = $domainCred
    #   DependsOn = '[WindowsFeature]DNS'
    #
    # }

    Script SetDNSServerScavenging
    {
      SetScript =
      {
        Set-DnsServerScavenging -ScavengingState $true -RefreshInterval  7:00:00:00 -NoRefreshInterval 7:00:00:00 -ScavengingInterval 7:00:00:00 -ApplyOnAllZones
      }

      TestScript = {
        if ((Get-DnsServerScavenging).scavengingState)
        {
          return $true
        }
        else
        {
          return $false
        }
      }

      GetScript = {
        return @{
          Result = [string](Get-DnsServerScavenging).scavengingState
        }
      }
      DependsOn = '[xDnsServerADZone]addReverseADZone'
    }

    Script SetDNSRootHints
    {
      SetScript =
      {
        Get-DnsServerRootHint | Remove-DnsServerRootHint
      }

      TestScript = {
        if (Get-DnsServerRootHint)
        {
          return $false
        }
        else
        {
          return $true
        }
      }

      GetScript = {
        return @{
          Result = Get-DnsServerRootHint
        }
      }
      DependsOn = '[xDnsServerADZone]addReverseADZone'
    }

    foreach($Record in $Node.DNSRecords)
    {
      xDnsRecord $($Record.Name)
      {
        Ensure = $($Record.Ensure)
        Name = $($Record.Name)
        Type = $($Record.Type)
        Zone = $($Record.Zone)
        Target = $($Record.Target)
        DependsOn = '[xDnsServerADZone]addReverseADZone'
      }
    }

   
    ###>DNS
  }
  <#bookmark config #>
}


if (!($dcred)) {$dcred = Get-Credential -UserName Citrix\administrator -message 'Citrix.local administrator'}
if (!($defaultusercred)) {$defaultusercred = Get-Credential -UserName default -message 'defaul user creds'}
if (!($SqlCitrixCredential)) {$SqlCitrixCredential = Get-Credential -UserName "Citrix\SQLCitrixService" -message 'SQL Citrix Account'}

DSC-Citrix -configurationData 'D:\GitHub\DSC-Citrix\Config.psd1' -domainCred $dcred -safemodeAdministratorCred $dcred -defaultuserCred $defaultusercred -OutputPath D:\Hyper-V\Configurations\ -SqlCitrixCredential $SqlCitrixCredential
#-domainCred (Get-Credential -Message "New Domain Admin Credentials") -safemodeAdministratorCred (Get-Credential -Message "New Domain Safe Mode Admin Credentials")
#Set-DscLocalConfigurationManager -Path C:\Users\mica\Documents\Citrix_DSC -Verbose

