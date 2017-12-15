Clear-Host
$ConfigData = @{
    AllNodes = @(
        @{
            NodeName = 'DC';
            Lability_ProcessorCount = 2;
            Lability_StartupMemory   = 4GB;
            Lability_SwitchName = 'citrix';
            Lability_Media = '2016_x64_Standard_EN_14393.1715';
            Lability_CustomBootStrap = @"
                Set-Item WSMan:\localhost\MaxEnvelopeSizekb 10000
                Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine -Force
                Enable-PSRemoting -SkipNetworkProfileCheck -Force
                New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\TcpIp\Parameters\' -Name 'ArpRetryCount' -PropertyType DWORD -Value '1' -Force
                New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\TcpIp\Parameters\' -Name 'ArpRetryCount' -PropertyType DWORD -Value '1' -Force
                get-disk | set-disk -IsOffline $false
                Get-Disk | Where partitionstyle -eq 'raw' |Initialize-Disk -PartitionStyle GPT -PassThru |New-Partition -UseMaximumSize |Set-Partition -NewDriveLetter D
                Format-Volume D -FileSystem NTFS
"@
        },
        @{
            NodeName = 'SQL';
            Lability_ProcessorCount = 2;
            Lability_SwitchName = 'citrix';
           Lability_StartupMemory  = 4GB;
            Lability_Media = '2016_x64_Standard_EN_14393.1715';
             Lability_CustomBootStrap = @"
                Set-Item WSMan:\localhost\MaxEnvelopeSizekb 10000
                Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine -Force
                Enable-PSRemoting -SkipNetworkProfileCheck -Force
                Enable-LocalUser Administrator
                New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\TcpIp\Parameters\' -Name 'ArpRetryCount' -PropertyType DWORD -Value '1' -Force
                New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\TcpIp\Parameters\' -Name 'ArpRetryCount' -PropertyType DWORD -Value '1' -Force
                get-disk | set-disk -IsOffline $false
                Get-Disk | Where partitionstyle -eq 'raw' |Initialize-Disk -PartitionStyle GPT -PassThru |New-Partition -UseMaximumSize |Set-Partition -NewDriveLetter D
                Format-Volume D -FileSystem NTFS
"@
        },
        @{
            NodeName = 'Hyperv';
            Lability_ProcessorCount = 2;
            Lability_SwitchName = 'citrix';
           Lability_StartupMemory  = 8GB;
            Lability_Media = '2016_x64_Standard_EN_14393.1715';
             Lability_CustomBootStrap = @"
                Set-Item WSMan:\localhost\MaxEnvelopeSizekb 10000
                Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine -Force
                Enable-PSRemoting -SkipNetworkProfileCheck -Force
                Enable-LocalUser Administrator
                New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\TcpIp\Parameters\' -Name 'ArpRetryCount' -PropertyType DWORD -Value '1' -Force
                New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\TcpIp\Parameters\' -Name 'ArpRetryCount' -PropertyType DWORD -Value '1' -Force
                get-disk | set-disk -IsOffline $false
                Get-Disk | Where partitionstyle -eq 'raw' |Initialize-Disk -PartitionStyle GPT -PassThru |New-Partition -UseMaximumSize |Set-Partition -NewDriveLetter D
                Format-Volume D -FileSystem NTFS
"@
        },
        @{
            NodeName = 'Citrix';
            Lability_ProcessorCount = 2;
            Lability_SwitchName = 'citrix';
           Lability_StartupMemory  = 4GB;
            Lability_Media = '2016_x64_Standard_EN_14393.1715';
             Lability_CustomBootStrap = @"
                Set-Item WSMan:\localhost\MaxEnvelopeSizekb 10000
                Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine -Force
                Enable-PSRemoting -SkipNetworkProfileCheck -Force
                Enable-LocalUser Administrator
                New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\TcpIp\Parameters\' -Name 'ArpRetryCount' -PropertyType DWORD -Value '1' -Force
                get-disk | set-disk -IsOffline $false
                New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\TcpIp\Parameters\' -Name 'ArpRetryCount' -PropertyType DWORD -Value '1' -Force
                get-disk | set-disk -IsOffline $false
                Get-Disk | Where partitionstyle -eq 'raw' |Initialize-Disk -PartitionStyle GPT -PassThru |New-Partition -UseMaximumSize |Set-Partition -NewDriveLetter D
                Format-Volume D -FileSystem NTFS
"@
        },
        @{
            NodeName = 'VMM';
            Lability_ProcessorCount = 2;
            Lability_SwitchName = 'citrix';
           Lability_StartupMemory  = 4GB;
            Lability_Media = '2016_x64_Standard_EN_14393.1715';
             Lability_CustomBootStrap = @'
                Set-Item WSMan:\localhost\MaxEnvelopeSizekb 10000
                Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine -Force
                Enable-PSRemoting -SkipNetworkProfileCheck -Force
                Enable-LocalUser Administrator
                New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\TcpIp\Parameters\' -Name 'ArpRetryCount' -PropertyType DWORD -Value '1' -Force
                New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\TcpIp\Parameters\' -Name 'ArpRetryCount' -PropertyType DWORD -Value '1' -Force
                get-disk | set-disk -IsOffline $false
                Get-Disk | Where partitionstyle -eq 'raw' |Initialize-Disk -PartitionStyle GPT -PassThru |New-Partition -UseMaximumSize |Set-Partition -NewDriveLetter D
                Format-Volume D -FileSystem NTFS
'@
        
        }
        
        
    )
    NonNodeData = @{
        Lability = @{
            Network = @(
                @{ Name = 'Citrix'; Type = 'Private'; }
            )
        }
    }
}

Start-LabConfiguration -ConfigurationData $ConfigData -IgnorePendingReboot -Force -SkipMofCheck -NoSnapshot

$vhdxpath = (get-vm DC).harddrives.Path|select -First 1|Split-Path

#### vytvoreni disku
foreach ($node in $ConfigData.AllNodes.NodeName){

#New-VHD -Path $($vhdxpath + '\' + "$node" + '_D.vhdx') -Dynamic -SizeBytes 100GB
Add-VMHardDiskDrive -vmname $node -Path $($vhdxpath + '\' + "$node" + '_D.vhdx')
}


#$ConfigData.AllNodes.nodename | foreach {Set-VMMemory $_ -DynamicMemoryEnabled $true -MinimumBytes 2GB -MaximumBytes 4GB}

Start-VM DC


#Start-Lab $ConfigData

#stop-lab $ConfigData
#Remove-LabConfiguration $ConfigData
#remove-item $vhdxpath\vxxxxxxx1citrixx100_D.vhdx
#remove-item $vhdxpath\vxxxxxxx1citrixx130_D.vhdx

#checkpoint-lab $ConfigData
