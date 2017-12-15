$Exists = test-path 'C:\Program Files\WindowsPowerShell\Modules\xWindowsEventForwarding\'
if (!$Exists) {
    mkdir 'C:\Program Files\WindowsPowerShell\Modules\xWindowsEventForwarding\'
    New-ModuleManifest -Path 'C:\Program Files\WindowsPowerShell\Modules\xWindowsEventForwarding\xWindowsEventForwarding.psd1' -Guid 'ab5e14f9-156e-49d2-ae1b-96576a929f3b' -CompanyName 'Microsoft Corporation' -Copyright 2015 -ModuleVersion '0.1.0.0' -Description 'This module can be used to manage configuration of a Windows Event Forwarding server in a Colelctor role.' -Author 'PowerShell Team' -PowerShellVersion '5.0'
    $SubscriptionID = New-xDscResourceProperty -Name SubscriptionID -Type String -Attribute Key -Description 'Name of the Subscription'
    $Ensure = New-xDscResourceProperty -Name Ensure -Type String -Attribute Write -ValidateSet 'Present','Absent' -Description 'Determines whether to validate or remove the scubscription'
    $SubscriptionType = New-xDscResourceProperty -Name SubscriptionType -Type String -Attribute Required -ValidateSet 'CollectorInitiated','SourceInitiated' -Description 'Type of Subscription to create'
    $Description = New-xDscResourceProperty -Name Description -Type String -Attribute Write -Description 'Description of the Collector subscription'
    $Enabled = New-xDscResourceProperty -Name Enabled -Type String -Attribute Write -ValidateSet 'true','false' -Description 'Sets whether the subscription will be enabled, default true'
    $DeliveryMode = New-xDscResourceProperty -Name DeliveryMode -Type String -Attribute Write -ValidateSet 'Push','Pull' -Description 'Configures whether the collector will pull events from source nodes or if the source nodes will push events to the collector, default push'
    $MaxItems = New-xDscResourceProperty -Name MaxItems -Type Sint32 -Attribute Write -Description 'The number of events that can occur on the source before they are submitted to the collector, default 1'
    $MaxLatencyTime = New-xDscResourceProperty -Name MaxLatencyTime -Type Uint64 -Attribute Write -Description 'The maximum amount of time that can pass before events are submitted to the collector, default 20000'
    $HeartBeatInterval = New-xDscResourceProperty -Name HeartBeatInterval -Type Uint64 -Attribute Write -Description 'Frequency to verify connectivity, default 20000'
    $ReadExistingEvents = New-xDscResourceProperty -Name ReadExistingEvents -Type String -Attribute Write -ValidateSet 'true','false' -Description 'Should the collector read existing or only new events, default false'
    $TransportName = New-xDscResourceProperty -Name TransportName -Type String -Attribute Write -ValidateSet 'HTTP','HTTPS' -Description 'Determines whether to require SSL, default HTTP'
    $TransportPort = New-xDscResourceProperty -Name TransportPort -Type String -Attribute Write -Description 'Set the port number that WinRM should use to make a connection, default 5985'
    $ContentFormat = New-xDscResourceProperty -Name ContentFormat -Type String -Attribute Write -Description 'Format that event logs will be submitted in, default RenderedText'
    $Locale = New-xDscResourceProperty -Name Locale -Type String -Attribute Write -Description 'Sets the subscription Locale, default en-US'
    $LogFile = New-xDscResourceProperty -Name LogFile -Type String -Attribute Write -Description 'Sets the event log that the collected events will be written to, default ForwardedEvents'
    $CredentialsType = New-xDscResourceProperty -Name CredentialsType -Type String -Attribute Write -ValidateSet 'Default','Basic','Negotiate','Digest' -Description 'Sets the credential type used for authenticating to WinRM, default Default'
    $AllowedSourceNonDomainComputers = New-xDscResourceProperty -Name AllowedSourceNonDomainComputers -Type String[] -Attribute Write -Description 'This parameter has not been fully implemented, only required for source initiated scenarios, provide XML to set IssuerCAList, AllowedSubjectList, or DeniedSubjectList if this will be used, default empty string'
    $AllowedSourceDomainComputers = New-xDscResourceProperty -Name AllowedSourceDomainComputers -Type String -Attribute Write -Description 'In Source Initiated scenario this SDDL determines who can push events, default O:NSG:NSD:(A;;GA;;;DC)(A;;GA;;;NS) which equates to Domain Computers and Network Service'
    $Query = New-xDscResourceProperty -Name Query -Type String[] -Attribute Write -Description 'Expects an array of hashtables that set which events should be collected, default is all application and system logs'
    $Address = New-xDscResourceProperty -Name Address -Type String[] -Attribute Write -Description 'Expects an array of source node FQDNs, default source.wef.test to prevent errors when only staging test subscription'
    New-xDscResource -Name MSFT_xWEFSubscription -Property $SubscriptionID, $Ensure, $SubscriptionType, $Description, $Enabled, $DeliveryMode, $MaxItems, $MaxLatencyTime, $HeartBeatInterval, $ReadExistingEvents, $TransportName, $TransportPort, $ContentFormat, $Locale, $LogFile, $CredentialsType, $AllowedSourceNonDomainComputers, $AllowedSourceDomainComputers, $Query, $Address -Path 'C:\Program Files\WindowsPowerShell\Modules\' -ModuleName xWindowsEventForwarding -ClassVersion '0.1.0.0' -FriendlyName 'xWEFSubscription' -Verbose
    $Ensure = New-xDscResourceProperty -Name Ensure -Type String -Attribute Write -ValidateSet 'Present','Absent' -Description 'Determines whether the Collector service should be enabled or disabled'
    $Name = New-xDscResourceProperty -Name Name -Type String -Attribute Key -Description 'Provide a unique name for the setting'
    New-xDscResource -Name MSFT_xWEFCollector -Property $Ensure, $Name -Path 'C:\Program Files\WindowsPowerShell\Modules\' -ModuleName xWindowsEventForwarding -ClassVersion '0.1.0.0' -FriendlyName 'xWEFCollector'
    }