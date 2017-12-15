function Install-CertificationAuthority {
<#
.ExternalHelp PSPKI.Help.xml
#>
[CmdletBinding(
	DefaultParameterSetName = 'NewKeySet',
	ConfirmImpact = 'High',
	SupportsShouldProcess = $true
)]
	param(
		[Parameter(ParameterSetName = 'NewKeySet')]
		[string]$CAName,
		[Parameter(ParameterSetName = 'NewKeySet')]
		[string]$CADNSuffix,
		[Parameter(ParameterSetName = 'NewKeySet')]
		[ValidateSet("Standalone Root","Standalone Subordinate","Enterprise Root","Enterprise Subordinate")]
		[string]$CAType,
		[Parameter(ParameterSetName = 'NewKeySet')]
		[string]$ParentCA,
		[Parameter(ParameterSetName = 'NewKeySet')]
		[string]$CSP,
		[Parameter(ParameterSetName = 'NewKeySet')]
		[int]$KeyLength,
		[Parameter(ParameterSetName = 'NewKeySet')]
		[string]$HashAlgorithm,
		[Parameter(ParameterSetName = 'NewKeySet')]
		[int]$ValidForYears = 5,
		[Parameter(ParameterSetName = 'NewKeySet')]
		[string]$RequestFileName,
		[Parameter(Mandatory = $true, ParameterSetName = 'PFXKeySet')]
		[IO.FileInfo]$CACertFile,
		[Parameter(Mandatory = $true, ParameterSetName = 'PFXKeySet')]
		[Security.SecureString]$Password,
		[Parameter(Mandatory = $true, ParameterSetName = 'ExistingKeySet')]
		[string]$Thumbprint,
		[string]$DBDirectory = $(Join-Path $env:SystemRoot "System32\CertLog"),
		[string]$LogDirectory = $(Join-Path $env:SystemRoot "System32\CertLog"),
		[switch]$OverwriteExisting,
		[switch]$AllowCSPInteraction,
		[switch]$Force
	)

#region OS and existing CA checking
	# check if script running on Windows Server 2008 or Windows Server 2008 R2
	$OS = Get-WmiObject Win32_OperatingSystem -Property ProductType
	if ([Environment]::OSVersion.Version.Major -lt 6) {
		Write-Error -Category NotImplemented -ErrorId "NotSupportedException" `
		-Message "Windows XP, Windows Server 2003 and Windows Server 2003 R2 are not supported!"
		return
	}
	if ($OS.ProductType -eq 1) {
		Write-Error -Category NotImplemented -ErrorId "NotSupportedException" `
		-Message "Client operating systems are not supported!"
		return
	}
	$CertConfig = New-Object -ComObject CertificateAuthority.Config
	try {$ExistingDetected = $CertConfig.GetConfig(3)}
	catch {}
	if ($ExistingDetected) {
		Write-Error -Category ResourceExists -ErrorId "ResourceExistsException" `
		-Message "Certificate Services are already installed on this computer. Only one Certification Authority instance per computer is supported."
		return
	}
	
#endregion

#region Binaries checking and installation if necessary
	if ([Environment]::OSVersion.Version.Major -eq 6 -and [Environment]::OSVersion.Version.Minor -eq 0) {
		cmd /c "servermanagercmd -install AD-Certificate 2> null" | Out-Null
	} else {
		try {Import-Module ServerManager -ErrorAction Stop}
		catch {
			ocsetup 'ServerManager-PSH-Cmdlets' /quiet | Out-Null
			Start-Sleep 1
			Import-Module ServerManager -ErrorAction Stop
		}
		$status = (Get-WindowsFeature -Name AD-Certificate).Installed
		# if still no, install binaries, otherwise do nothing
		if (!$status) {$retn = Add-WindowsFeature -Name AD-Certificate -ErrorAction Stop
			if (!$retn.Success) {
				Write-Error -Category NotInstalled -ErrorId "NotInstalledException" `
				-Message "Unable to install ADCS installation packages due of the following error: $($retn.breakCode)"
				return
			}
		}
	}
	try {$CASetup = New-Object -ComObject CertOCM.CertSrvSetup.1}
	catch {
		Write-Error -Category NotImplemented -ErrorId "NotImplementedException" `
		-Message "Unable to load necessary interfaces. Your Windows Server operating system is not supported!"
		return
	}
	# initialize setup binaries
	try {$CASetup.InitializeDefaults($true, $false)}
	catch {
		Write-Error -Category InvalidArgument -ErrorId ParameterIncorrectException `
		-ErrorAction Stop -Message "Cannot initialize setup binaries!"
	}
#endregion

#region Property enums
	$CATypesByName = @{"Enterprise Root" = 0; "Enterprise Subordinate" = 1; "Standalone Root" = 3; "Standalone Subordinate" = 4}
	$CATypesByVal = @{}
	$CATypesByName.keys | ForEach-Object {$CATypesByVal.Add($CATypesByName[$_],$_)}
	$CAPRopertyByName = @{"CAType"=0;"CAKeyInfo"=1;"Interactive"=2;"ValidityPeriodUnits"=5;
		"ValidityPeriod"=6;"ExpirationDate"=7;"PreserveDataBase"=8;"DBDirectory"=9;"Logdirectory"=10;
		"ParentCAMachine"=12;"ParentCAName"=13;"RequestFile"=14;"WebCAMachine"=15;"WebCAName"=16
	}
	$CAPRopertyByVal = @{}
	$CAPRopertyByName.keys | ForEach-Object {$CAPRopertyByVal.Add($CAPRopertyByName[$_],$_)}
	$ValidityUnitsByName = @{"years" = 6}
	$ValidityUnitsByVal = @{6 = "years"}
#endregion
	$ofs = ", "
#region Key set processing functions

#region NewKeySet
function NewKeySet ($CAName, $CADNSuffix, $CAType, $ParentCA, $CSP, $KeyLength, $HashAlgorithm, $ValidForYears, $RequestFileName, $AllowCSPInteraction) {

#region CSP, key length and hashing algorithm verification
	$CAKey = $CASetup.GetCASetupProperty(1)
	if ($AllowCSPInteraction) {$CASetup.SetCASetupProperty(0x2,$true)}
	if ($CSP -ne "") {
		if ($CASetup.GetProviderNameList() -notcontains $CSP) {
			# TODO add available CSP list
			Write-Error -Category InvalidArgument -ErrorId "InvalidCryptographicServiceProviderException" `
			-ErrorAction Stop -Message "Specified CSP '$CSP' is not valid!"
		} else {
			$CAKey.ProviderName = $CSP
		}
	} else {
		$CAKey.ProviderName = "RSA#Microsoft Software Key Storage Provider"
	}
	if ($KeyLength -ne 0) {
		if ($CASetup.GetKeyLengthList($CAKey.ProviderName).Length -eq 1) {
			$CAKey.Length = $CASetup.GetKeyLengthList($CAKey.ProviderName)[0]
		} else {
			if ($CASetup.GetKeyLengthList($CAKey.ProviderName) -notcontains $KeyLength) {
				Write-Error -Category InvalidArgument -ErrorId "InvalidKeyLengthException" `
				-ErrorAction Stop -Message @"
The specified key length '$KeyLength' is not supported by the selected CSP '$($CAKey.ProviderName)' The following
key lengths are supported by this CSP: $($CASetup.GetKeyLengthList($CAKey.ProviderName))
"@
			}
			$CAKey.Length = $KeyLength
		}
	}
	if ($HashAlgorithm -ne "") {
		if ($CASetup.GetHashAlgorithmList($CAKey.ProviderName) -notcontains $HashAlgorithm) {
				Write-Error -Category InvalidArgument -ErrorId "InvalidHashAlgorithmException" `
				-ErrorAction Stop -Message @"
The specified hash algorithm is not supported by the selected CSP '$($CAKey.ProviderName)' The following
hash algorithms are supported by this CSP: $($CASetup.GetHashAlgorithmList($CAKey.ProviderName))
"@
		}
		$CAKey.HashAlgorithm = $HashAlgorithm
	}
	$CASetup.SetCASetupProperty(1,$CAKey)
#endregion

#region Setting CA type
	if ($CAType) {
		$SupportedTypes = $CASetup.GetSupportedCATypes()
		$SelectedType = $CATypesByName[$CAType]
		if ($SupportedTypes -notcontains $CATypesByName[$CAType]) {
			Write-Error -Category InvalidArgument -ErrorId "InvalidCATypeException" `
			-ErrorAction Stop -Message @"
Selected CA type: '$CAType' is not supported by current Windows Server installation.
The following CA types are supported by this installation: $([int[]]$CASetup.GetSupportedCATypes() | %{$CATypesByVal[$_]})
"@
		} else {$CASetup.SetCASetupProperty($CAPRopertyByName.CAType,$SelectedType)}
	}
#endregion

#region setting CA certificate validity
	if ($SelectedType -eq 0 -or $SelectedType -eq 3 -and $ValidForYears -ne 0) {
		try{$CASetup.SetCASetupProperty(6,$ValidForYears)}
		catch {
			Write-Error -Category InvalidArgument -ErrorId "InvalidCAValidityException" `
			-ErrorAction Stop -Message "The specified CA certificate validity period '$ValidForYears' is invalid."
		}
	}
#endregion

#region setting CA name
	if ($CAName -ne "") {
		if ($CADNSuffix -ne "") {$Subject = "CN=$CAName" + ",$CADNSuffix"} else {$Subject = "CN=$CAName"}
		$DN = New-Object -ComObject X509Enrollment.CX500DistinguishedName
		# validate X500 name format
		try {$DN.Encode($Subject,0x0)}
		catch {
			Write-Error -Category InvalidArgument -ErrorId "InvalidX500NameException" `
			-ErrorAction Stop -Message "Specified CA name or CA name suffix is not correct X.500 Distinguished Name."
		}
		$CASetup.SetCADistinguishedName($Subject, $true, $true, $true)
	}
#endregion

#region set parent CA/request file properties
	if ($CASetup.GetCASetupProperty(0) -eq 1 -and $ParentCA) {
		[void]($ParentCA -match "^(.+)\\(.+)$")
		try {$CASetup.SetParentCAInformation($ParentCA)}
		catch {
			Write-Error -Category ObjectNotFound -ErrorId "ObjectNotFoundException" `
			-ErrorAction Stop -Message @"
The specified parent CA information '$ParentCA' is incorrect. Make sure if parent CA
information is correct (you must specify existing CA) and is supplied in a 'CAComputerName\CASanitizedName' form.
"@
		}
	} elseif ($CASetup.GetCASetupProperty(0) -eq 1 -or $CASetup.GetCASetupProperty(0) -eq 4 -and $RequestFileName -ne "") {
		$CASetup.SetCASetupProperty(14,$RequestFileName)
	}
#endregion
}

#endregion

#region PFXKeySet
function PFXKeySet ($CACertFile, $Password) {
	$FilePath = Resolve-Path $CACertFile -ErrorAction Stop
	try {[void]$CASetup.CAImportPFX(
		$FilePath.Path,
		[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)),
		$true)
	} catch {Write-Error $_ -ErrorAction Stop}
}
#endregion

#region ExistingKeySet
function ExistingKeySet ($Thumbprint) {
	$ExKeys = $CASetup.GetExistingCACertificates() | Where-Object {
		([Security.Cryptography.X509Certificates.X509Certificate2]$_.ExistingCACertificate).Thumbprint -eq $Thumbprint
	}
	if (!$ExKeys) {
		Write-Error -Category ObjectNotFound -ErrorId "ElementNotFoundException" `
		-ErrorAction Stop -Message "The system cannot find a valid CA certificate with thumbprint: $Thumbprint"
	} else {$CASetup.SetCASetupProperty(1,@($ExKeys)[0])}
}
#endregion

#endregion

#region set database settings
	if ($DBDirectory -ne "" -and $LogDirectory -ne "") {
		try {$CASetup.SetDatabaseInformation($DBDirectory,$LogDirectory,$null,$OverwriteExisting)}
		catch {
			Write-Error -Category InvalidArgument -ErrorId "InvalidPathException" `
			-ErrorAction Stop -Message "Specified path to either database directory or log directory is invalid."
		}
	} elseif ($DBDirectory -ne "" -and $LogDirectory -eq "") {
		Write-Error -Category InvalidArgument -ErrorId "InvalidPathException" `
		-ErrorAction Stop -Message "CA Log file directory cannot be empty."
	} elseif ($DBDirectory -eq "" -and $LogDirectory -ne "") {
		Write-Error -Category InvalidArgument -ErrorId "InvalidPathException" `
		-ErrorAction Stop -Message "CA database directory cannot be empty."
	}

#endregion
	# process parametersets.
	switch ($PSCmdlet.ParameterSetName) {
		"ExistingKeySet" {ExistingKeySet $Thumbprint}
		"PFXKeySet" {PFXKeySet $CACertFile $Password}
		"NewKeySet" {NewKeySet $CAName $CADNSuffix $CAType $ParentCA $CSP $KeyLength $HashAlgorithm $ValidForYears $RequestFileName $AllowCSPInteraction}
	}
	try {
		Write-Host "Installing Certification Authority role on $env:computername ..." -ForegroundColor Cyan
		if ($Force -or $PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Install Certification Authority")) {
			$CASetup.Install()
			$PostRequiredMsg = @"
Certification Authority role was successfully installed, but not completed. To complete installation submit
request file '$($CASetup.GetCASetupProperty(14))' to parent Certification Authority
and install issued certificate by running the following command: certutil -installcert 'PathToACertFile'
"@
			if ($CASetup.GetCASetupProperty(0) -eq 1 -and $ParentCA -eq "") {
				Write-Host $PostRequiredMsg -ForegroundColor Yellow -BackgroundColor Black
			} elseif ($CASetup.GetCASetupProperty(0) -eq 1 -and $PSCmdlet.ParameterSetName -eq "NewKeySet" -and $ParentCA -ne "") {
				$CASName = (Get-ItemProperty HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration).Active
				$SetupStatus = (Get-ItemProperty HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration\$CASName).SetupStatus
				$RequestID = (Get-ItemProperty HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration\$CASName).RequestID
				if ($SetupStatus -ne 1) {
					Write-Host $PostRequiredMsg -ForegroundColor Yellow -BackgroundColor Black
				}
			} elseif ($CASetup.GetCASetupProperty(0) -eq 4) {
				Write-Host $PostRequiredMsg -ForegroundColor Yellow -BackgroundColor Black
			} else {Write-Host "Certification Authority role is successfully installed!" -ForegroundColor Green}
		}
	} catch {Write-Error $_ -ErrorAction Stop}
	Remove-Module ServerManager -ErrorAction SilentlyContinue
}
# SIG # Begin signature block
# MIIX1gYJKoZIhvcNAQcCoIIXxzCCF8MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDjitbJylaZViXr
# eg+0PwSAFltS4f+FgK80Zexul+fv2KCCEuQwggPuMIIDV6ADAgECAhB+k+v7fMZO
# WepLmnfUBvw7MA0GCSqGSIb3DQEBBQUAMIGLMQswCQYDVQQGEwJaQTEVMBMGA1UE
# CBMMV2VzdGVybiBDYXBlMRQwEgYDVQQHEwtEdXJiYW52aWxsZTEPMA0GA1UEChMG
# VGhhd3RlMR0wGwYDVQQLExRUaGF3dGUgQ2VydGlmaWNhdGlvbjEfMB0GA1UEAxMW
# VGhhd3RlIFRpbWVzdGFtcGluZyBDQTAeFw0xMjEyMjEwMDAwMDBaFw0yMDEyMzAy
# MzU5NTlaMF4xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3Jh
# dGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGltZSBTdGFtcGluZyBTZXJ2aWNlcyBD
# QSAtIEcyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsayzSVRLlxwS
# CtgleZEiVypv3LgmxENza8K/LlBa+xTCdo5DASVDtKHiRfTot3vDdMwi17SUAAL3
# Te2/tLdEJGvNX0U70UTOQxJzF4KLabQry5kerHIbJk1xH7Ex3ftRYQJTpqr1SSwF
# eEWlL4nO55nn/oziVz89xpLcSvh7M+R5CvvwdYhBnP/FA1GZqtdsn5Nph2Upg4XC
# YBTEyMk7FNrAgfAfDXTekiKryvf7dHwn5vdKG3+nw54trorqpuaqJxZ9YfeYcRG8
# 4lChS+Vd+uUOpyyfqmUg09iW6Mh8pU5IRP8Z4kQHkgvXaISAXWp4ZEXNYEZ+VMET
# fMV58cnBcQIDAQABo4H6MIH3MB0GA1UdDgQWBBRfmvVuXMzMdJrU3X3vP9vsTIAu
# 3TAyBggrBgEFBQcBAQQmMCQwIgYIKwYBBQUHMAGGFmh0dHA6Ly9vY3NwLnRoYXd0
# ZS5jb20wEgYDVR0TAQH/BAgwBgEB/wIBADA/BgNVHR8EODA2MDSgMqAwhi5odHRw
# Oi8vY3JsLnRoYXd0ZS5jb20vVGhhd3RlVGltZXN0YW1waW5nQ0EuY3JsMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQEAwIBBjAoBgNVHREEITAfpB0wGzEZ
# MBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtMTANBgkqhkiG9w0BAQUFAAOBgQADCZuP
# ee9/WTCq72i1+uMJHbtPggZdN1+mUp8WjeockglEbvVt61h8MOj5aY0jcwsSb0ep
# rjkR+Cqxm7Aaw47rWZYArc4MTbLQMaYIXCp6/OJ6HVdMqGUY6XlAYiWWbsfHN2qD
# IQiOQerd2Vc/HXdJhyoWBl6mOGoiEqNRGYN+tjCCBKMwggOLoAMCAQICEA7P9DjI
# /r81bgTYapgbGlAwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxHTAbBgNV
# BAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTAwLgYDVQQDEydTeW1hbnRlYyBUaW1l
# IFN0YW1waW5nIFNlcnZpY2VzIENBIC0gRzIwHhcNMTIxMDE4MDAwMDAwWhcNMjAx
# MjI5MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29y
# cG9yYXRpb24xNDAyBgNVBAMTK1N5bWFudGVjIFRpbWUgU3RhbXBpbmcgU2Vydmlj
# ZXMgU2lnbmVyIC0gRzQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCi
# Yws5RLi7I6dESbsO/6HwYQpTk7CY260sD0rFbv+GPFNVDxXOBD8r/amWltm+YXkL
# W8lMhnbl4ENLIpXuwitDwZ/YaLSOQE/uhTi5EcUj8mRY8BUyb05Xoa6IpALXKh7N
# S+HdY9UXiTJbsF6ZWqidKFAOF+6W22E7RVEdzxJWC5JH/Kuu9mY9R6xwcueS51/N
# ELnEg2SUGb0lgOHo0iKl0LoCeqF3k1tlw+4XdLxBhircCEyMkoyRLZ53RB9o1qh0
# d9sOWzKLVoszvdljyEmdOsXF6jML0vGjG/SLvtmzV4s73gSneiKyJK4ux3DFvk6D
# Jgj7C72pT5kI4RAocqrNAgMBAAGjggFXMIIBUzAMBgNVHRMBAf8EAjAAMBYGA1Ud
# JQEB/wQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQEAwIHgDBzBggrBgEFBQcBAQRn
# MGUwKgYIKwYBBQUHMAGGHmh0dHA6Ly90cy1vY3NwLndzLnN5bWFudGVjLmNvbTA3
# BggrBgEFBQcwAoYraHR0cDovL3RzLWFpYS53cy5zeW1hbnRlYy5jb20vdHNzLWNh
# LWcyLmNlcjA8BgNVHR8ENTAzMDGgL6AthitodHRwOi8vdHMtY3JsLndzLnN5bWFu
# dGVjLmNvbS90c3MtY2EtZzIuY3JsMCgGA1UdEQQhMB+kHTAbMRkwFwYDVQQDExBU
# aW1lU3RhbXAtMjA0OC0yMB0GA1UdDgQWBBRGxmmjDkoUHtVM2lJjFz9eNrwN5jAf
# BgNVHSMEGDAWgBRfmvVuXMzMdJrU3X3vP9vsTIAu3TANBgkqhkiG9w0BAQUFAAOC
# AQEAeDu0kSoATPCPYjA3eKOEJwdvGLLeJdyg1JQDqoZOJZ+aQAMc3c7jecshaAba
# tjK0bb/0LCZjM+RJZG0N5sNnDvcFpDVsfIkWxumy37Lp3SDGcQ/NlXTctlzevTcf
# Q3jmeLXNKAQgo6rxS8SIKZEOgNER/N1cdm5PXg5FRkFuDbDqOJqxOtoJcRD8HHm0
# gHusafT9nLYMFivxf1sJPZtb4hbKE4FtAC44DagpjyzhsvRaqQGvFZwsL0kb2yK7
# w/54lFHDhrGCiF3wPbRRoXkzKy57udwgCRNx62oZW8/opTBXLIlJP7nPf8m/PiJo
# Y1OavWl0rMUdPH+S4MO8HNgEdTCCBRMwggP7oAMCAQICEAGfcm2O2qyxDgPgWB72
# KpowDQYJKoZIhvcNAQELBQAwcjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lD
# ZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8GA1UEAxMoRGln
# aUNlcnQgU0hBMiBBc3N1cmVkIElEIENvZGUgU2lnbmluZyBDQTAeFw0xNTEyMTgw
# MDAwMDBaFw0xNjEyMjIxMjAwMDBaMFAxCzAJBgNVBAYTAkxWMQ0wCwYDVQQHEwRS
# aWdhMRgwFgYDVQQKEw9TeXNhZG1pbnMgTFYgSUsxGDAWBgNVBAMTD1N5c2FkbWlu
# cyBMViBJSzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOhRW+I+23Aa
# e7xYARsDbO9iPf54kvGula1yiS/JkAsR3yF/ubX3IIiu4KEHdvcKzO04yOBX5rgy
# g80SMx2dsVWy076cLFuH8nVboCuOoQhphfofhkk3B8UPtLbYk14odbv9n/+N2w9J
# NG9K6Ba4YXOLHQPF19MMBO6rXQnqK+LVOT0Nkmkx8QoyfPrN7bhR8lQVfVfFxt4O
# BN0rad3VEYAwqfFhCGfgbO/5Otsslaz3vpotH+0ny13hSq2Ur8ETQ8FLcbtdvh02
# Obh7WdUXPsU1/oOpBDfhkOT5eBVVAg3E1sHZaaQ4wQkVfYbf4Xnf13hXoR9EAXT6
# /VT05+bWbpMCAwEAAaOCAcUwggHBMB8GA1UdIwQYMBaAFFrEuXsqCqOl6nEDwGD5
# LfZldQ5YMB0GA1UdDgQWBBT/cEXZqgVC/msreM/XBbwjW3+6gzAOBgNVHQ8BAf8E
# BAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwdwYDVR0fBHAwbjA1oDOgMYYvaHR0
# cDovL2NybDMuZGlnaWNlcnQuY29tL3NoYTItYXNzdXJlZC1jcy1nMS5jcmwwNaAz
# oDGGL2h0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9zaGEyLWFzc3VyZWQtY3MtZzEu
# Y3JsMEwGA1UdIARFMEMwNwYJYIZIAYb9bAMBMCowKAYIKwYBBQUHAgEWHGh0dHBz
# Oi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwCAYGZ4EMAQQBMIGEBggrBgEFBQcBAQR4
# MHYwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBOBggrBgEF
# BQcwAoZCaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0U0hBMkFz
# c3VyZWRJRENvZGVTaWduaW5nQ0EuY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcN
# AQELBQADggEBAFGo/QXI8xd2YZ/gL65sh4dJ4VFy6dLqQV3KiSfy0oocWoC95rxA
# KZ0Wow9NN63RYr/Y7xGKKxxYAMNubIdML0ow06595pta00JvDBoF6DTGKvx6jZ15
# fUlVZ+OLhl3AdOWolHmGcIz6LWIPrTNY7Hv7xYAXq2gKzk7X4IOq3k+G+/RF7RjX
# sN4VZ7001qc53L+35ylO4lmZfdNHl2FFklMxlmdN3OLipNYgBpFfib99R6Ep8HB3
# mnOhnCVnREL/lGdEyl1S1qeTAo92tKMs9I5snAPDGhm9nCkAqHCbXBrj1G/VseD+
# vT3QisKWcBQDo6zU8kBhFYxTxrIwxC4zj3owggUwMIIEGKADAgECAhAECRgbX9W7
# ZnVTQ7VvlVAIMA0GCSqGSIb3DQEBCwUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0xMzEwMjIxMjAwMDBa
# Fw0yODEwMjIxMjAwMDBaMHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNVBAMTKERpZ2lD
# ZXJ0IFNIQTIgQXNzdXJlZCBJRCBDb2RlIFNpZ25pbmcgQ0EwggEiMA0GCSqGSIb3
# DQEBAQUAA4IBDwAwggEKAoIBAQD407Mcfw4Rr2d3B9MLMUkZz9D7RZmxOttE9X/l
# qJ3bMtdx6nadBS63j/qSQ8Cl+YnUNxnXtqrwnIal2CWsDnkoOn7p0WfTxvspJ8fT
# eyOU5JEjlpB3gvmhhCNmElQzUHSxKCa7JGnCwlLyFGeKiUXULaGj6YgsIJWuHEqH
# CN8M9eJNYBi+qsSyrnAxZjNxPqxwoqvOf+l8y5Kh5TsxHM/q8grkV7tKtel05iv+
# bMt+dDk2DZDv5LVOpKnqagqrhPOsZ061xPeM0SAlI+sIZD5SlsHyDxL0xY4PwaLo
# LFH3c7y9hbFig3NBggfkOItqcyDQD2RzPJ6fpjOp/RnfJZPRAgMBAAGjggHNMIIB
# yTASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAK
# BggrBgEFBQcDAzB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9v
# Y3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDCBgQYDVR0fBHow
# eDA6oDigNoY0aHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJl
# ZElEUm9vdENBLmNybDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0Rp
# Z2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDBPBgNVHSAESDBGMDgGCmCGSAGG/WwA
# AgQwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAK
# BghghkgBhv1sAzAdBgNVHQ4EFgQUWsS5eyoKo6XqcQPAYPkt9mV1DlgwHwYDVR0j
# BBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8wDQYJKoZIhvcNAQELBQADggEBAD7s
# DVoks/Mi0RXILHwlKXaoHV0cLToaxO8wYdd+C2D9wz0PxK+L/e8q3yBVN7Dh9tGS
# dQ9RtG6ljlriXiSBThCk7j9xjmMOE0ut119EefM2FAaK95xGTlz/kLEbBw6RFfu6
# r7VRwo0kriTGxycqoSkoGjpxKAI8LpGjwCUR4pwUR6F6aGivm6dcIFzZcbEMj7uo
# +MUSaJ/PQMtARKUT8OZkDCUIQjKyNookAv4vcn4c10lFluhZHen6dGRrsutmQ9qz
# sIzV6Q3d9gEgzpkxYz0IGhizgZtPxpMQBvwHgfqL2vmCSfdibqFT+hKUGIUukpHq
# aGxEMrJmoecYpJpkUe8xggRIMIIERAIBATCBhjByMQswCQYDVQQGEwJVUzEVMBMG
# A1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMTEw
# LwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQgQ29kZSBTaWduaW5nIENB
# AhABn3JtjtqssQ4D4Fge9iqaMA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcC
# AQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYB
# BAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINIZ2YbAgNwd
# C48yC+1tnVBT4BCDUqRsL4R/qMqtrR3TMA0GCSqGSIb3DQEBAQUABIIBAAAMALW7
# QGU5b6MOZmFsJjVw3SXJEhr/2sxC/tugyMf/xSKy5jYcwh3g6dY8i7jqDWANVH+u
# nyVbf+gV8e31fLhP2rBsNHsOY16odxvUy6oLOAFYy3qBuCcMMWx3GneU8yE/k4/3
# YuE6XaA3XnWUClsMS+F9BaZ3ZZq+h2oqZ1BFP/apquMlLk6Vfg47C2DZz4AovKYY
# j+EWF8aP5nRXpwuPwNyUpJ4qEMSofQH2mPeDd04MiIc/bG4LIY0st+5dD9xRP3dv
# rfQ0I6BduQdmH/qGZkT4QB80r3U+5Ek4Yam0yieYfLvznAdyayKtzA9UvE4UU1cl
# /GYRGyGArxvdzHihggILMIICBwYJKoZIhvcNAQkGMYIB+DCCAfQCAQEwcjBeMQsw
# CQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xMDAuBgNV
# BAMTJ1N5bWFudGVjIFRpbWUgU3RhbXBpbmcgU2VydmljZXMgQ0EgLSBHMgIQDs/0
# OMj+vzVuBNhqmBsaUDAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3
# DQEHATAcBgkqhkiG9w0BCQUxDxcNMTYwODA3MTgwNDQxWjAjBgkqhkiG9w0BCQQx
# FgQUaCBVPmss6IMLJKDsKHhm4Nidm4owDQYJKoZIhvcNAQEBBQAEggEAGz2SeYtg
# TCbumMpRXDMKKzoIc9ZBN64LcR73LkxtyQV2OFEoKZvilJp06/BxoezbbCG071w/
# 5em9nIHIqBId0El2UOf0rRUguAGjdCCZKKPaDSZsQB/33no/las6B2f/8LiaG9Ts
# Cc2FY+XsVnMf4h5bw+z45UERpqiA0YPltjCuGlcbQijhwhFFDznGlGARGXwkSYy8
# hoDvtEXNjwlm6rbrK2Fs8qfgnDRIO87iXpy6EU2PVtin4Sri9ljlUnC1zqkfDzgA
# ADqLtn6jzgqd47xDU3jrlVUKb5te18qxR8X1Y0h1XEp/WcQM5eJbElVuNfSKJkqB
# kAqDKYLr6f8FjA==
# SIG # End signature block
