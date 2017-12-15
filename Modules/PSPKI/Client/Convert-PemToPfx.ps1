function Convert-PemToPfx {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('[System.Security.Cryptography.X509Certificates.X509Certificate2]')]
[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true, Position = 0)]
		[string]$InputPath,
		[string]$KeyPath,
		[string]$OutputPath,
		[Security.Cryptography.X509Certificates.X509KeySpecFlags]$KeySpec = "AT_KEYEXCHANGE",
		[Security.SecureString]$Password,
		[string]$ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider",
		[Security.Cryptography.X509Certificates.StoreLocation]$StoreLocation = "CurrentUser",
		[switch]$Install
	)
	if ($PSBoundParameters.Verbose) {$VerbosePreference = "continue"}
	if ($PSBoundParameters.Debug) {
		$Host.PrivateData.DebugForegroundColor = "Cyan"
		$DebugPreference = "continue"
	}
	
	#region helper functions
	function __normalizeAsnInteger ($array) {
        $padding = $array.Length % 8
        if ($padding) {
            $array = $array[$padding..($array.Length - 1)]
        }
        [array]::Reverse($array)
        [Byte[]]$array
    }
	function __extractCert([string]$Text) {
		if ($Text -match "(?msx).*-{5}BEGIN\sCERTIFICATE-{5}(.+)-{5}END\sCERTIFICATE-{5}") {
		$keyFlags = [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
		if ($Install) {
			$keyFlags += if ($StoreLocation -eq "CurrentUser") {
				[Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet
			} else {
				[Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet
			}
		}
		$RawData = [Convert]::FromBase64String($matches[1])
			try {
				New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $RawData, "", $keyFlags
			} catch {throw "The data is not valid security certificate."}
			Write-Debug "X.509 certificate is correct."
		} else {throw "Missing certificate file."}
	}
	# returns [byte[]]
	function __composePRIVATEKEYBLOB($modulus, $PublicExponent, $PrivateExponent, $Prime1, $Prime2, $Exponent1, $Exponent2, $Coefficient) {
		Write-Debug "Calculating key length."
		$bitLen = "{0:X4}" -f $($modulus.Length * 8)
		Write-Debug "Key length is $($modulus.Length * 8) bits."
		[byte[]]$bitLen1 = Invoke-Expression 0x$([int]$bitLen.Substring(0,2))
		[byte[]]$bitLen2 = Invoke-Expression 0x$([int]$bitLen.Substring(2,2))
		[Byte[]]$PrivateKey = 0x07,0x02,0x00,0x00,0x00,0x24,0x00,0x00,0x52,0x53,0x41,0x32,0x00
		[Byte[]]$PrivateKey = $PrivateKey + $bitLen1 + $bitLen2 + $PublicExponent + ,0x00 + `
			$modulus + $Prime1 + $Prime2 + $Exponent1 + $Exponent2 + $Coefficient + $PrivateExponent
		$PrivateKey
	}
	# returns RSACryptoServiceProvider for dispose purposes
	function __attachPrivateKey($Cert, [Byte[]]$PrivateKey) {
		$cspParams = New-Object Security.Cryptography.CspParameters -Property @{
			ProviderName = $ProviderName
			KeyContainerName = "pspki-" + [Guid]::NewGuid().ToString()
			KeyNumber = [int]$KeySpec
		}
		if ($Install -and $StoreLocation -eq "LocalMachine") {
			$cspParams.Flags += [Security.Cryptography.CspProviderFlags]::UseMachineKeyStore
		}
		$rsa = New-Object Security.Cryptography.RSACryptoServiceProvider $cspParams
		$rsa.ImportCspBlob($PrivateKey)
		$Cert.PrivateKey = $rsa
		$rsa
	}
	# returns Asn1Reader
	function __decodePkcs1($base64) {
		Write-Debug "Processing PKCS#1 RSA KEY module."
		$asn = New-Object SysadminsLV.Asn1Parser.Asn1Reader @(,[Convert]::FromBase64String($base64))
		if ($asn.Tag -ne 48) {throw "The data is invalid."}
		$asn
	}
	# returns Asn1Reader
	function __decodePkcs8($base64) {
		Write-Debug "Processing PKCS#8 Private Key module."
		$asn = New-Object SysadminsLV.Asn1Parser.Asn1Reader @(,[Convert]::FromBase64String($base64))
		if ($asn.Tag -ne 48) {throw "The data is invalid."}
		# version
		if (!$asn.MoveNext()) {throw "The data is invalid."}
		# algorithm identifier
		if (!$asn.MoveNext()) {throw "The data is invalid."}
		# octet string
		if (!$asn.MoveNextCurrentLevel()) {throw "The data is invalid."}
		if ($asn.Tag -ne 4) {throw "The data is invalid."}
		if (!$asn.MoveNext()) {throw "The data is invalid."}
		$asn
	}
	#endregion
	$ErrorActionPreference = "Stop"
	
	$File = Get-Item $InputPath -Force -ErrorAction Stop
	if ($KeyPath) {$Key = Get-Item $KeyPath -Force -ErrorAction Stop}
	
	# parse content
	$Text = Get-Content -Path $InputPath -Raw -ErrorAction Stop
	Write-Debug "Extracting certificate information..."
	$Cert = __extractCert $Text
	if ($Key) {$Text = Get-Content -Path $KeyPath -Raw -ErrorAction Stop}
	$asn = if ($Text -match "(?msx).*-{5}BEGIN\sPRIVATE\sKEY-{5}(.+)-{5}END\sPRIVATE\sKEY-{5}") {
		__decodePkcs8 $matches[1]
	} elseif ($Text -match "(?msx).*-{5}BEGIN\sRSA\sPRIVATE\sKEY-{5}(.+)-{5}END\sRSA\sPRIVATE\sKEY-{5}") {
		__decodePkcs1 $matches[1]
	}  else {throw "The data is invalid."}
	# private key version
	if (!$asn.MoveNext()) {throw "The data is invalid."}
	# modulus n
	if (!$asn.MoveNext()) {throw "The data is invalid."}
	$modulus = __normalizeAsnInteger $asn.GetPayload()
	Write-Debug "Modulus length: $($modulus.Length)"
	# public exponent e
	if (!$asn.MoveNext()) {throw "The data is invalid."}
	# public exponent must be 4 bytes exactly.
	$PublicExponent = if ($asn.GetPayload().Length -eq 3) {
		,0 + $asn.GetPayload()
	} else {
		$asn.GetPayload()
	}
	Write-Debug "PublicExponent length: $($PublicExponent.Length)"
	# private exponent d
	if (!$asn.MoveNext()) {throw "The data is invalid."}
	$PrivateExponent = __normalizeAsnInteger $asn.GetPayload()
	Write-Debug "PrivateExponent length: $($PrivateExponent.Length)"
	# prime1 p
	if (!$asn.MoveNext()) {throw "The data is invalid."}
	$Prime1 = __normalizeAsnInteger $asn.GetPayload()
	Write-Debug "Prime1 length: $($Prime1.Length)"
	# prime2 q
	if (!$asn.MoveNext()) {throw "The data is invalid."}
	$Prime2 = __normalizeAsnInteger $asn.GetPayload()
	Write-Debug "Prime2 length: $($Prime2.Length)"
	# exponent1 d mod (p-1)
	if (!$asn.MoveNext()) {throw "The data is invalid."}
	$Exponent1 = __normalizeAsnInteger $asn.GetPayload()
	Write-Debug "Exponent1 length: $($Exponent1.Length)"
	# exponent2 d mod (q-1)
	if (!$asn.MoveNext()) {throw "The data is invalid."}
	$Exponent2 = __normalizeAsnInteger $asn.GetPayload()
	Write-Debug "Exponent2 length: $($Exponent2.Length)"
	# coefficient (inverse of q) mod p
	if (!$asn.MoveNext()) {throw "The data is invalid."}
	$Coefficient = __normalizeAsnInteger $asn.GetPayload()
	Write-Debug "Coefficient length: $($Coefficient.Length)"
	# creating Private Key BLOB structure
	$PrivateKey = __composePRIVATEKEYBLOB $modulus $PublicExponent $PrivateExponent $Prime1 $Prime2 $Exponent1 $Exponent2 $Coefficient
	#region key attachment and export
	try {
		$rsaKey = __attachPrivateKey $Cert $PrivateKey
		if (![string]::IsNullOrEmpty($OutputPath)) {
			if (!$Password) {
				$Password = Read-Host -Prompt "Enter PFX password" -AsSecureString
			}
			$pfxBytes = $Cert.Export("pfx", $Password)
			Set-Content -Path $OutputPath -Value $pfxBytes -Encoding Byte
		}
		#endregion
		if ($Install) {
			$store = New-Object Security.Cryptography.X509Certificates.X509Store "my", $StoreLocation
			$store.Open("ReadWrite")
			$store.Add($Cert)
			$store.Close()
		}
	} finally {
		if ($rsaKey -ne $null) {
			$rsaKey.Dispose()
			$Cert
		}
	}
}
# SIG # Begin signature block
# MIIX1gYJKoZIhvcNAQcCoIIXxzCCF8MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCT7JUlngrKZ1w3
# a/SSO89Kw2FHbeCzktIiRAt9N20E06CCEuQwggPuMIIDV6ADAgECAhB+k+v7fMZO
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
# BAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEII4U76TLplrK
# xorPqulALyTvAo5+w1Imh0rhj3ABZgAqMA0GCSqGSIb3DQEBAQUABIIBAFA84rT5
# FS4gPY8cJi1kvVeIxtO1q4ON2lukSF1pPnorahihOZqc9oclAwJb00Llno7jYKbY
# jljrQAfHyRCcezSpkYt+ahPLvF/mhZb1qFvDruljJssb5648RJl5DSTNipUuYFbt
# vknG0MLx6Ryu+KBH1S1/3hwYvuqaWpyr/AuzpoLp5W/VqHCZ4Mj26F+oa3ttouHY
# RFRHwE0frBEmmSHqqOKomSjbpF+K79rKKB7bOIQK/qsdnviD7rgJ/zrQuewTmVF9
# m6VNE6vXiOMh24Smqq6eg87t0DVz1BKp+NfnbKErulztjc64wgZz60LE2mC83e1O
# 1KFFbYcqEbCAdFWhggILMIICBwYJKoZIhvcNAQkGMYIB+DCCAfQCAQEwcjBeMQsw
# CQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xMDAuBgNV
# BAMTJ1N5bWFudGVjIFRpbWUgU3RhbXBpbmcgU2VydmljZXMgQ0EgLSBHMgIQDs/0
# OMj+vzVuBNhqmBsaUDAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3
# DQEHATAcBgkqhkiG9w0BCQUxDxcNMTYwODA3MTgwMDUyWjAjBgkqhkiG9w0BCQQx
# FgQUSWYrBYegaQgKw3bmdDQGenWyE+gwDQYJKoZIhvcNAQEBBQAEggEAIZ6oHkvb
# 5HZ/wA/fCWzKnv96k2ohM1qjWRUbtzgbDHVDzWYzDIsTaOodUWuwWsHKBqekX+sf
# Eww/Zfb+YK/1FV1uKbOOfkrS4f8bCgzVQzs0kEsfj1BSpNiAcs1uDHzMZzdgkEwl
# 2RQnodsE6wvyV3/UaeiTxkkFksgfIcMWIEER8eNpQAfgyXmd6d29lOL11TBDeId3
# 1zoE0Pl2eFHB72u9h4DhrHNXq2qVlwhCntsmEZglCXfsTfsonkGRLSd30sDOdg7i
# cnZH3RlX8K7jE6b3ELow2cjbo5gATVaoBsyJd9qzQsbog11gRtM9d9VZ2xaQ+XZn
# 0yU9ZGqk/GQYlQ==
# SIG # End signature block
