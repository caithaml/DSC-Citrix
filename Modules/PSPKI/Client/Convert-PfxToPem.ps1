function Convert-PfxToPem {
<#
.ExternalHelp PSPKI.Help.xml
#>
[CmdletBinding(DefaultParameterSetName = '__pfxfile')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = '__pfxfile', Position = 0)]
        [IO.FileInfo]$InputFile,
        [Parameter(Mandatory = $true, ParameterSetName = '__cert', Position = 0)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true, ParameterSetName = '__pfxfile', Position = 1)]
        [Security.SecureString]$Password,
        [Parameter(Mandatory = $true, Position = 2)]
        [IO.FileInfo]$OutputFile,
        [Parameter(Position = 3)]
        [ValidateSet("Pkcs1","Pkcs8")]
        [string]$OutputType = "Pkcs8",
		[switch]$IncludeChain
    )
$signature = @"
[DllImport("crypt32.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern bool CryptAcquireCertificatePrivateKey(
    IntPtr pCert,
    uint dwFlags,
    IntPtr pvReserved,
    ref IntPtr phCryptProv,
    ref uint pdwKeySpec,
    ref bool pfCallerFreeProv
);
[DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern bool CryptGetUserKey(
    IntPtr hProv,
    uint dwKeySpec,
    ref IntPtr phUserKey
);
[DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern bool CryptExportKey(
    IntPtr hKey,
    IntPtr hExpKey,
    uint dwBlobType,
    uint dwFlags,
    byte[] pbData,
    ref uint pdwDataLen
);
[DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern bool CryptDestroyKey(
    IntPtr hKey
);
[DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern bool PFXIsPFXBlob(
    CRYPTOAPI_BLOB pPFX
);
[DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern bool PFXVerifyPassword(
    CRYPTOAPI_BLOB pPFX,
    [MarshalAs(UnmanagedType.LPWStr)]
    string szPassword,
    int dwFlags
);
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
public struct CRYPTOAPI_BLOB {
    public int cbData;
    public IntPtr pbData;
}
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
public struct PUBKEYBLOBHEADERS {
    public byte bType;
    public byte bVersion;
    public short reserved;
    public uint aiKeyAlg;
    public uint magic;
    public uint bitlen;
    public uint pubexp;
 }
"@
    Add-Type -MemberDefinition $signature -Namespace PKI -Name PfxTools
#region helper functions
    function Encode-Integer ([Byte[]]$RawData) {
        # since CryptoAPI is little-endian by nature, we have to change byte ordering
        # to big-endian.
        [array]::Reverse($RawData)
        # if high byte contains more than 7 bits, an extra zero byte is added
        if ($RawData[0] -ge 128) {$RawData = ,0 + $RawData}
        [SysadminsLV.Asn1Parser.Asn1Utils]::Encode($RawData, 2)
    }
#endregion

#region parameterset processing
    switch ($PsCmdlet.ParameterSetName) {
        "__pfxfile" {
            $bytes = [IO.File]::ReadAllBytes($InputFile)
            $ptr = [Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length)
            [Runtime.InteropServices.Marshal]::Copy($bytes,0,$ptr,$bytes.Length)
            $pfx = New-Object PKI.PfxTools+CRYPTOAPI_BLOB -Property @{
                cbData = $bytes.Length;
                pbData = $ptr
            }
            # just check whether input file is valid PKCS#12/PFX file.
            if ([PKI.PfxTools]::PFXIsPFXBlob($pfx)) {
				$certs = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection
				try {
					$certs.Import(
						$bytes,
						[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)),
						"Exportable"
					)
					$Certificate = ($certs | Where-Object {$_.HasPrivateKey})[0]
				} catch {
					throw $_
					return
				} finally {
                    [Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
                    Remove-Variable bytes, ptr, pfx -Force
                }
            } else {
                [Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
                Remove-Variable bytes, ptr, pfx -Force
                Write-Error -Category InvalidData -Message "Input file is not valid PKCS#12/PFX file." -ErrorAction Stop
            }
        }
        "__cert" {
            if (!$Certificate.HasPrivateKey) {
                Write-Error -Category InvalidOperation -Message "Specified certificate object does not contain associated private key." -ErrorAction Stop
            }
        }
    }
#endregion

#region constants
	$CRYPT_ACQUIRE_SILENT_FLAG = 0x40
	$PRIVATEKEYBLOB = 0x7
	$CRYPT_OAEP = 0x40
#endregion

#region private key export routine
    $phCryptProv = [IntPtr]::Zero
    $pdwKeySpec = 0
    $pfCallerFreeProv = $false
    # attempt to acquire private key container
    if (![PKI.PfxTools]::CryptAcquireCertificatePrivateKey($Certificate.Handle,$CRYPT_ACQUIRE_SILENT_FLAG,0,[ref]$phCryptProv,[ref]$pdwKeySpec,[ref]$pfCallerFreeProv)) {
		throw New-Object ComponentModel.Win32Exception ([Runtime.InteropServices.Marshal]::GetLastWin32Error())
		return
	}
	$phUserKey = [IntPtr]::Zero
	# attempt to acquire private key handle
	if (![PKI.PfxTools]::CryptGetUserKey($phCryptProv,$pdwKeySpec,[ref]$phUserKey)) {
		throw New-Object ComponentModel.Win32Exception ([Runtime.InteropServices.Marshal]::GetLastWin32Error())
		return
	}
	$pdwDataLen = 0
	# attempt to export private key. This method fails if certificate has non-exportable private key.
	if (![PKI.PfxTools]::CryptExportKey($phUserKey,0,$PRIVATEKEYBLOB,$CRYPT_OAEP,$null,[ref]$pdwDataLen)) {
		throw New-Object ComponentModel.Win32Exception ([Runtime.InteropServices.Marshal]::GetLastWin32Error())
		return
	}
	$pbytes = New-Object byte[] -ArgumentList $pdwDataLen
	[void][PKI.PfxTools]::CryptExportKey($phUserKey,0,$PRIVATEKEYBLOB,$CRYPT_OAEP,$pbytes,[ref]$pdwDataLen)
	# release private key handle
	[void][PKI.PfxTools]::CryptDestroyKey($phUserKey)
#endregion

#region private key blob splitter
    # extracting private key blob header.
    $headerblob = $pbytes[0..19]
    # extracting actual private key data exluding header.
    $keyblob = $pbytes[20..($pbytes.Length - 1)]
    Remove-Variable pbytes -Force
    # public key structure header has fixed length: 20 bytes: http://msdn.microsoft.com/en-us/library/aa387689(VS.85).aspx
    # copy header information to unmanaged memory and copy it to structure.
    $ptr = [Runtime.InteropServices.Marshal]::AllocHGlobal(20)
    [Runtime.InteropServices.Marshal]::Copy($headerblob,0,$ptr,20)
    $header = [Runtime.InteropServices.Marshal]::PtrToStructure($ptr,[Type][PKI.PfxTools+PUBKEYBLOBHEADERS])
    [Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
    # extract public exponent from blob header and convert it to a byte array
    $pubExponentHex = "{0:x2}" -f $header.pubexp
    if ($pubExponentHex.Length % 2) {$pubExponentHex = "0" + $pubExponentHex}
    $publicExponent = $pubExponentHex -split "([a-f0-9]{2})" | Where-Object {$_} | ForEach-Object {[Convert]::ToByte($_,16)}
    # this object is created to reduce code size. This object has properties, where each property represents
    # a part (component) of the private key and property value contains private key component length.
    # 8 means that the length of the component is KeyLength / 8. Resulting length is measured in bytes.
    # for details see private key structure description: http://msdn.microsoft.com/en-us/library/aa387689(VS.85).aspx
    $obj = New-Object psobject -Property @{
        modulus = 8; privateExponent = 8;
        prime1 = 16; prime2 = 16; exponent1 = 16; exponent2 = 16; coefficient = 16;
    }
    $offset = 0
    # I pass variable names (each name represents the component of the private key) to foreach loop
    # in the order as they follow in the private key structure and parse private key for
    # appropriate offsets and write component information to variable.
    "modulus","prime1","prime2","exponent1","exponent2","coefficient","privateExponent" | ForEach-Object {
        Set-Variable -Name $_ -Value ($keyblob[$offset..($offset + $header.bitlen / $obj.$_ - 1)])
        $offset = $offset + $header.bitlen / $obj.$_
    }
    # PKCS#1/PKCS#8 uses slightly different component order, therefore I reorder private key
    # components and pass them to a simplified ASN encoder.
    $asnblob = Encode-Integer 0
    $asnblob += "modulus","publicExponent","privateExponent","prime1","prime2","exponent1","exponent2","coefficient" | ForEach-Object {
        Encode-Integer (Get-Variable -Name $_).Value
    }
    # remove unused variables
    Remove-Variable modulus,publicExponent,privateExponent,prime1,prime2,exponent1,exponent2,coefficient -Force
    # encode resulting set of INTEGERs to a SEQUENCE
    $asnblob = [SysadminsLV.Asn1Parser.Asn1Utils]::Encode($asnblob, 48)
    # $out variable just holds output file. The file will contain private key and public certificate
    # each will be enclosed with header and footer.
	$out = New-Object Text.StringBuilder
    if ($OutputType -eq "Pkcs8") {
        $asnblob = [SysadminsLV.Asn1Parser.Asn1Utils]::Encode($asnblob, 4)
        $algid = [Security.Cryptography.CryptoConfig]::EncodeOID("1.2.840.113549.1.1.1") + 5,0
        $algid = [SysadminsLV.Asn1Parser.Asn1Utils]::Encode($algid, 48)
        $asnblob = 2,1,0 + $algid + $asnblob
        $asnblob = [SysadminsLV.Asn1Parser.Asn1Utils]::Encode($asnblob, 48)
		$base64 = [SysadminsLV.Asn1Parser.AsnFormatter]::BinaryToString($asnblob,"Base64").Trim()
		[void]$out.AppendFormat("{0}{1}", "-----BEGIN PRIVATE KEY-----", [Environment]::NewLine)
		[void]$out.AppendFormat("{0}{1}", $base64, [Environment]::NewLine)
		[void]$out.AppendFormat("{0}{1}", "-----END PRIVATE KEY-----", [Environment]::NewLine)
    } else {
        # PKCS#1 requires RSA identifier in the header.
        # PKCS#1 is an inner structure of PKCS#8 message, therefore no additional encodings are required.
		$base64 = [SysadminsLV.Asn1Parser.AsnFormatter]::BinaryToString($asnblob,"Base64").Trim()
		[void]$out.AppendFormat("{0}{1}", "-----BEGIN RSA PRIVATE KEY-----", [Environment]::NewLine)
		[void]$out.AppendFormat("{0}{1}", $base64, [Environment]::NewLine)
		[void]$out.AppendFormat("{0}{1}", "-----END RSA PRIVATE KEY-----", [Environment]::NewLine)
    }
    $base64 = [SysadminsLV.Asn1Parser.AsnFormatter]::BinaryToString($Certificate.RawData,"Base64Header")
	$out.Append($base64)
	if ($IncludeChain) {
		$chain = New-Object Security.Cryptography.X509Certificates.X509Chain
		$chain.ChainPolicy.RevocationMode = "NoCheck"
		if ($certs) {
			$chain.ChainPolicy.ExtraStore.AddRange($certs)
		}
		[void]$chain.Build($Certificate)
		for ($n = 1; $n -lt $chain.ChainElements.Count; $n++) {
			$base64 = [SysadminsLV.Asn1Parser.AsnFormatter]::BinaryToString($chain.ChainElements[$n].Certificate.RawData,"Base64Header")
			$out.Append($base64)
		}
	}
    [IO.File]::WriteAllLines($OutputFile,$out.ToString())
#endregion
}
# SIG # Begin signature block
# MIIX1gYJKoZIhvcNAQcCoIIXxzCCF8MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC3M9HxcEr6xez6
# SDJ0wWfBLj3Lb9a8lRhGqlmkXrYaKqCCEuQwggPuMIIDV6ADAgECAhB+k+v7fMZO
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
# BAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIOF157qsWkN8
# qplvYASd2nLCYFqQDxm85K8iPwykOax+MA0GCSqGSIb3DQEBAQUABIIBAH6vGK0f
# gAz1CWuJo86dn5RbCoPbbasjOfWj2PjBBNY9Zv3Dx9mvgMiecCx+8EB9oYtFw46v
# 6Ts+J5kAEK4Fm29GgQdOyhpa2IGdNS3nuddLEuHBx237kbdNFYCljJTxgYWlxG5M
# Gr8x7sSTyRB/SD36DnzeIUCDUIP31/DrwanqjW1rSLJ109Ie+yP5YgAyeFrwwMjZ
# 604gVtTT4ci3z3xhUeyiXGKd3rd0hdJ1YMz7zo1wsRTXBby2O32HhydnnRiufU4/
# cCE1FbQJnri8jyR/XNxAQSR/Gqx8G8NdqK2AxhtwGUOjCK97dLGILXeiUFj/Bm/P
# MKdvpbgc3b441DOhggILMIICBwYJKoZIhvcNAQkGMYIB+DCCAfQCAQEwcjBeMQsw
# CQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xMDAuBgNV
# BAMTJ1N5bWFudGVjIFRpbWUgU3RhbXBpbmcgU2VydmljZXMgQ0EgLSBHMgIQDs/0
# OMj+vzVuBNhqmBsaUDAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3
# DQEHATAcBgkqhkiG9w0BCQUxDxcNMTYwODA3MTgwMDU1WjAjBgkqhkiG9w0BCQQx
# FgQU8/S8PhywnUspOuZiTrok2MpLlA8wDQYJKoZIhvcNAQEBBQAEggEAYxxv3MmF
# SkwYMrprdkKNfoY/hPjeWb+ZrMJqIlWrcuYSLuT5aWLcSWbiAhAJnzJfne7XeFUm
# 5Z8Xfyjh2cs84v68pho3iJlUcqoCuPns5AU9Vr6JP6P0LbY+1NOwkLAJ+L/EwPEs
# 7owNAP+DAqIOTNV5ZXOJjgppDEH0tjxF4DgCbFPFny+7oKWmS21kCiMLQXQQn6WZ
# D2gPbr3M+5wKNhhcx8w5vyK+fn46VCVx7thNxru2uy0S9JLhhPT+HxdAASIEQXJV
# VSyfuEvTrenhwwdl5sEUJ2KdV0mmsEh0PjKHYzuXZXXzjp9149WWFz6Cd/dxFfPI
# 5/25ZAqZkRKNIg==
# SIG # End signature block
