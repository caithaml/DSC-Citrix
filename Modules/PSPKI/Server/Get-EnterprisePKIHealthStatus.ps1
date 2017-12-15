function Get-EnterprisePKIHealthStatus {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('PKI.CertificateServices.PolicyModule.ExtensionList[]')]
[CmdletBinding(DefaultParameterSetName = '__CA')]
	param(
		[Parameter(
			Mandatory = $true,
			ValueFromPipeline = $true,
			ValueFromPipelineByPropertyName = $true,
			ParameterSetName = '__CA'
		)]
		[Alias('CA')]
		[PKI.CertificateServices.CertificateAuthority[]]$CertificateAuthority,
		[Parameter(Mandatory = $true, ParameterSetName = '__EndCerts')]
		[Security.Cryptography.X509Certificates.X509Certificate2[]]$Certificate,
		# configuration
		[int]$DownloadTimeout = 15,
		[ValidateRange(1,99)]
		[int]$CaCertExpirationThreshold = 80,
		[ValidateRange(1,99)]
		[int]$BaseCrlExpirationThreshold = 80,
		[ValidateRange(1,99)]
		[int]$DeltaCrlExpirationThreshold = 80,
		[ValidateRange(1,99)]
		[int]$OcspCertExpirationThreshold = 80
	)
	begin {
#region native function declarations
$cryptnetsignature = @"
[DllImport("cryptnet.dll", CharSet = CharSet.Auto, SetLastError = true)]
public static extern bool CryptRetrieveObjectByUrl(
	//[MarshalAs(UnmanagedType.LPStr)]
	string pszUrl,
	//[MarshalAs(UnmanagedType.LPStr)]
	int pszObjectOid,
	int dwRetrievalFlags,
	int dwTimeout,
	ref IntPtr ppvObject,
	IntPtr hAsyncRetrieve,
	IntPtr pCredentials,
	IntPtr pvVerify,
	IntPtr pAuxInfo
);
"@
Add-Type -MemberDefinition $cryptnetsignature -Namespace "PKI.EnterprisePKI" -Name Cryptnet
$crypt32signature = @"
[DllImport("Crypt32.dll", SetLastError = true)]
public static extern Boolean CertFreeCertificateContext(
	IntPtr pCertContext
);
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
public struct CRL_CONTEXT {
	public int dwCertEncodingType;
	public IntPtr pbCrlEncoded;
	public int cbCrlEncoded;
	public IntPtr pCrlInfo;
	public IntPtr hCertStore;
}
"@
Add-Type -MemberDefinition $crypt32signature -Namespace "PKI.EnterprisePKI" -Name Crypt32
Add-Type @"
using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
namespace PKI.EnterprisePKI {
	public enum ChildStatus {
		Ok = 0x0,
		Warning = 0x100,
		Error = 0x8000,
	}
	// 0-49 -- common
	// 50-99 -- certs
	// 100-149 -- crls
	// 150-199 -- ocsp
	public enum UrlStatus {
		// common
		Ok = 0,
		// CRT/CRL/OCSP
		FailedToDownload = 10, NotYetValid = 11, Expired = 12, Expiring = 13,
		InvalidSignature = 14, NetworkRetrievalError = 15,
		// certs only
		Revoked = 50, InvalidCert = 51,
		// CRLs only. ScheduleExpired means that there is a "Next CRL Publish"
		// extension and current time is ahead of "Next CRL Publish value"
		InvalidIssuer = 100, ScheduleExpired = 101, InvalidBase = 102, InvalidCrlType = 103,
		NonCriticalDeltaIndicator = 104, StaleDelta = 105,
		// ocsp only
		MalformedRequest = 151, InternalError = 152, TryLater = 153,
		SignatureRequired = 155, Unauthorized = 156,
		ResponseInvalidData = 160, InvalidSignerCert = 161,
		// CAs only
		Offline,
	}
	public enum UrlType {
		Certificate, Crl, Ocsp
	}
	public class UrlElement {
		ushort error;

		Object hiddenObject;
		public String Name { get; set; }
		public UrlStatus Status {
			get {
				return (UrlStatus)(error & 0xff);
			}
		}
		public String ExtendedErrorInfo { get; set; }
		public Uri Url { get; set; }
		public DateTime? ExpirationDate { get; set; }
		public UrlType UrlType { get; set; }

		public Object GetObject() { return hiddenObject; }
		public void SetObject(Object obj) { hiddenObject = obj; }
		public void SetError(ushort statusCode) {
			error = statusCode;
		}
		public ushort GetError() {
			return error;
		}
		public override String ToString() {
			return Name + ": " + Url + ", expire: " + ExpirationDate + ", Status: " + Status;
		}
	}
	public class CAObject {
		bool isOffline;
		public String Name { get; set; }
		// can be 'Ok', 'Warning', or 'Error'
		public ChildStatus Status {
			get {
				if (isOffline) { return ChildStatus.Error; }
				if (URLs == null) {
					return ChainStatus == X509ChainStatusFlags.NoError ? ChildStatus.Ok : ChildStatus.Error;
				}
				ChildStatus retValue = ChildStatus.Ok;
				foreach (var url in URLs) {
					if ((url.GetError() & 0xFF00) > (int)retValue) { retValue = (ChildStatus)(url.GetError() & 0xFF00); }
				}
				return retValue;
			}
		}
		public X509ChainStatusFlags ChainStatus { get; set; }
		public String ExtendedErrorInfo { get; set; }
		public UrlElement[] URLs { get; set; }
		public void Offline() {
			isOffline = true;
		}
	}
	public class X509HealthPath {
		public String Name { get; set; }
		public ChildStatus Status {
			get {
				if (Childs == null || Childs.Length == 0) { return ChildStatus.Ok; }
				return Childs.Any(child => child.Status == ChildStatus.Error)
					? ChildStatus.Error
					: (Childs.Any(child => child.Status == ChildStatus.Warning)
						? ChildStatus.Warning
						: ChildStatus.Ok);
			}
		}
		public CAObject[] Childs { get; set; }
	}
}
"@
#endregion
		#region Error severity
		$s_ok = 0x0
		$s_warning = 0x100
		$s_error = 0x8000
		#endregion
		#region script internal config
		$Host.PrivateData.VerboseForegroundColor = "Yellow"
		$Host.PrivateData.DebugForegroundColor = "Cyan"
		if ($PSBoundParameters.Verbose) {$VerbosePreference = "continue"}
		if ($PSBoundParameters.Debug) {$DebugPreference = "continue"}
		$timeout = $DownloadTimeout * 1000
		#endregion
		#region helper functions
		# returns [X509ChainElement[]]
		$chainRoots = @()
		function __getChain {
			param(
				[Security.Cryptography.X509Certificates.X509Certificate2]$cert
			)
			Write-Verbose "Entering certificate chaining engine."
			$chain = New-Object Security.Cryptography.X509Certificates.X509Chain
			$chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
			$status = $chain.Build($cert)
			Write-Debug "Chain status for certificate '$($cert.Subject)': $status"
			if ($chainRoots -notcontains $chain.ChainElements[0].Certificate.Thumbprint) {
				$chainRoots += $chain.ChainElements[0].Certificate.Thumbprint
			}
			$retValue = New-Object Security.Cryptography.X509Certificates.X509ChainElement[] -ArgumentList $chain.ChainElements.Count
			$chain.ChainElements.CopyTo($retValue,0)
			$chain.Reset()
			$retValue
		}
		# returns [X509Certificate2] or [String] that contains error message
		function __downloadCert($url) {
			Write-Debug "Downloading cert URL: $url."
			$ppvObject = [IntPtr]::Zero
			if ([PKI.EnterprisePKI.Cryptnet]::CryptRetrieveObjectByUrl($url,1,4,$timeout,[ref]$ppvObject,
				[IntPtr]::Zero,
				[IntPtr]::Zero,
				[IntPtr]::Zero,
				[IntPtr]::Zero)
			) {
				$cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 $ppvObject
				Write-Debug "Certificate: $($cert.Subject)"
				$cert
				[void][PKI.EnterprisePKI.Crypt32]::CertFreeCertificateContext($ppvObject)
			} else {
				$hresult = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
				Write-Debug "URL error: $hresult"
				$CertRequest = New-Object -ComObject CertificateAuthority.Request
				$CertRequest.GetErrorMessageText($hresult,0)
				[void][Runtime.InteropServices.Marshal]::ReleaseComObject($CertRequest)
			}
		}
		# returns [X509CRL2] or [String] that contains error message
		function __downloadCrl($url) {
			Write-Debug "Downloading CRL URL: $url."
			$ppvObject = [IntPtr]::Zero
			if ([PKI.EnterprisePKI.Cryptnet]::CryptRetrieveObjectByUrl($url,2,4,$timeout,[ref]$ppvObject,
				[IntPtr]::Zero,
				[IntPtr]::Zero,
				[IntPtr]::Zero,
				[IntPtr]::Zero)
			) {
				$crlContext = [Runtime.InteropServices.Marshal]::PtrToStructure($ppvObject,[Type][PKI.EnterprisePKI.Crypt32+CRL_CONTEXT])
				$rawData = New-Object byte[] -ArgumentList $crlContext.cbCrlEncoded
				[Runtime.InteropServices.Marshal]::Copy($crlContext.pbCrlEncoded,$rawData,0,$rawData.Length)
				$crl = New-Object Security.Cryptography.X509Certificates.X509CRL2 (,$rawData)
				Write-Debug "CRL: $($crl.Issuer)"
				$crl
			} else {
				$hresult = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
				Write-Debug "URL error: $hresult"
				$CertRequest = New-Object -ComObject CertificateAuthority.Request
				$CertRequest.GetErrorMessageText($hresult,0)
				[void][Runtime.InteropServices.Marshal]::ReleaseComObject($CertRequest)
			}
		}
		# returns PSObject -- UrlPack
		function __getUrl ([Byte[]]$rawData, [bool]$isCert) {
			Write-Verbose "Getting URLs."
			Write-Debug "Getting URLs."
			$URLs = New-Object psobject -Property @{
				CDP = $null;
				AIA = $null;
				OCSP = $null;
				FreshestCRL = $null;
			}
			$ofs = "`n"
			if ($isCert) {
				$cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 @(,$rawData)
				# CRL Distribution Points
				Write-Debug "Fetching 'CRL Distribution Points' extension..."
				$e = $cert.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.31"}
				if ($e) {
					$asn = New-Object Security.Cryptography.AsnEncodedData (,$e.RawData)
					$cdp = New-Object Security.Cryptography.X509Certificates.X509CRLDistributionPointsExtension $asn, $false
					$URLs.CDP = $cdp.GetURLs()
					Write-Debug "Found $(($URLs.CDP).Length) CDP URLs."
					if ($URLs.CDP) {$URLs.CDP | ForEach-Object {Write-Debug "$_"}}
				} else {
					Write-Debug "Missing 'CRL Distribution Points' extension."
				}
				# Authority Information Access
				Write-Debug "Fetching 'Authority Information Access' extension..."
				$e = $cert.Extensions | Where-Object {$_.Oid.Value -eq "1.3.6.1.5.5.7.1.1"}
				if ($e) {
					$asn = New-Object Security.Cryptography.AsnEncodedData (,$e.RawData)
					$aia = New-Object Security.Cryptography.X509Certificates.X509AuthorityInformationAccessExtension $asn, $false
					$URLs.AIA = $aia.CertificationAuthorityIssuer
					Write-Debug "Found $(($URLs.AIA).Length) Certification Authority Issuer URLs."
					if ($URLs.AIA) {$URLs.AIA | ForEach-Object {Write-Debug $_}}
					$URLs.OCSP = $aia.OnlineCertificateStatusProtocol
					Write-Debug "Found $(($URLs.OCSP).Length) On-line Certificate Status Protocol URLs."
					if ($URLs.OCSP) {$URLs.OCSP | ForEach-Object {Write-Debug $_}}
				} else {
					Write-Debug "Missing 'Authority Information Access' extension."
				}
				$URLs
				return
			} else {
				Write-Debug "Fetching 'Freshest CRL' extension..."
				$crl = New-Object Security.Cryptography.X509Certificates.X509CRL2 @(,$rawData)
				$e = $crl.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.46"}
				if ($e) {
					$URLs.FreshestCRL = $e.GetURLs()
					Write-Debug "Found $(($URLs.FreshestCRL).Length) Freshest CRL URLs."
					if ($URLs.FreshestCRL) {$URLs.FreshestCRL | ForEach-Object {Write-Debug $_}}
				} else {
					Write-Debug "Missing 'Freshest CRL' extension."
				}
			}
		}
		# returns UrlElement
		function __verifyAIA {
			param (
				[PKI.EnterprisePKI.UrlElement]$urlElement,
				[Security.Cryptography.X509Certificates.X509ChainElement]$CAcert
			)
			Write-Verbose "Entering certificate validation routine."
			Write-Debug "Entering certificate validation routine."
			$cert = $urlElement.GetObject()
			Write-Debug "Leaf certificate: $($cert.Subject)."
			$parent = if ($cert.Subject -eq $cert.Issuer) {
				Write-Debug "Self-signed certificate, issuer is itself."
				$cert
			} else {
				Write-Debug "Issuer candidate: $($CAcert.Certificate.Subject)."
				$CAcert.Certificate
			}
			Write-Debug "Certificate start validity : $($cert.NotBefore)"
			Write-Debug "Certificate end validity   : $($cert.NotAfter)"
			$urlElement.ExpirationDate = $cert.NotAfter
			$subjComp = Compare-Object $cert.SubjectName.RawData $parent.SubjectName.RawData
			$pubKeyComp = Compare-Object $cert.PublicKey.EncodedKeyValue.RawData $parent.PublicKey.EncodedKeyValue.RawData
			$pubKeyParamComp = Compare-Object $cert.PublicKey.EncodedParameters.RawData $parent.PublicKey.EncodedParameters.RawData
			Write-Debug "Subject name binary comparison         : $(if ($subjComp) {'failed'} else {'passed'})"
			Write-Debug "Public key binary comparison           : $(if ($pubKeyComp) {'failed'} else {'passed'})"
			Write-Debug "Public key parameters binary comparison: $(if ($pubKeyParamComp) {'failed'} else {'passed'})"
			$fullTime = ($cert.NotAfter - $cert.NotBefore).TotalSeconds
			$elapsed = ((Get-Date) - $cert.NotBefore).TotalSeconds
			$errorCode = if ($subjComp -or $pubKeyComp -or $pubKeyParamComp) {
				$s_error -bor [PKI.EnterprisePKI.UrlStatus]::InvalidCert
			} elseif ($cert.NotBefore -gt (Get-Date)) {
				Write-Debug "Certificate is not yet valid."
				$s_error -bor [PKI.EnterprisePKI.UrlStatus]::NotYetValid
			} elseif ($cert.NotAfter -lt (Get-Date)) {
				Write-Debug "Certificate is expired."
				$s_error -bor [PKI.EnterprisePKI.UrlStatus]::Expired
			} elseif ($CaCertExpirationThreshold -lt $elapsed / $fullTime * 100) {
				Write-Debug "Certificate is about to expire. Elapsed $([int]($elapsed / $fullTime * 100))%"
				$s_warning -bor [PKI.EnterprisePKI.UrlStatus]::Expiring
			} else {
				Write-Debug "Certificate passed all validity checks."
				$s_ok -bor [PKI.EnterprisePKI.UrlStatus]::Ok
			}
			$urlElement.SetError($errorCode)
			$urlElement
		}
		# returns DateTime or Null (for CRL v1)
		function __getCrlNextPublish($crl) {
			$e = $crl.Extensions | Where-Object {$_.Oid.Value -eq "1.3.6.1.4.1.311.21.4"}
			if (!$e) {return}
			$dt = try {
					[SysadminsLV.Asn1Parser.Asn1Utils]::DecodeUTCTime($e.RawData)
				} catch {
					[SysadminsLV.Asn1Parser.Asn1Utils]::DecodeGeneralizedTime($e.RawData)
				}
		}
		# returns UrlElement. $cert -- issuer candidate/X509ChainElement.
		function __verifyCDP {
			param(
				[PKI.EnterprisePKI.UrlElement]$urlElement,
				[Security.Cryptography.X509Certificates.X509ChainElement]$cert,
				[Security.Cryptography.X509Certificates.X509CRL2]$BaseCRL,
				[switch]$DeltaCRL
			)
			Write-Verbose "Entering CRL validation routine..."
			Write-Debug "Entering CRL validation routine..."
			$crl = $urlElement.GetObject()
			Write-Debug "$($crl.Type) start validity : $($crl.ThisUpdate)"
			Write-Debug "$($crl.Type) end validity   : $($crl.NextUpdate)"
			$urlElement.ExpirationDate = $crl.NextUpdate
			[Int64]$dcrlNumber = [SysadminsLV.Asn1Parser.Asn1Utils]::DecodeInteger(($crl.Extensions | Where-Object {$_.OID.Value -eq "2.5.29.20"}).RawData)
			Write-Debug "CRL number: $dcrlNumber"
			if ($DeltaCRL) {
				[Int64]$bcrlNumber = [SysadminsLV.Asn1Parser.Asn1Utils]::DecodeInteger(($BaseCRL.Extensions | Where-Object {$_.OID.Value -eq "2.5.29.20"}).RawData)
				Write-Debug "Referenced Base CRL number: $bcrlNumber"
				[UInt64]$indicator = [SysadminsLV.Asn1Parser.Asn1Utils]::DecodeInteger(($crl.Extensions | Where-Object {$_.OID.Value -eq "2.5.29.27"}).RawData)
				Write-Debug "Required minimum Base CRL number: $indicator"
				[bool]$indicatorIsCritical = ($crl.Extensions | Where-Object {$_.OID.Value -eq "2.5.29.27"}).Critical
			}
			$errorCode = if ($DeltaCRL -and ($crl.Type -ne "Delta CRL")) {
				Write-Debug "Invalid CRL type. Expected Delta CRL, but received Base CRL."
				$s_error -bor [PKI.EnterprisePKI.UrlStatus]::InvalidCrlType
			} elseif (!$DeltaCRL -and ($crl.Type -ne "Base CRL")) {
				Write-Debug "Invalid CRL type. Expected Base CRL, but received Delta CRL."
				$s_error -bor [PKI.EnterprisePKI.UrlStatus]::InvalidCrlType
			} elseif (!$crl.VerifySignature($cert.Certificate, $true)) {
				Write-Debug "CRL signature check failed."
				$s_error -bor [PKI.EnterprisePKI.UrlStatus]::InvalidIssuer
			} elseif ($crl.ThisUpdate -gt [datetime]::Now) {
				Write-Debug "CRL is not yet valid."
				$s_error -bor [PKI.EnterprisePKI.UrlStatus]::NotYetValid
			} elseif ($crl.NextUpdate -lt [datetime]::Now) {
				Write-Debug "CRL is expired."
				$s_error -bor [PKI.EnterprisePKI.UrlStatus]::Expired
			} elseif ($DeltaCRL -and !$indicatorIsCritical) {
				Write-Debug "'Delta CRL Indicator' is not critical."
				$s_error -bor [PKI.EnterprisePKI.UrlStatus]::NonCriticalDeltaIndicator
			} elseif ($DeltaCRL -and ($bcrlNumber -lt $indicator)) {
				Write-Debug "Base CRL number has lower version than version required by 'Delta CRL Indicator' extension."
				$s_error -bor [PKI.EnterprisePKI.UrlStatus]::InvalidBase
			} elseif ($DeltaCRL -and ($dcrlNumber -le $bcrlNumber)) {
				Write-Debug "Delta CRL is outdated. A new version of Base CRL is available that overlaps current Delta CRL."
				$s_warning -bor [PKI.EnterprisePKI.UrlStatus]::StaleDelta
			} else {
				$dt = __getCrlNextPublish $crl
				if ($dt) {
					if ((Get-Date) -gt $dt) {
						Write-Debug "Scheduled CRL publish expired."
						$urlElement.SetError($s_warning -bor [PKI.EnterprisePKI.UrlStatus]::ScheduleExpired)
					}
					$urlElement
					return
				}
				$fullTime = ($crl.NextUpdate - $crl.ThisUpdate).TotalSeconds
				$elapsed = ((Get-Date) - $crl.ThisUpdate).TotalSeconds
				if ($DeltaCRL) {
					if ($DeltaCrlExpirationThreshold -lt $elapsed / $fullTime * 100) {
						Write-Debug "$($crl.Type) is about to expire. Elapsed: $([int]($elapsed / $fullTime * 100))%"
						$s_warning -bor [PKI.EnterprisePKI.UrlStatus]::Expiring
					} else {
						
						$s_ok -bor [PKI.EnterprisePKI.UrlStatus]::Ok
					}
				} else {
					if ($BaseCrlExpirationThreshold -lt $elapsed / $fullTime * 100) {
						Write-Debug "$($crl.Type) is about to expire. Elapsed: $([int]($elapsed / $fullTime * 100))%"
						$s_warning -bor [PKI.EnterprisePKI.UrlStatus]::Expiring
					} else {
						$s_ok -bor [PKI.EnterprisePKI.UrlStatus]::Ok
					}
				}
			}
			$urlElement.SetError($errorCode)
			$urlElement
		}
		# returns UrlElement
		function __verifyOCSP {
			param(
				[Security.Cryptography.X509Certificates.X509ChainElement]$cert,
				[PKI.EnterprisePKI.UrlElement]$urlElement
			)
			Write-Verbose "Entering OCSP validation routine..."
			Write-Debug "Entering OCSP validation routine..."
			Write-Debug "URL: $($urlElement.Url.AbsoluteUri)"
			$req = New-Object PKI.OCSP.OCSPRequest $cert.Certificate
			$req.URL = $urlElement.Url
			try {
				$resp = $req.SendRequest()
				$urlElement.SetObject($resp)
				$errorCode = if ($resp.ResponseStatus -ne [PKI.OCSP.OCSPResponseStatus]::Successful) {
					Write-Debug "OCSP server failed: $($resp.ResponseStatus)"
					$s_error -bor (150 + $resp.ResponseStatus)
				} elseif (!$resp.SignatureIsValid) {
					Write-Debug "OCSP response signature validation failed."
					$s_error -bor [PKI.EnterprisePKI.UrlStatus]::InvalidSignature
				} elseif ([int]$resp.ResponseErrorInformation) {
					Write-Debug "Response contains invalid data: $($resp.ResponseErrorInformation)"
					$s_error -bor [PKI.EnterprisePKI.UrlStatus]::ResponseInvalidData
				} elseif (!$resp.SignerCertificateIsValid) {
					Write-Debug "Signer certificate has one or more issues."
					$s_error -bor [PKI.EnterprisePKI.UrlStatus]::InvalidSignerCert
				} else {
					$totalValidity = ($resp.SignerCertificates[0].NotAfter - $resp.SignerCertificates[0].NotBefore).TotalSeconds
					$elapsed = ((Get-Date) - $resp.SignerCertificates[0].NotBefore).TotalSeconds
					if ($OcspCertExpirationThreshold -le $elapsed / $totalValidity * 100) {
						Write-Debug "OCSP signing certificate is about to expire. Elapsed: $($elapsed / $totalValidity * 100)%"
						$s_warning -bor [PKI.EnterprisePKI.UrlStatus]::Expiring
					} else {
						Write-Debug "OCSP response passed all checks."
						$urlElement.ExpirationDate = $resp.Responses[0].NextUpdate
						Write-Debug "OCSP response expires: $($urlElement.ExpirationDate)"
						$s_ok -bor [PKI.EnterprisePKI.UrlStatus]::Ok
					}
				}
				$urlElement.SetError($errorCode)
			} catch {
				$urlElement.SetError($s_error -bor [PKI.EnterprisePKI.UrlStatus]::NetworkRetrievalError)
				$urlElement.ExtendedErrorInfo = $_.Error.Exception.Message
			}
			$urlElement
		}
		# returns CAObject
		function __processCerts ($CAObject, $projectedChain) {
			Write-Verbose "Processing Certification Authority Issuer URLs..."
			Write-Debug "Processing Certification Authority Issuer URLs..."
			for ($n = 0; $n -lt $urlPack.AIA.Length; $n++) {
				$urlElement = New-Object PKI.EnterprisePKI.UrlElement -Property @{
					Name = "AIA Location #$($n + 1)";
					Url = $urlPack.AIA[$n];
					UrlType = [PKI.EnterprisePKI.UrlType]::Certificate;
				}
				$obj = __downloadCert $urlElement.Url
				if ($obj -is [Security.Cryptography.X509Certificates.X509Certificate2]) {
					$urlElement.SetObject($obj)
					$urlElement = __verifyAIA $urlElement $projectedChain[$i + 1]
				} else {
					Write-Debug "Failed to download certificate."
					$urlElement.SetError($s_error -bor [PKI.EnterprisePKI.UrlStatus]::FailedToDownload)
					$urlElement.ExtendedErrorInfo = $obj
				}
				$CAObject.URLs += $urlElement
			}
			$CAObject
		}
		# returns CAObject
		function __processOcsp ($CAObject, $projectedChain) {
			Write-Verbose "Processing On-line Certificate Status Protocol URLs..."
			Write-Debug "Processing On-line Certificate Status Protocol URLs..."
			for ($n = 0; $n -lt $urlPack.OCSP.Length; $n++) {
				$urlElement = New-Object PKI.EnterprisePKI.UrlElement -Property @{
					Name = "OCSP Location #$($n + 1)";
					Url = $urlPack.OCSP[$n];
					UrlType = [PKI.EnterprisePKI.UrlType]::Ocsp;
				}
				$urlElement = __verifyOCSP $projectedChain[$i] $urlElement
				$CAObject.URLs += $urlElement
			}
			$CAObject
		}
		# returns X509HealthPath
		function __validateSinglePath {
			param(
				[Security.Cryptography.X509Certificates.X509Certificate2]$cert,
				# this parameter is not used
				[int]$keyIndex = -1
			)
			Write-Verbose "Entering certification path validation routine..."
			Write-Debug "Entering certification path validation routine..."
			if ([IntPtr]::Zero.Equals($cert.Handle)) {
				throw New-Object PKI.Exceptions.UninitializedObjectException "The certificate is not initialized."
				return
			}
			$projectedChain = __getChain $cert
			[void]($cert.Issuer -match "CN=([^,]+)")
			Write-Debug "CA name: $($matches[1])"
			$out = if ($keyIndex -lt 0) {
				New-Object PKI.EnterprisePKI.X509HealthPath -Property @{Name = $matches[1]}
			} else {
				New-Object PKI.EnterprisePKI.X509HealthPath -Property @{Name = "$($matches[1]) ($keyIndex)"}
			}
			for ($i = 0; $i -lt $projectedChain.Length; $i++) {
				Write-Debug "========================= $($projectedChain[$i].Certificate.Issuer) ========================="
				# skip self-signed certificate from checking
				if (!(
					Compare-Object -ReferenceObject $projectedChain[$i].Certificate.SubjectName.RawData `
						-DifferenceObject $projectedChain[$i].Certificate.IssuerName.RawData)) {
					Write-Debug "Leaf certificate is self-signed, skip validation."
					break
				}
				[void]($projectedChain[$i].Certificate.Issuer -match "CN=([^,]+)")
				$CAObject = if ($keyIndex -lt 0) {
					New-Object PKI.EnterprisePKI.CAObject -Property @{Name = $matches[1]}
				} else {
					New-Object PKI.EnterprisePKI.CAObject -Property @{Name = "$($matches[1]) ($keyIndex)"}
				}
				$projectedChain | ForEach-Object {[int]$CAObject.ChainStatus += [int]$_.Status}
				$urlpack = __getUrl $projectedChain[$i].Certificate.RawData $true
				# process and validate certificate issuer in the AIA extension
				$CAObject = __processCerts $CAObject $projectedChain
				# process and validate CDP extensions
				$deltaUrls = @()
				for ($n = 0; $n -lt $urlPack.CDP.Length; $n++) {
					$urlElement = New-Object PKI.EnterprisePKI.UrlElement -Property @{
						Name = "CDP Location #$($n + 1)";
						Url = $urlPack.CDP[$n];
						UrlType = [PKI.EnterprisePKI.UrlType]::Crl;
					}
					$obj = __downloadCrl $urlElement.Url
					if ($obj -is [Security.Cryptography.X509Certificates.X509CRL2]) {
						$urlElement.SetObject($obj)
						$urlElement = __verifyCDP $urlElement $projectedChain[$i + 1]
						$urlPack2 = __getUrl ($urlElement.GetObject()).RawData $false
						# process and validate FreshestCRL extension if exist
						$deltas = @()
						for ($m = 0; $m -lt $urlPack2.FreshestCRL.Length; $m++) {
							# skip duplicate
							if ($deltaUrls -contains $urlPack2.FreshestCRL[$m]) {return}
							$urlElement2 = New-Object PKI.EnterprisePKI.UrlElement -Property @{
								Name = "DeltaCRL Location #$($m + 1)";
								Url = $urlPack2.FreshestCRL[$n];
								UrlType = [PKI.EnterprisePKI.UrlType]::Crl;
							}
							$obj2 = __downloadCrl $urlElement2.Url
							if ($obj2 -is [Security.Cryptography.X509Certificates.X509CRL2]) {
								$urlElement2.SetObject($obj2)
								$urlElement2 = __verifyCDP $urlElement2 $projectedChain[$i + 1] $obj -DeltaCRL
							} else {
								Write-Debug "Failed to download CRL."
								$urlElement2.SetError($s_error -bor [PKI.EnterprisePKI.UrlStatus]::FailedToDownload)
								$urlElement2.ExtendedErrorInfo = $obj2
							}
							$deltas += $urlElement2
						}
					} else {
						Write-Debug "Failed to download CRL."
						$urlElement.SetError($s_error -bor [PKI.EnterprisePKI.UrlStatus]::FailedToDownload)
						$urlElement.ExtendedErrorInfo = $obj
					}
					$CAObject.URLs += $urlElement
					$CAObject.URLs += $deltas
				}
				# process OCSP links in the AIA extension
				$CAObject = __processOcsp $CAObject $projectedChain
				$out.Childs += $CAObject
			}
			$out
		}
		#endregion
		Write-Debug "Initializing parameterset: $($PsCmdlet.ParameterSetName)."
	}
	process {
		switch ($PsCmdlet.ParameterSetName) {
			'__CA' {
				foreach ($CA in $CertificateAuthority) {
					if (!$CA.Ping()) {
						Write-Debug "$($CA.DisplayName): ICertAdmin is down."
						$retValue = New-Object PKI.EnterprisePKI.CAObject -Property @{Name = $CA.DisplayName}
						$retValue.Offline()
						$retValue
						return
					}
					if (!$CA.Type.StartsWith("Enterprise")) {
						Write-Debug "$($CA.DisplayName): not supported edition. Current: $($CA.Type)."
						Write-Warning "Only Enterprise CAs are supported by this parameterset."
						return
					}
					Write-Host ("=" * 20) $CA.DisplayName ("=" * 20)
					Write-Debug "$($CA.DisplayName): retrieving CA Exchange certificate."
					$xchg = $CA.GetCAExchangeCertificate()
					__validateSinglePath $xchg
				}
			}
			'__EndCerts' {
				$Certificate | ForEach-Object {__validateSinglePath $_}
			}
		}
	}
}
# SIG # Begin signature block
# MIIX1gYJKoZIhvcNAQcCoIIXxzCCF8MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAGVBvzIbAz2Fv2
# VDk/NygBlZpViLnKIvatbW7FK4KfRaCCEuQwggPuMIIDV6ADAgECAhB+k+v7fMZO
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
# BAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIBhCAzIQcbfH
# x9TryHKz8GCoagQ9VCy0rr5gHYExqlyTMA0GCSqGSIb3DQEBAQUABIIBACP7qYQ+
# 8xpzT1CMkmW/HQSP5djrpGj1/pfiHwNDNHU10xwSGXwJN2ndELURnjaABopFfflZ
# YlWzzUKsAjZMqBAJuUeiee2ISvld/PxQmMMLivNQuytKxXznoaKLlT1M2Zw09teZ
# SbTg6XhxnQVtRU/QY9Szb+HOrV+rAbiz6ODKS8nsfBg1GSyt47amN8sOVnRh1IyJ
# Z6J9uhu0evXLW0WO8kq8JCW8U3SY8KpdHSg86D134vlHRvQ0rSjfEssgatcK1hva
# gbigdQiP1hwM57I/oll4l469BgxStUnt1HljVSwrJOOXyFCgAurm8ft3qMUpH3Q8
# pjOScRhmmi6yhBKhggILMIICBwYJKoZIhvcNAQkGMYIB+DCCAfQCAQEwcjBeMQsw
# CQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xMDAuBgNV
# BAMTJ1N5bWFudGVjIFRpbWUgU3RhbXBpbmcgU2VydmljZXMgQ0EgLSBHMgIQDs/0
# OMj+vzVuBNhqmBsaUDAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3
# DQEHATAcBgkqhkiG9w0BCQUxDxcNMTYwODA3MTgwNDA3WjAjBgkqhkiG9w0BCQQx
# FgQUrIHqYA5JdccCW3H5/j3C4xGzaH8wDQYJKoZIhvcNAQEBBQAEggEAXOuKLvWX
# s6CRHRSQD3QCW1Occuk/EN1cRvgqLy7YM88w4VArEFJd47aPghFsHCipFgneBTIF
# b9nCbkrFTHa0rcJJXgbJsx9bSgfw3t0eWOjdAF1OOWBQnYYRHIdl9KkfLxcBtE/x
# bg7AJHoviFf6rTc2fFqhJqdVrRYVQTNDDyVwQQLzr9dXzxbuP/2gLhrtSw4tifrR
# SncJyzmLi5BMPRiPZlzp+vG648DKzHM8BfqFdkhWmNE+AvaLMmmZoddtU6YtIgh/
# bXOCHUyVeUCYXo+fAi7MQ3ssV+EAoW9JMCggwLYOsBrfVWRD4+kmK4U+0+O0dWMt
# o9D7Ia2eWgh8fQ==
# SIG # End signature block
