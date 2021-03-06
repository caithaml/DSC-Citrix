function Start-PsFCIV {
<#
.ExternalHelp PSPKI.Help.xml
#>
[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true, Position = 0)]
		[IO.DirectoryInfo]$Path,
		[Parameter(Mandatory = $true, Position = 1, ParameterSetName = '__xml')]
		[string]$XML,
		[Parameter(Position = 2)]
		[string]$Include = "*",
		[Parameter(Position = 3)]
		[string[]]$Exclude,
		[ValidateSet("Rename", "Delete")]
		[string]$Action,
		[ValidateSet("Bad", "Locked", "Missed", "New", "Ok", "Unknown", "All")]
		[String[]]$Show,
		[ValidateSet("MD5", "SHA1", "SHA256", "SHA384", "SHA512")]
		[AllowEmptyCollection()]
		[String[]]$HashAlgorithm = "SHA1",
		[switch]$Recurse,
		[switch]$Rebuild,
		[switch]$Quiet,
		[switch]$NoStatistic,
		[Parameter(ParameterSetName = '__online')]
		[switch]$Online
	)

#region C# wrappers
Add-Type @"
using System;
using System.Collections.Generic;
using System.Xml.Serialization;
namespace PsFCIV {
	public class StatTable {
		public List<String> Total = new List<String>();
		public List<String> New = new List<String>();
		public List<String> Ok = new List<String>();
		public List<String> Bad = new List<String>();
		public List<String> Missed = new List<String>();
		public List<String> Locked = new List<String>();
		public List<String> Unknown = new List<String>();
		public int Del;
	}
	public class IntStatTable {
		public Int32 Total;
		public Int32 New;
		public Int32 Ok;
		public Int32 Bad;
		public Int32 Missed;
		public Int32 Locked;
		public Int32 Unknown;
		public Int32 Del;
	}
	[XmlType(AnonymousType = true)]
	[XmlRoot(Namespace = "", IsNullable = false)]
	public class FCIV {
		public FCIV() { FILE_ENTRY = new List<FCIVFILE_ENTRY>(); }
		
		[XmlElement("FILE_ENTRY")]
		public List<FCIVFILE_ENTRY> FILE_ENTRY { get; set; }
	}
	[XmlType(AnonymousType = true)]
	public class FCIVFILE_ENTRY {
		public FCIVFILE_ENTRY() { }
		public FCIVFILE_ENTRY(string path) { name = path; }

		public String name { get; set; }
		public UInt64 Size { get; set; }
		public String TimeStamp { get; set; }
		public String MD5 { get; set; }
		public String SHA1 { get; set; }
		public String SHA256 { get; set; }
		public String SHA384 { get; set; }
		public String SHA512 { get; set; }

		public override Int32 GetHashCode() { return name.GetHashCode(); }
		public override Boolean Equals(Object other) {
			if (ReferenceEquals(null, other) || other.GetType() != GetType()) { return false; }
			return other.GetType() == GetType() && String.Equals(name, ((FCIVFILE_ENTRY)other).name);
		}
	}
}
"@ -Debug:$false -Verbose:$false -ReferencedAssemblies "System.Xml"
Add-Type -AssemblyName System.Xml
#endregion
	
	if ($PSBoundParameters.Verbose) {$VerbosePreference = "continue"}
	if ($PSBoundParameters.Debug) {$DebugPreference = "continue"}
	$oldverb = $host.PrivateData.VerboseForegroundColor
	$olddeb = $host.PrivateData.DebugForegroundColor
	# preserving current path
	$oldpath = $pwd.Path
	$Exclude += $XML

	if (Test-Path -LiteralPath $path) {
		Set-Location -LiteralPath $path
		if ($pwd.Provider.Name -ne "FileSystem") {
			Set-Location $oldpath
			throw "Specified path is not filesystem path. Try again!"
		}
	} else {throw "Specified path not found."}
	
	# statistic variables
	$sum = $new = New-Object PsFCIV.FCIV
	# creating statistics variable with properties. Each property will contain file names (and paths) with corresponding status.
	$global:stats = New-Object PsFCIV.StatTable
	$script:statcount = New-Object PsFCIV.IntStatTable
	
	# lightweight proxy function for Get-ChildItem cmdlet
	function dirx ([string]$Path, [string]$Filter, [string[]]$Exclude, $Recurse, [switch]$Force) {
		Get-ChildItem @PSBoundParameters -ErrorAction SilentlyContinue | Where-Object {!$_.psiscontainer}
	}	
	# internal function that will check whether the file is locked. All locked files are added to a group with 'Unknown' status.
	function __filelock ($file) {
		$locked = $false
		trap {Set-Variable -name locked -value $true -scope 1; continue}
		$inputStream = New-Object IO.StreamReader $file.FullName
		if ($inputStream) {$inputStream.Close()}
		if ($locked) {
			$host.PrivateData.VerboseForegroundColor = "Yellow"
			$host.PrivateData.DebugForegroundColor = "Yellow"
			Write-Verbose "File $($file.Name) is locked. Skipping this file.."
			Write-Debug "File $($file.Name) is locked. Skipping this file.."
			__statcounter $filename Locked
		}
		$locked
	}	
	# internal function to generate UI window with results by using Out-GridView cmdlet.
	function __formatter ($props, $max) {
		$total = @($input)
		foreach ($property in $props) {
			$(for ($n = 0; $n -lt $max; $n++) {
				$total[0] | Select-Object @{n = $property; e = {$_.$property[$n]}}
			}) | Out-GridView -Title "File list by category: $property"
		}
	}
	# internal hasher
	function __hashbytes ($type, $file) {
		$hasher = [Security.Cryptography.HashAlgorithm]::Create($type)
		$inputStream = New-Object IO.StreamReader $file.FullName
		$hashBytes = $hasher.ComputeHash($inputStream.BaseStream)
		$hasher.Clear()
		$inputStream.Close()
		$hashBytes
	}
	# internal function which reads the XML file (if exist).
	function __fromxml ($xml) {
	# reading existing XML file and selecting required properties
		if (!(Test-Path -LiteralPath $XML)) {return New-Object PsFCIV.FCIV}
		try {
			$fs = New-Object IO.FileStream $XML, "Open"
			$xmlser = New-Object System.Xml.Serialization.XmlSerializer ([Type][PsFCIV.FCIV])
			$sum = $xmlser.Deserialize($fs)
			$fs.Close()
			$sum
		} catch {
			Write-Error -Category InvalidData -Message "Input XML file is not valid FCIV XML file."
		} finally {
			if ($fs -ne $null) {$fs.Close()}
		}
		
	}
	# internal xml writer
	function __writexml ($sum) {
		if ($sum.FILE_ENTRY.Count -eq 0) {
			$host.PrivateData.VerboseForegroundColor = "Yellow"
			$host.PrivateData.DebugForegroundColor = "Yellow"
			Write-Verbose "There is no data to write to XML database."
			Write-Debug "There is no data to write to XML database."
		} else {
			$host.PrivateData.DebugForegroundColor = "Cyan"
			Write-Debug "Preparing to DataBase file creation..."
			try {
				$fs = New-Object IO.FileStream $XML, "Create"
				$xmlser = New-Object System.Xml.Serialization.XmlSerializer ([Type][PsFCIV.FCIV])
				$xmlser.Serialize($fs,$sum)
			} finally {
				if ($fs -ne $null) {$fs.Close()}
			}
			Write-Debug "DataBase file created..."
		}
	}
	# internal function to create XML entry object for a file.
	function __makeobject ($file, [switch]$NoHash, [switch]$hex) {
		$host.PrivateData.DebugForegroundColor = "Yellow"
		Write-Debug "Starting object creation for '$($file.FullName)'..."
		$object = New-Object PsFCIV.FCIVFILE_ENTRY
		$object.name = $file.FullName -replace [regex]::Escape($($pwd.ProviderPath + "\"))
		$object.Size = $file.Length
		# use culture-invariant date/time format.
		$object.TimeStamp = "$($file.LastWriteTime.ToUniversalTime())"
		if (!$NoHash) {
		# calculating appropriate hash and convert resulting byte array to a Base64 string
			foreach ($hash in "MD5", "SHA1", "SHA256", "SHA384", "SHA512") {
				if ($HashAlgorithm -contains $hash) {
					Write-Debug "Calculating '$hash' hash..."
					$hashBytes = __hashbytes $hash $file
					if ($hex) {
						$object.$hash = -join ($hashBytes | Foreach-Object {"{0:X2}" -f $_})
					} else {
						Write-Debug ("Calculated hash value: " + (-join ($hashBytes | Foreach-Object {"{0:X2}" -f $_})))
						$object.$hash = [System.Convert]::ToBase64String($hashBytes)
					}
				}
			}
		}
		Write-Debug "Object created!"
		$object
	}	
	# internal function that calculates current file hash and formats it to an octet string (for example, B926D7416E8235E6F94F756E9F3AE2F33A92B2C4).
	function __precheck ($entry, $file, $HashAlgorithm) {
		$host.PrivateData.DebugForegroundColor = "Yellow"
		if ($HashAlgorithm.Length -gt 0) {
			$SelectedHash = $HashAlgorithm
		} else {
			:outer foreach ($hash in "SHA512", "SHA384", "SHA256", "SHA1", "MD5") {
				if ($entry.$hash) {$SelectedHash = $hash; break outer}
			}
		}
		$host.PrivateData.DebugForegroundColor = "Green"
		Write-Debug "Selected hash: $hash"
		-join ($(__hashbytes $SelectedHash $file) | ForEach-Object {"{0:X2}" -f $_})
		$SelectedHash
	}
	# process -Action parameter to perform an action against bad file (if actual file properties do not match the record in XML).
	function __takeaction ($file, $Action) {
		switch ($Action) {
			"Rename" {Rename-Item $file $($file.FullName + ".bad")}
			"Delete" {Remove-Item $file -Force}
		}
	}	
	# core file verification function.
	function __checkfiles ($entry, $file, $Action) {
		if (($file.Length -eq $entry.Size) -and ("$($file.LastWriteTime.ToUniversalTime())" -eq $entry.TimeStamp)) {
			$hexhash = __precheck $entry $file $HashAlgorithm
			$ActualHash = -join ([Convert]::FromBase64String($entry.($hexhash[1])) | ForEach-Object {"{0:X2}" -f $_})
			if (!$ActualHash) {
				$host.PrivateData.VerboseForegroundColor = "Red"
				Write-Verbose "XML database entry does not contains '$($hexhash[1])' hash value for the entry '$($entry.name)'."
				__statcounter $entry.name Unknown
				return
			} elseif ($ActualHash -eq $hexhash[0]) {
				$host.PrivateData.VerboseForegroundColor = $Host.PrivateData.DebugForegroundColor = "Green"
				Write-Debug "File hash: $ActualHash"
				Write-Verbose "File '$($file.name)' is ok."
				__statcounter $entry.name Ok
				return
			} else {
				$host.PrivateData.DebugForegroundColor = "Red"
				Write-Debug "File '$($file.name)' failed hash verification.
					Expected hash: $hexhash
					Actual hash: $ActualHash"
				__statcounter $entry.name Bad
				if ($Action) {__takeaction $file $Action}
			}
		} else {
			$host.PrivateData.VerboseForegroundColor = $Host.PrivateData.DebugForegroundColor = "Red"
			Write-Verbose "File '$($file.FullName)' size or Modified Date/Time mismatch."
			Write-Debug "Expected file size is: $($entry.Size) byte(s), actual size is: $($file.Length) byte(s)."
			Write-Debug "Expected file modification time is: $($entry.TimeStamp), actual file modification time is: $($file.LastWriteTime.ToUniversalTime())"
			__statcounter $entry.name Bad
			if ($Action) {__takeaction $file $Action}
		}
	}
	# internal function to calculate resulting statistics and show if if necessary.	
	function __stats {
	# if -Show parameter is presented we display selected groups (Total, New, Ok, Bad, Missed, Unknown)
		if ($show -and !$NoStatistic) {
			if ($Show -eq "All" -or $Show.Contains("All")) {
				$global:stats | __formatter "Bad", "Locked", "Missed", "New", "Ok", "Unknown" $script:statcount.Total
			} else {
				$global:stats | Select-Object $show | __formatter $show $script:statcount.Total
			}			
		}
		# script work in numbers
		if (!$Quiet) {
			Write-Host ----------------------------------- -ForegroundColor Green
			if ($Rebuild) {
				Write-Host Total entries processed: $script:statcount.Total -ForegroundColor Cyan
				Write-Host Total removed unused entries: $script:statcount.Del -ForegroundColor Yellow
			} else {Write-Host Total files processed: $script:statcount.Total -ForegroundColor Cyan}
			Write-Host Total new added files: $script:statcount.New -ForegroundColor Green
			Write-Host Total good files: $script:statcount.Ok -ForegroundColor Green
			Write-Host Total bad files: $script:statcount.Bad -ForegroundColor Red
			Write-Host Total unknown status files: $script:statcount.Unknown -ForegroundColor Yellow
			Write-Host Total missing files: $script:statcount.Missed -ForegroundColor Yellow
			Write-Host Total locked files: $script:statcount.Locked -ForegroundColor Yellow
			Write-Host ----------------------------------- -ForegroundColor Green
		}
		# restore original variables
		Set-Location -LiteralPath $oldpath
		$host.PrivateData.VerboseForegroundColor = $oldverb
		$host.PrivateData.DebugForegroundColor = $olddeb
		$exit = 0
		# create exit code depending on check status
		if ($Rebuild) {$exit = [int]::MaxValue} else {
			if ($script:statcount.Bad -ne 0) {$exit += 1}
			if ($script:statcount.Missed -ne 0) {$exit += 2}
			if ($script:statcount.Unknown -ne 0) {$exit += 4}
			if ($script:statcount.Locked -ne 0) {$exit += 8}
		}
		if ($Quiet) {exit $exit}
	}
	# internal function to update statistic counters.
	function __statcounter ($filename, $status) {
		$script:statcount.$status++
		$script:statcount.Total++
		if (!$NoStatistic) {
			$global:stats.$status.Add($filename)
		}
	}
	if ($Online) {
		$host.PrivateData.DebugForegroundColor = "White"
		Write-Debug "Online mode ON"
		dirx -Path .\* -Filter $Include -Exclude $Exclude $Recurse -Force | ForEach-Object {
			$host.PrivateData.VerboseForegroundColor = $Host.UI.RawUI.ForegroundColor
			Write-Verbose "Perform file '$($_.fullName)' checking."
			$file = Get-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
			if (__filelock $file) {return}
			__makeobject $file -hex
		}
		return
	}

	<#
	in this part we perform XML file update by removing entries for non-exist files and
	adding new entries for files that are not in the database.
	#>
	if ($Rebuild) {
		$host.PrivateData.DebugForegroundColor = "White"
		Write-Debug "Rebuild mode ON"
		if (Test-Path -LiteralPath $xml) {
			$old = __fromxml $xml
		} else {
			Set-Location $oldpath
			throw "Unable to find XML file. Please, run the command without '-Rebuild' switch."
		}
		$interm = New-Object PsFCIV.FCIV
		# use foreach-object instead of where-object to keep original types.
		$host.PrivateData.VerboseForegroundColor = $host.UI.RawUI.ForegroundColor
		Write-Verbose "Perform DB file cleanup from non-existent items."
		$old.FILE_ENTRY | ForEach-Object {
			if ((Test-Path -LiteralPath $_.name)) {
				if ($_.name -eq $xml) {
					$host.PrivateData.DebugForegroundColor = "Yellow"
					Write-Debug "File '$($_.name)' is DB file. Removed."
				} else {
					$interm.FILE_ENTRY.Add($_)
				}
			} else {
				$host.PrivateData.DebugForegroundColor = "Yellow"
				Write-Debug "File '$($_.name)' does not exist. Removed."
			}
		}
		$script:statcount.Del = $interm.Length
		$script:statcount.Total = $old.FILE_ENTRY.Count - $interm.Length
		dirx -Path .\* -Filter $Include -Exclude $Exclude $Recurse -Force | ForEach-Object {
			$host.PrivateData.VerboseForegroundColor = $host.UI.RawUI.ForegroundColor
			Write-Verbose "Perform file '$($_.FullName)' checking."
			$file = Get-Item -LiteralPath $_.FullName -Force
			if (__filelock $file) {return}
			$filename = $file.FullName -replace [regex]::Escape($($pwd.providerpath + "\"))
			$host.PrivateData.VerboseForegroundColor = "Green"
			if ($interm.FILE_ENTRY.Contains((New-Object PsFCIV.FCIVFILE_ENTRY $filename))) {
				Write-Verbose "File '$filename' already exist in XML database. Skipping."
				return
			} else {
				$new.FILE_ENTRY.Add((__makeobject $file))
				Write-Verbose "File '$filename' is added."
				__statcounter $filename New
			}
		}
		$interm.FILE_ENTRY.AddRange($new.FILE_ENTRY)
		__writexml $interm
		__stats
		return
	}
	
	# this part contains main routine
	$sum = __fromxml $xml
	<#
	check XML file format. If Size property of the first element is zero, then the file was generated by
	original FCIV.exe tool. In this case we transform existing XML to a new PsFCIV format by adding new
	properties. Each record is checked against hashes stored in the source XML file. If hash check fails,
	an item is removed from final XML.
	#>
	if ($sum.FILE_ENTRY.Count -gt 0 -and $sum.FILE_ENTRY[0].Size -eq 0) {
		# 
		if ($PSBoundParameters.ContainsKey("HashAlgorithm")) {$HashAlgorithm = $HashAlgorithm[0].ToUpper()} else {$HashAlgorithm = @()}
		$host.PrivateData.DebugForegroundColor = "White"
		Write-Debug "FCIV (compatibility) mode ON"
		if ($HashAlgorithm -and $HashAlgorithm -notcontains "sha1" -and $HashAlgorithm -notcontains "md5") {
			throw "Specified hash algorithm (or algorithms) is not supported. For native FCIV source, use MD5 and/or SHA1."
		}
		for ($index = 0; $index -lt $sum.FILE_ENTRY.Count; $index++) {
			$host.PrivateData.VerboseForegroundColor = $host.UI.RawUI.ForegroundColor
			Write-Verbose "Perform file '$($sum.FILE_ENTRY[$index].name)' checking."
			$filename = $sum.FILE_ENTRY[$index].name
			# check if the path is absolute and matches current path. If the path is absolute and does not belong to
			# current path -- skip this entry.
			if ($filename.Contains(":") -and $filename -notmatch [regex]::Escape($pwd.ProviderPath)) {return}
			# if source file name record contains absolute path, and belongs to the current pathe,
			# just strip base path. New XML format uses relative paths only.
			if ($filename.Contains(":")) {$filename = $filename -replace ([regex]::Escape($($pwd.ProviderPath + "\")))}
			# Test if the file exist. If the file does not exist, skip the current entry and process another record.
			if (!(Test-Path -LiteralPath $filename)) {
				$host.PrivateData.VerboseForegroundColor = "Yellow"
				Write-Verbose "File '$filename' not found. Skipping."
				__statcounter $filename Missed
				return
			}
			# get file item and test if it is not locked by another application
			$file = Get-Item -LiteralPath $filename -Force -ErrorAction SilentlyContinue
			if (__filelock $file) {return}
			# create new-style entry record that stores additional data: file length and last modification timestamp.
			$entry = __makeobject $file -NoHash
			$entry.name = $filename
			# process current hash entries and copy required hash values to a new entry object.
			"SHA1", "MD5" | ForEach-Object {$entry.$_ = $sum.FILE_ENTRY[$index].$_}
			$sum.FILE_ENTRY[$index] = $entry
			__checkfiles $newentry $file $Action
		}
		# we are done. Overwrite XML, display stats and exit.
		__writexml $sum
		# display statistics and exit right now.
		__stats
	}
	# if XML file exist, proccess and check all records. XML file will not be modified.
	if ($sum.FILE_ENTRY.Count -gt 0) {
		$host.PrivateData.DebugForegroundColor = "White"
		Write-Debug "Native PsFCIV mode ON"
		# this part is executed only when we want to process certain file. Wildcards are not allowed.
		if ($Include -ne "*") {
			$sum.FILE_ENTRY | Where-Object {$_.name -like $Include} | ForEach-Object {
				$host.PrivateData.VerboseForegroundColor = $host.UI.RawUI.ForegroundColor
				Write-Verbose "Perform file '$($_.name)' checking."
				$entry = $_
				# calculate the hash if the file exist.
				if (Test-Path -LiteralPath $entry.name) {
					# and check file integrity
					$file = Get-Item -LiteralPath $entry.name -Force -ErrorAction SilentlyContinue
					__checkfiles $entry $file $Action
				} else {
					# if there is no record for the file, skip it and display appropriate message
					$host.PrivateData.VerboseForegroundColor = "Yellow"
					Write-Verbose "File '$filename' not found. Skipping."
					__statcounter $entry.name Missed
				}
			}
		} else {
			$sum.FILE_ENTRY | ForEach-Object {
				<#
				to process files only in the current directory (without subfolders), we remove items
				that contain slashes from the process list and continue regular file checking.
				#>
				if (!$Recurse -and $_.name -match "\\") {return}
				$host.PrivateData.VerboseForegroundColor = $host.UI.RawUI.ForegroundColor
				Write-Verbose "Perform file '$($_.name)' checking."
				$entry = $_
				if (Test-Path -LiteralPath $entry.name) {
					$file = Get-Item -LiteralPath $entry.name -Force -ErrorAction SilentlyContinue
					__checkfiles $entry $file $Action
				} else {
					$host.PrivateData.VerboseForegroundColor = "Yellow"
					Write-Verbose "File '$($entry.name)' not found. Skipping."
					__statcounter $entry.name Missed
				}
			}
		}
	} else {
		# if there is no existing XML DB file, start from scratch and create a new one.
		$host.PrivateData.DebugForegroundColor = "White"
		Write-Debug "New XML mode ON"

		dirx -Path .\* -Filter $Include -Exclude $Exclude $Recurse -Force | ForEach-Object {
			$_
			# $host.PrivateData.VerboseForegroundColor = $Host.UI.RawUI.ForegroundColor
			# Write-Verbose "Perform file '$($_.fullName)' checking."
			# $file = Get-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
			# if (__filelock $file) {return}
			# $entry = __makeobject $file
			# $sum.FILE_ENTRY.Add($entry)
			# __statcounter $entry.name New
		}
		__writexml $sum
	}
	__stats
}
# SIG # Begin signature block
# MIIX1gYJKoZIhvcNAQcCoIIXxzCCF8MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCh54G+7BnjUc2T
# VlNgo0WdRcbYHLAtcSrMGdoBXdwbhqCCEuQwggPuMIIDV6ADAgECAhB+k+v7fMZO
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
# BAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIKcC4coYcSre
# bMoP1brm3/BvZ//aOrgGFgileMCztTmwMA0GCSqGSIb3DQEBAQUABIIBABckyfUa
# XSXLyBerbXPwKjs/LcFtl5hgeWhhjizBsLMa2R7u69WlSFcAy5cmB/oRB5JhqIsd
# mIFVRuAh04FufoT2LA0K7GKf/sU1H5wxIip9PDBQ7vp6jrmg24yk2vU8Zm+XwWwx
# 5ATHht8NCcpvnbI48fgvOgQkiFn95v6RIWDI0hQNL2ZNy9m/Um8pokvnq5fvpCTH
# 0ENW0kgU2XSdM1s1B1prJ1LlBKljjBvohiVV2RatAHkmwiDRcvQydU19SJH2HazK
# Od2iAm+yIaul2z+8qd+flFptbdz5HjZKTEveHWD5vJyVhds6jmuBI8lRMmYmLBXj
# BJP3z3aqjh8QtVKhggILMIICBwYJKoZIhvcNAQkGMYIB+DCCAfQCAQEwcjBeMQsw
# CQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xMDAuBgNV
# BAMTJ1N5bWFudGVjIFRpbWUgU3RhbXBpbmcgU2VydmljZXMgQ0EgLSBHMgIQDs/0
# OMj+vzVuBNhqmBsaUDAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3
# DQEHATAcBgkqhkiG9w0BCQUxDxcNMTYwODA3MTgwMTQ4WjAjBgkqhkiG9w0BCQQx
# FgQU+6FAFCREHWGxD6m1B6vkJNGwqTowDQYJKoZIhvcNAQEBBQAEggEAOjf1PaZU
# ftJH4zb3Y+n6BjrxKTppz9gx6d9Ygb5nPvg+WLABwOsB9PPmKWjxt35f5c+lieTh
# JDZvCsY4+LQwYAFuTbquyubqDf1JQ2QmNMtsYUNZnR0Qm1bcjlYrxOhxcuTN1pX6
# 5xte1pEF+h1WGuMxdqZEpoPbj5kpplecU0b95F5ZOnLTde3KgcK60pCVjozmxvQq
# 9jTBzEhAJqlr4LzLrBxmlrObBLH5ygI2kKekyMJ/9Lgr6we3kblvP1NfeGZf4rKY
# yGh1UIFF+3TYuRSeI9Fcc+hst3F1yOJaIH3upHmMRV6SGUmxec221YPWHYAHCv+C
# nQ7T8XeajTYpNg==
# SIG # End signature block
