#------------------------------------------------------------------------------
#PROCESS: 		PGPDecrypt.ps1
#PARAMS: 		$FileDecrypt, $FileOut, $Passphrase (OPTIONAL)
#USAGE:			PGPDecrypt "C:\path\to\files\*.txt" "C:\output\" "Ch1ck3n$0up4Th3$0ul"
#AUTHOR: 		Nicholas Raymond
#LAST EDITED:	16 JAN 2015
#
#DESCRIPTION:	This script takes in a file path or directory with a wildcard
#				as it's 1st parameter. It will decrypt the files to the path
#				specified as the 2nd parameter. The files are decrypted using
#               the matching key from the users' keyring executing the script.
#				Lastly, if needed a passphrase may be provided as the 3rd
#				parameter if the key being used requires one.
#------------------------------------------------------------------------------
Function PGPDecrypt {
#	Set Params
	param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$FileDecrypt = $(throw "FileDecrypt parameter is required"),
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$FileOut = $(throw "FileOut parameter is required"),
		[string]$Passphrase = ""
		)

#	Set Script Working Path & PGP App Path
	$Invocation = (Get-Variable MyInvocation -Scope 1).Value
	$ScriptPath = Split-Path $Invocation.MyCommand.Path
	$PgpPath = "${ScriptPath}\lib\gpg2.exe"
	$FileOutPath = Split-Path -Parent $FileOut
	
#	Check For File to Decrypt
	$FileDecryptFound = Test-Path $FileDecrypt
	if ($FileDecryptFound -match $False) {
		throw("ERROR: Unable to locate file to decrypt (path=${FileDecrypt})")
	}

#	Check for PGP Encryption Application
	$PgpAppFound = Test-Path $PgpPath
	if($PgpAppFound -match $False) {
		throw("ERROR: Unable to locate PGP App (path=${PgpPath})")
	}

#	Check For Existing Outbound File Directory
	$FileOutDirFound = Test-Path (Split-Path -Parent $FileOut)
	if($FileOutDirFound -match $False) {
		throw("ERROR: Directory used for exporting decrypted file not found (path=${FileOut})")
	}
	
#	If Declared, Check For Existing Passphrase File
	if($Passphrase -ne "") {
		$PassphraseFile = $ScriptPath + "\" + "passphrase.txt"
		$PassphraseFileExists = Test-Path $PassphraseFile
		if($PassphraseFileExists -eq $true) {
			Remove-Item $PassphraseFile -Force
		}
		New-Item $PassphraseFile -Type file | Out-Null
		[io.file]::WriteAllText($PassphraseFile,$Passphrase)
	}
	
#	Determine Options Set Based On Passphrase Param
	$FileDecryptOptions = " --batch --output $FileOut --passphrase-file $PassphraseFile --decrypt $FileDecrypt"
	if($PassphraseFile -eq "") {
		$FileDecryptOptions = " --batch --output $FileOut --decrypt $FileDecrypt"
	}
	
#	Run File Decryption	
	$DecryptProcess = ExecuteProcess $PgpPath $FileDecryptOptions
	$DecryptProcess | Out-Null
	if($PassphraseFile -ne "") {
		Remove-Item $PassphraseFile
	}
}