#------------------------------------------------------------------------------
#PROCESS: 		PGPEncrypt.ps1
#PARAMS: 		$FileEncrypt, $FileEncryptKey, $FileOut
#USAGE:			PGPEncrypt "C:\path\to\files\*.txt" "Nameofmykey@email.com" "C:\output"
#AUTHOR: 		Nicholas Raymond
#LAST EDITED:	16 JAN 2015
#
#DESCRIPTION:	This script takes in a file path or directory with a wildcard
#				as it's 1st parameter. It will encrypt the files using the
#				encryption key provided as the 2nd parameter. Last, specify
#				where the encrypted files should be saved to.
#				NOTE: The encryption key used needs to have already been
#				imported into the users' keyring that is executing this script.
#------------------------------------------------------------------------------
Function PGPEncrypt {
#	Set Params
	param(
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$FileEncrypt = $(throw "FileEncrypt parameter is required"),
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$FileEncryptKey = $(throw "FileEncryptKey parameter is required"),
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$FileOut = $(throw "FileOut parameter is required")
		)

#	Set Script Working Path & PGP App Path
	$Invocation = (Get-Variable MyInvocation -Scope 1).Value
	$ScriptPath = Split-Path $Invocation.MyCommand.Path
	$PgpPath = "${ScriptPath}\lib\gpg2.exe"
	$FileOutPath = Split-Path -Parent $FileOut
	
#	Check For File to Encrypt
	$FileEncryptFound = Test-Path $FileEncrypt
	if ($FileEncryptFound -match $False) {
		throw("ERROR: Unable to locate file to encrypt (path=${FileEncrypt})")
	}

#	Check for PGP Encryption Application
	$PgpAppFound = Test-Path $PgpPath
	if($PgpAppFound -match $False) {
		throw("ERROR: Unable to locate PGP App (path=${PgpPath})")
	}

#	Check For Existing Outbound File Directory
	$FileOutDirFound = Test-Path (Split-Path -Parent $FileOut)
	if($FileOutDirFound -match $False) {
		throw("ERROR: Directory used for exporting encrypted file not found (path=${FileOut})")
	}
	
#	Create Structured Parameters for Encryption Call		
	$FileEncryptOptions = " --encrypt --recipient `"$FileEncryptKey`" --output `"$FileOut`" `"$FileEncrypt`""
	
#	Run File Encryption	
	$EncryptProcess = ExecuteProcess $PgpPath $FileEncryptOptions
	$EncryptProcess | Out-Null
}