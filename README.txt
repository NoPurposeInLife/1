Set objShell = CreateObject("WScript.Shell")
Set objMouse = CreateObject("WScript.Shell")

Do
    WScript.Sleep 300000 ' Wait 5 minutes
    
    ' Move mouse slightly
    Set objWshShell = CreateObject("WScript.Shell")
    objWshShell.Run "powershell -Command [System.Windows.Forms.Cursor]::Position = New-Object System.Drawing.Point(100,100)", 0, True
    objWshShell.Run "powershell -Command [System.Windows.Forms.Cursor]::Position = New-Object System.Drawing.Point(102,102)", 0, True
Loop
