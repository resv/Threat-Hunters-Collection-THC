INS::
Send, cd ~
Sleep, 100
Send, {Enter}
Sleep, 100
Send, cd .\Desktop\THC
Sleep, 100
Send, {Enter}
Sleep, 100
Send, powershell.exe -noprofile -executionpolicy bypass -file .\THC.ps1
Sleep, 100
Send, {Enter}
Sleep, 500
Sleep, 100
return
