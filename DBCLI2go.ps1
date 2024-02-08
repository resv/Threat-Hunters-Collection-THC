$Text = @"

_____________________________________________________________________________

    ____  ________________     ____  __    __  ________   ________    ____
   / __ \/ ____/ ____/ __ \   / __ )/ /   / / / / ____/  / ____/ /   /  _/
  / / / / __/ / __/ / /_/ /  / __  / /   / / / / __/    / /   / /    / /  
 / /_/ / /___/ /___/ ____/  / /_/ / /___/ /_/ / /___   / /___/ /____/ /   
/_____/_____/_____/_/      /_____/_____/\____/_____/   \____/_____/___/   
                                                                                            
                                                     Powered by Cyber Seidon
_____________________________________________________________________________									 

"@

# Initialize Variables
$Hostname = hostname
$Profile = $env:userprofile
$PrintWorkingDirectory = pwd
$AppURL = "https://github.com/sans-blue-team/DeepBlueCLI.git"
$AppFolder = "DBCLI"
$AppName = "DeepBlueCLI"
$IPAddress = $env:HostIP = (
    Get-NetIPConfiguration |
    Where-Object {
        $_.IPv4DefaultGateway -ne $null -and
        $_.NetAdapter.Status -ne "Disconnected"
    }
).IPv4Address.IPAddress



# Execution starts here:
# -------------------------------------------------------------------
# Change CWD to the desktop
set-location "$($env:userprofile)\Desktop\"

# Banner
Write-Host $Text

#------- Some Stats -------
# Notify DBCLI URL being used
Write-host "[Application URL]:" $AppURL

# Notify working directory
Write-Host "[PWD]:" $PrintWorkingDirectory\$AppFolder

# Notify hostname & IP address
Write-Host "[Hostname]:" $Hostname
Write-Host "[Profile]:" $Profile
Write-Host "[IP Address ]:" $IPAddress
Write-Host ""
Write-Host ""
Write-Host "*************************************************************"
Write-Host "********* Creating `"$AppFolder`" folder on your desktop ***********"
Write-Host "*************************************************************"
Write-Host ""
Write-Host ""

# Create the AppFolder (Also hiding the Powershell Output)
$null = new-item -path "$($env:userprofile)\Desktop" -name $AppFolder -itemtype directory -Force

# Change the directory to AppFolder
set-location "$($env:userprofile)\Desktop\$AppFolder"

#--------
Invoke-WebRequest 'https://github.com/sans-blue-team/DeepBlueCLI/archive/refs/heads/master.zip' -OutFile .\$AppName.zip
Expand-Archive .\$AppName.zip .\
Rename-Item .\$AppName-master .\$AppName
Remove-Item .\$AppName.zip
