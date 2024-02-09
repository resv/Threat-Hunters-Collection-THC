



# Initialize Variables (go down to execution line)
$Banner = @"

_____________________________________________________________________________

    ____  ________________     ____  __    __  ________   ________    ____
   / __ \/ ____/ ____/ __ \   / __ )/ /   / / / / ____/  / ____/ /   /  _/
  / / / / __/ / __/ / /_/ /  / __  / /   / / / / __/    / /   / /    / /  
 / /_/ / /___/ /___/ ____/  / /_/ / /___/ /_/ / /___   / /___/ /____/ /   
/_____/_____/_____/_/      /_____/_____/\____/_____/   \____/_____/___/   
                                                                                            
                                                     Powered by Cyber Seidon
_____________________________________________________________________________									 

"@

$HealthCheck = "False"
$Hostname = hostname
$Profile = $env:userprofile
$PrintWorkingDirectory = pwd
$AppURL = "https://github.com/sans-blue-team/DeepBlueCLI.git"
$ParentAppFolder = "DBCLI"
$AppName = "DeepBlueCLI"
$IPAddress = $env:HostIP = (
    Get-NetIPConfiguration |
    Where-Object {
        $_.IPv4DefaultGateway -ne $null -and
        $_.NetAdapter.Status -ne "Disconnected"
    }
).IPv4Address.IPAddress


$StatusCreatedParentAppFolder = @"
---------- [ Created folder on your desktop called `"$ParentAppFolder`" ] ---------- `n
"@
$StatusDownloadedApp = @"
---------- [ Downloaded and extracted `"$AppName`" ] ----------------- `n
"@
$StatusChangedDirToAppFolder = @"
---------- [ Changed working directory to `"$AppName`" ] ------------- `n
"@


# Execution starts here:
# -------------------------------------------------------------------
# Change CWD to the desktop
set-location "$($env:userprofile)\Desktop\"


# Welcome Banner
Write-Host $Banner

#------- Some Stats -------
# Notify DBCLI URL being used
Write-host "[Application URL]:" $AppURL

# Notify working directory
Write-Host "[PWD]:" $PrintWorkingDirectory\$ParentAppFolder

# Notify hostname & IP address
Write-Host "[Hostname]:" $Hostname
Write-Host "[Profile]:" $Profile
Write-Host "[IP Address ]:" $IPAddress

"`n"

# Create the ParentAppFolder (Also hiding the Powershell Output)
$null = new-item -path "$($env:userprofile)\Desktop" -name $ParentAppFolder -itemtype directory -Force
Write-Host $StatusCreatedParentAppFolder

# Change the directory to ParentAppFolder
set-location "$($env:userprofile)\Desktop\$ParentAppFolder"

# Download zip file from Repo, extract zip, rename zip, delete downloaded zip file
Invoke-WebRequest 'https://github.com/sans-blue-team/DeepBlueCLI/archive/refs/heads/master.zip' -OutFile .\$AppName.zip
Expand-Archive .\$AppName.zip .\
Rename-Item .\$AppName-master .\$AppName
Remove-Item .\$AppName.zip
Write-Host $StatusDownloadedApp

# Change the directory to AppName
set-location "$($env:userprofile)\Desktop\$ParentAppFolder\$AppName"
Write-Host $StatusChangedDirToAppFolder

# Check if staging and initialization is complete
$HealthCheck = "True"

if ($HealthCheck -eq "True")
{
    Write-Host "`n Ready for Hunting... `n"
}
else
{
    Write-Host "Intialization process has failed..."
}

