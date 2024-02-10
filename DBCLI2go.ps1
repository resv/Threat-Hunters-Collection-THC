



# Initialize Variables (go down to execution line)
$BannerA = @"

_____________________________________________________________________________

                __  ______  ___________   _____   ____________ 
               / / / / __ \/ ___/_  __/  /  _/ | / / ____/ __ \
              / /_/ / / / /\__ \ / /     / //  |/ / /_  / / / /
             / __  / /_/ /___/ // /    _/ // /|  / __/ / /_/ / 
            /_/ /_/\____//____//_/    /___/_/ |_/_/    \____/                                                     
                                                                                            
                                                     Powered by Cyber Seidon
_____________________________________________________________________________									 

"@



$BannerB = @"

_____________________________________________________________________________

                   _______  _______ __  _______  _   __
                  / ___/\ \/ / ___//  |/  / __ \/ | / /
                  \__ \  \  /\__ \/ /|_/ / / / /  |/ / 
                 ___/ /  / /___/ / /  / / /_/ / /|  /  
                /____/  /_//____/_/  /_/\____/_/ |_/                                           
                                                                                                                                    
                                                     Powered by Cyber Seidon
_____________________________________________________________________________									 

"@

$BannerC = @"

_____________________________________________________________________________

    ____  ________________     ____  __    __  ________   ________    ____
   / __ \/ ____/ ____/ __ \   / __ )/ /   / / / / ____/  / ____/ /   /  _/
  / / / / __/ / __/ / /_/ /  / __  / /   / / / / __/    / /   / /    / /  
 / /_/ / /___/ /___/ ____/  / /_/ / /___/ /_/ / /___   / /___/ /____/ /   
/_____/_____/_____/_/      /_____/_____/\____/_____/   \____/_____/___/   
                                                                                            
                                                     Powered by Cyber Seidon
_____________________________________________________________________________									 

"@

$BannerD = @"

_____________________________________________________________________________

                ___   __  ____________  ____  __  ___   _______
               /   | / / / /_  __/ __ \/ __ \/ / / / | / / ___/
              / /| |/ / / / / / / / / / /_/ / / / /  |/ /\__ \ 
             / ___ / /_/ / / / / /_/ / _, _/ /_/ / /|  /___/ / 
            /_/  |_\____/ /_/  \____/_/ |_|\____/_/ |_//____/  
                                                                                    
                                                     Powered by Cyber Seidon
_____________________________________________________________________________									 

"@


$HealthCheck = "False"
$Hostname = hostname
$Profile = $env:userprofile
$PrintWorkingDirectory = pwd
$AppURL = "https://github.com/sans-blue-team/DeepBlueCLI.git"
$ParentAppCFolder = "DBCLI"
$SysmonFolder = "Sysmon vXX.XX"
$AppBName = "Sysmon vXX.XX"
$AppCName = "DeepBlueCLI"
$AppDName = "Sysinternals"
$IPAddress = $env:HostIP = (
    Get-NetIPConfiguration |
    Where-Object {
        $_.IPv4DefaultGateway -ne $null -and
        $_.NetAdapter.Status -ne "Disconnected"
    }
).IPv4Address.IPAddress

$Menu = @" 
$BannerC
[A] Get Host information
[B] Download & Install $AppBName 
[C] Download & Run $AppCName
[D] Download & Run $AppDName 
[Z] Close and exit `n
Waiting for your input `n`n
"@



$StatusCreatedParentAppCFolder = @"
---------- [ Created folder on your desktop called `"$ParentAppCFolder`" ] ---------- `n
"@
$StatusDownloadedApp = @"
---------- [ Downloaded and extracted `"$AppCName`" ] ----------------- `n
"@
$StatusChangedDirToAppFolder = @"
---------- [ Changed working directory to `"$AppCName`" ] ------------- `n
"@


# Execution starts here:
# -------------------------------------------------------------------
while($true) {
    $readHostValue = Read-Host -Prompt "$Menu"
    switch ($readHostValue) {
        'a' {
            #Insert logic here
            return #Exits the script
        }
        'b' {
            #Insert logic here
            return #Exits the script
        }
        'c' {
            #Insert logic here
            return #Exits the script
        }
        'd' {
            #Insert logic here
            return #Exits the script
        }

        Default {
            Write-Host "Invalid Input"
        }
    }
}





# Change CWD to the desktop
set-location "$($env:userprofile)\Desktop\"


# Welcome Banner
Write-Host $Banner

#------- Some Stats -------
# Notify DBCLI URL being used
Write-host "[Application URL]:" $AppURL

# Notify working directory
Write-Host "[PWD]:" $PrintWorkingDirectory\$ParentAppCFolder

# Notify hostname & IP address
Write-Host "[Hostname]:" $Hostname
Write-Host "[Profile]:" $Profile
Write-Host "[IP Address ]:" $IPAddress

"`n"

# Create the ParentAppCFolder (Also hiding the Powershell Output)
$null = new-item -path "$($env:userprofile)\Desktop" -name $ParentAppCFolder -itemtype directory -Force
Write-Host $StatusCreatedParentAppCFolder

# Change the directory to ParentAppCFolder
set-location "$($env:userprofile)\Desktop\$ParentAppCFolder"

# Download zip file from Repo, extract zip, rename zip, delete downloaded zip file
Invoke-WebRequest 'https://github.com/sans-blue-team/DeepBlueCLI/archive/refs/heads/master.zip' -OutFile .\$AppCName.zip
Expand-Archive .\$AppCName.zip .\
Rename-Item .\$AppCName-master .\$AppCName
Remove-Item .\$AppCName.zip
Write-Host $StatusDownloadedApp

# Change the directory to AppCName
set-location "$($env:userprofile)\Desktop\$ParentAppCFolder\$AppCName"
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

