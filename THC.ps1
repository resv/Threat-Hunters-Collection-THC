
#(go down to execution line)


# VARIABLES - BANNERS
$Banner= @"
_________________________________________________________________________________
  ________  ______  _________  ______   __  ____  ___   __________________  _____
 /_  __/ / / / __ \/ ____/   |/_  __/  / / / / / / / | / /_  __/ ____/ __ \/ ___/
  / / / /_/ / /_/ / __/ / /| | / /    / /_/ / / / /  |/ / / / / __/ / /_/ /\__ \ 
 / / / __  / _, _/ /___/ ___ |/ /    / __  / /_/ / /|  / / / / /___/ _, _/___/ / 
/_/ /_/ /_/_/_|_/_____/_/  |_/_/   _/_/_/_/\____/_/_|_/_/_/_/_____/_/ |_|/____/  
          / ____/ __ \/ /   / /   / ____/ ____/_  __/  _/ __ \/ | / /            
         / /   / / / / /   / /   / __/ / /     / /  / // / / /  |/ /             
        / /___/ /_/ / /___/ /___/ /___/ /___  / / _/ // /_/ / /|  /              
        \____/\____/_____/_____/_____/\____/ /_/ /___/\____/_/ |_/
                                            Catalyzed with purpose by: Adam Kim
_________________________________________________________________________________

"@

$BannerA = @"
_________________________________________________________________________________
                    __  ______  ___________   _____   ____________ 
                   / / / / __ \/ ___/_  __/  /  _/ | / / ____/ __ \
                  / /_/ / / / /\__ \ / /     / //  |/ / /_  / / / /
                 / __  / /_/ /___/ // /    _/ // /|  / __/ / /_/ / 
                /_/ /_/\____//____//_/    /___/_/ |_/_/    \____/   
_________________________________________________________________________________

"@

$BannerB = @"
_________________________________________________________________________________
                       _______  _______ __  _______  _   __
                      / ___/\ \/ / ___//  |/  / __ \/ | / /
                      \__ \  \  /\__ \/ /|_/ / / / /  |/ / 
                     ___/ /  / /___/ / /  / / /_/ / /|  /  
                    /____/  /_//____/_/  /_/\____/_/ |_/
_________________________________________________________________________________

"@

$BannerC = @"
_________________________________________________________________________________
        ____  ________________     ____  __    __  ________   ________    ____
       / __ \/ ____/ ____/ __ \   / __ )/ /   / / / / ____/  / ____/ /   /  _/
      / / / / __/ / __/ / /_/ /  / __  / /   / / / / __/    / /   / /    / /  
     / /_/ / /___/ /___/ ____/  / /_/ / /___/ /_/ / /___   / /___/ /____/ /   
    /_____/_____/_____/_/      /_____/_____/\____/_____/   \____/_____/___/
_________________________________________________________________________________

"@

$BannerD = @"
_________________________________________________________________________________
                    ___   __  ____________  ____  __  ___   _______
                   /   | / / / /_  __/ __ \/ __ \/ / / / | / / ___/
                  / /| |/ / / / / / / / / / /_/ / / / /  |/ /\__ \ 
                 / ___ / /_/ / / / / /_/ / _, _/ /_/ / /|  /___/ / 
                /_/  |_\____/ /_/  \____/_/ |_|\____/_/ |_//____/
_________________________________________________________________________________

"@

$BannerE = @"
_________________________________________________________________________________
               ________________   _____ _________    ____  ________  __
              / ____/_  __/  _/  / ___// ____/   |  / __ \/ ____/ / / /
             / /     / /  / /    \__ \/ __/ / /| | / /_/ / /   / /_/ / 
            / /___  / / _/ /    ___/ / /___/ ___ |/ _, _/ /___/ __  /  
            \____/ /_/ /___/   /____/_____/_/  |_/_/ |_|\____/_/ /_/
_________________________________________________________________________________

"@

$BannerX = @"
_________________________________________________________________________________
                   __________  _   ___________   ____________
                  / ____/ __ \/ | / /_  __/   | / ____/_  __/
                 / /   / / / /  |/ / / / / /| |/ /     / /   
                / /___/ /_/ / /|  / / / / ___ / /___  / /    
                \____/\____/_/ |_/ /_/ /_/  |_\____/ /_/
_________________________________________________________________________________

"@


$HealthCheck = "False"

# VARIABLES - ParentFolder
$ParentFolder = "Threat Hunters Collection"

# VARIABLES - AppA (Host Info)
    $AppAName = "Host Info"
    $AppAdescription = "Spec viewer"
    $Hostname = hostname
    $Profile = $env:userprofile
    $PrintWorkingDirectory = pwd
        #Grab IP info
        $IPAddress = $env:HostIP = (
            Get-NetIPConfiguration |
            Where-Object {
                $_.IPv4DefaultGateway -ne $null -and
                $_.NetAdapter.Status -ne "Disconnected"
            }
        ).IPv4Address.IPAddress


# VARIABLES - AppB (Sysmon)
    $AppBName = "Sysmon vXX.XX"
    $AppBdescription = "Event Collector"
    $ParentAppCFolder = "DBCLI"
    $MenuAppC = @"
    [0] Back to Main Menu
    [1] Download $AppBName from main source
    [2] Download $AppBName from backup source
    [3] Install $AppBName 
    [4] Additional configurations for $AppBName
"@

# VARIABLES - AppC (DeepBlueCLI)
    $AppCName = "DeepBlueCLI"
    $AppCdescription = "Sysmon Reviewer"
        # URLs
        $AppCURL = "https://github.com/sans-blue-team/DeepBlueCLI.git"
        $AppCURLBackup = ""
    $MenuAppC = @"
    [0] Back to Main Menu
    [1] Download $AppCName from main source
    [2] Download $AppCName from backup source
    [3] Commands for $AppCName for current host
    [4] Commands for $AppCName for remote host
"@

# VARIABLES - AppD (Autoruns)
    $AppDName = "Autoruns"
    $AppDdescription = "Scheduled tasks/persistence checker"
    $MenuAppD = @"
    [0] Back to Main Menu
    [1] Download $AppDName from main source
    [2] Download $AppDName from backup source
    [3] Commands for $AppDName
"@

# VARIABLES - AppE (CTI Search Online Reputation Search)
    $AppEName = "CTI Search" 
    $AppEdescription = "Online Reputation Searcher"
    $MenuAppE= @"
    Commands: ipx <ip> | dx <domain> | ex <email> | df <defanglink> | 0 (Main menu) |
    You are in $AppEName mode, provide your query.
"@

# VARIABLES - AppX (More Info & Contact)
    $AppXName = "More Info & Contact"
    $DiscordLink = "https://discord.gg/tQn4SWDG"
    $GithubLink = "https://github.com/resv"
    $EmailLink = "info@atomkim.com"
    $LinkedinLink = "https://www.linkedin.com/in/adamkim456/"

# VARIABLES - AppZ (Exit and keep CLI Open)
    $AppZName = "Exit THC, keep shell open"
    $AppZDescrption = "Exits THC and keep shell open"

# VARIABLES - AppZZ
    $AppZZName = "Exit THC and close shell"
    $AppZZDescrption = "Exit THC and close shell"






$MenuMain = @" 
$Banner
 [A] Get Host information $AppAName - $AppADescription
 [B] Download & Install $AppBName - $AppBDescription
 [C] Download & Run $AppCName - $AppCDescription
 [D] Download & Run $AppDName - $AppDDescription
 [E] Download & Run $AppEName - $AppEDescription
 [X] More Info & Contact - $AppXDescription
 [Z] Exit THC, keep CLI open - $AppZDescription
 [ZZ] Exit THC, close CLI `n - $AppZZDescription
Waiting for your input `n`n
"@


# VARIABLES - Status notifications
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
        'x' {
            #Insert logic here
            return #Exits the script
        }
        'z' {
            #Exit CLI
            exit
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
Write-host "[Application URL]:" $AppCURL

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

