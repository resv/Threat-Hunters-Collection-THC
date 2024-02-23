 
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
    $AppAdescription = "Get Host information"
    $Hostname = hostname
    $Profile = $env:userprofile
    $PrintWorkingDirectory = Get-Location
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
    $AppBdescription = "Get $AppBName from MS and install"
    $ParentAppCFolder = "DBCLI"

# VARIABLES - AppC (DeepBlueCLI)
    $AppCName = "DeepBlueCLI"
    $AppCdescription = "Get $AppCName from offical repo, extract to desktop, remove zip"
        # URLs
        $AppCURL = "https://github.com/sans-blue-team/DeepBlueCLI.git"
        $AppCURLBackup = ""

    # VARIABLES - Status notifications
    $StatusCCreatedParentAppCFolder = @"
    > [ Adding new directory `"$ParentAppCFolder`" to `"$ParentFolder`" ]`n
"@

    $StatusCChangedDirToParentAppCFolder = @"
    >> [ Changed working directory to `"$ParentAppCFolder`" ]`n
"@

    $StatusCDownloadApp = @"
    >>> [ Downloading `"$AppCName`"]`n
"@

    $StatusCExtractedApp = @"
    >>>> [ Extracted `"$AppCName`" ]`n
"@

    $StatusCRemoveDownload = @"
    >>>>> [ Removed downloaded files for `"$AppCName`" ]`n
"@

    $StatusCChangedDirToAppFolder = @"
    >>>>>> [ You are in the `"$AppCName`" directory ]`n
"@

    $StatusCReady = @"
    >>>>>>> [ Ready for Hunting... ]`n
"@

    $AppCCommands = @"
    ---------- [ `"$AppCName`" Commands ] -------------
    _____________________________________________________________________________________________________________________
    |                                                                                                                    |
    | [list]  .\DeepBlue.ps1 C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx | Format-List    |
    | [table] .\DeepBlue.ps1 C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx | Format-Table   |
    | [grid]  .\DeepBlue.ps1 C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx | Out-GridView   |
    | [html]  .\DeepBlue.ps1 C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx | ConvertTo-Html |
    | [json]  .\DeepBlue.ps1 C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx | ConvertTo-Json |
    | [xml]   .\DeepBlue.ps1 C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx | ConvertTo-Xml  |
    |____________________________________________________________________________________________________________________|`n
"@

#DBCLI Quick and easy variables for user to input instead of copy/pasting
    $DBCLIList = Write-Host ".\DeepBlue.ps1 C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx | Format-List"
    $DBCLITable = Write-Host ".\DeepBlue.ps1 C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx | Format-Table"
    $DBCLIGrid = Write-Host ".\DeepBlue.ps1 C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx | Out-GridView"
    $DBCLIHtml = Write-Host ".\DeepBlue.ps1 C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx | ConvertTo-Html"
    $DBCLIJson = Write-Host ".\DeepBlue.ps1 C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx | ConvertTo-Json"
    $DBCLIXml = Write-Host ".\DeepBlue.ps1 C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx | ConvertTo-Xml"

# VARIABLES - AppD (Autoruns)
    $AppDName = "Autoruns"
    $AppDDescription = "Scheduled tasks/persistence checker"

# VARIABLES - AppE (CTI Search Online Reputation Search)
    $AppEName = "CTI Search"
    $AppEdescription = "Online Reputation Searcher"

# VARIABLES - AppX (More Info & Contact)
    $AppXName = "Contact"
    $AppXDescription = "More Info & Contact"
    $DiscordLink = "https://discord.gg/tQn4SWDG"
    $GithubLink = "https://github.com/resv"
    $EmailLink = "info@atomkim.com"
    $LinkedinLink = "https://www.linkedin.com/in/adamkim456/"

# VARIABLES - AppZ (Exit and keep CLI Open)
    $AppZName = "Soft Exit"
    $AppZDescription = "Exit THC and keep shell open"

# VARIABLES - AppZZ
    $AppZZName = "Hard Exit"
    $AppZZDescription = "Exit THC and close shell"

# MainMenu
$MenuMain = @" 
$Banner
  [A] $AppAName - $AppADescription
  [B] $AppBName - $AppBDescription
  [C] $AppCName - $AppCDescription
  [D] $AppDName - $AppDDescription
  [E] $AppEName - $AppEDescription
  [X] $AppXName - $AppXDescription
  [Z] $AppZName - $AppZDescription
 [ZZ] $AppZZName - $AppZZDescription `n
"@


function StartDBCLI {   
    #Clear
    clear

    # Welcome BannerAppC
    Write-Host $BannerC

    #DBCLI
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

    # Create the ParentAppCFolder in ParentFolder (Also hiding the Powershell Output)
    $null = new-item -path "$($env:userprofile)\Desktop\$ParentFolder" -name $ParentAppCFolder -itemtype directory -Force
    Write-Host $StatusCCreatedParentAppCFolder

    # Change the directory to ParentAppCFolder
    set-location "$($env:userprofile)\Desktop\$ParentFolder\$ParentAppCFolder"
    Write-Host $StatusCChangedDirToParentAppCFolder
   
    # Download zip file from Repo, extract zip, rename zip, delete downloaded zip file
    Write-Host $StatusCDownloadApp
    Invoke-WebRequest 'https://github.com/sans-blue-team/DeepBlueCLI/archive/refs/heads/master.zip' -OutFile .\$AppCName.zip
    
    
    $StatusCExtractedApp
    Expand-Archive .\$AppCName.zip .\
    Rename-Item .\$AppCName-master .\$AppCName
    Remove-Item .\$AppCName.zip
    Write-Host $StatusCRemoveDownload
    
    # Change the directory to AppCName
    set-location "$($env:userprofile)\Desktop\$ParentFolder\$ParentAppCFolder\$AppCName"
    Write-Host $StatusCChangedDirToAppFolder

    # Check if staging and initialization is complete
    $HealthCheck = "True"

        if ($HealthCheck -eq "True") 
        {   
            Write-Host $StatusCReady
            Write-Host $AppCCommands
            do
            {
                # Show-Menu <- this is a function, commented out fo rnow
                $selection = Read-Host "Ready for Hunting... "
                switch ($selection)
                {
                    'List' {
                    $DBCLIList
                    return
                    } 
                    'Table' {
                    $DBCLITable
                    } 
                    'Grid' {
                    DBCLIGrid
                    return
                    } 
                    'HTML' {
                    DBCLIHtml
                    } 
                    'JSON' {
                    $DBCLIJson
                    } 
                    'XML' {
                    $DBCLIXml
                    }
                }
                pause
            }
            until ($selection -eq 'q')


        }
        else
        {
            Write-Host "Intialization process has failed..."
        }
}


# Execution starts here:
# -------------------------------------------------------------------


function Show-Menu {
    Clear-Host
    Write-Host $MenuMain
}


do
 {
    Show-Menu
    $selection = Read-Host "Standing by"
    switch ($selection)
    {
        'A' {
        'You chose option #1'
        return
        } 
        'B' {
        'You chose option #2'
        } 
        'C' {
        StartDBCLI
        return
        } 
        'D' {
        'You chose option #3'
        } 
        'E' {
        'You chose option #3'
        } 
        'F' {
        'You chose option #3'
        }
    }
    pause
 }
 until ($selection -eq 'q')

