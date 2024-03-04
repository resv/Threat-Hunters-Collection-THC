 
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
    
    $GetVolume = "Get-Volume | Sort-Object -Property BasePriority | Format-Table -GroupBy BasePriority -Wrap | Out-String"
    $GetPartition = "Get-Partition"
    $GetCIM = "Get-CimInstance -ClassName Win32_Desktop | Format-Table | Out-String"

# FUNCTION A
    function HostInfo {
        #Clear
        clear

        # Welcome BannerAppA
        Write-Host $BannerA

        # Notify hostname & IP address
        Write-Host "[Hostname]:" $Hostname
        Write-Host "[Profile]:" $Profile
        Write-Host "[IP Address ]:" $IPAddress
        
        # Notify working directory
        #Write-Host "[PWD]:" $PrintWorkingDirectory\$ParentAppCFolder

        #More PC Info
        Get-ComputerInfo  -Property "CsNetworkAdapters","CsDomain","CsUserName","LogonServer","WindowsRegisteredOwner","WindowsProductName","WindowsEditionId","OsArchitecture","OsBuildNumber","OsVersion","CsManufacturer","CsModel","BiosName","CsProcessors","CsNumberOfLogicalProcessors","TimeZone","OsInstallDate","OsLastBootUpTime","OsLocalDateTime","OsUptime"

        #Drive Information
        Write-Host "------------------------------------------------------- [ Drive Information ] -------------------------------------------------------"
        Invoke-expression $GetVolume.Trim()
        #This one below is ok, but the above might be better
        #Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" | Format-Table -Property DeviceID, VolumeName, FreeSpace, Size, DriveType

        #Partition Information (excluded for now)
        #Write-Host "------------------------------------------------------ [ Parition Info Start ] -------------------------------------------------------"
        #Invoke-expression $GetPartition
        #Write-Host "------------------------------------------------------ [ Parition Info End ] -------------------------------------------------------"
        
        #All Desktops in Use or Not
        Write-Host "--------------------------------------------------------- [ All Desktops ] ----------------------------------------------------------" 
        Invoke-expression $GetCIM.Trim()
    }

# VARIABLES - AppB (Sysmon)
    $AppBName = "Sysmon vXX.XX"
    $AppBdescription = "Get $AppBName from MS and install"
    $AppBFolder = "$AppBName"

# VARIABLES - AppC (DeepBlueCLI)
    $AppCName = "DeepBlueCLI"
    $AppCdescription = "Get $AppCName from offical repo, extract to desktop, remove zip"
    $AppCFolder = "DeepBlueCLI"
        # URLs
        $AppCURL = "https://github.com/sans-blue-team/DeepBlueCLI/archive/refs/heads/master.zip"
        $AppCURLBackup = ""
    
    # VARIABLES - Status notifications
    $StatusCCreatedAppCFolder = "> [ Adding new directories ..\Desktop\$ParentFolder\$AppCFolder ]`n"
    $StatusCChangedDirToAppCFolder = ">> [ Changed working directory to (..\$AppCFolder) ]`n"
    $StatusCDownloadApp = ">>> [ Downloading `"$AppCName`" ]`n"
    $StatusCExtractedApp = ">>>> [ Extracted `"$AppCName`" ]`n"
    $StatusCRemoveDownload =  ">>>>> [ Removed downloaded files for `"$AppCName`" ]`n"
    $StatusCChangedDirToAppFolder = ">>>>>> [ You are in the (..\Desktop\$ParentFolder\$AppCFolder) directory ]`n"
    $StatusCReady = ">>>>>>> [ Ready for Hunting... ]`n"
    $StatusCLoading = ">>>>>>>> [ Retrieving Data... ]`n"
    $StatusCCreatedAppCLogFolder = "`n>>>>>>>> [ Adding new directory `"$Hostname-Evtx-Logs`" ]`n"
    $StatusCExportComplete = "`n>>>>>>>>>> [ Exported Raw Logs to (Desktop\$ParentFolder\$Hostname-Evtx-Logs) ]`n"
    $DeepBlueExecute = ".\DeepBlue.ps1"
    $LogPathExportFolder = "$($env:userprofile)\Desktop\$ParentFolder\$Hostname-Evtx-Logs"
    $LogPathSecurity = "C:\Windows\System32\winevt\Logs\Security.evtx"
    $LogPathSystem = "C:\Windows\System32\winevt\Logs\System.evtx "
    $LogPathApplication = "C:\Windows\System32\winevt\Logs\Application.evtx"
    $LogPathAppLocker = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-AppLocker%4EXE and DLL.evtx"
    $LogPathPowerShell = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx"
    $LogPathSysmon = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx"
    $LogPathWMI = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-WMI-Activity%4Operational.evtx"
    $PipeList = "| Format-List"
    $PipeTable = "| Format-Table"
    $PipeGrid = "| Out-GridView"
    $PipeHtml = "| ConvertTo-Html"
    $PipeJson = "| ConvertTo-Json"
    $PipeXml = "| ConvertTo-Xml"

    # AppCMenuSub
    $AppCMenuSub = @"
    `n
          $global:LogTarget Log Sub-Menu
     ________[ Quick Commands ]________
    |                                  |
    | *[List]   | Format-List view     |
    | *[Table]  | Format-Table view    |
    | *[Grid]   | Out-GridView view    |
    |  [HTML]   | ConvertTo-Html view  |
    |  [JSON]   | ConvertTo-Json view  |
    |  [XML]    | ConvertTo-Xml view   |
    |  [Export] | Export Logs          |
    |  [Back]   | Back to Main Menu    |
    |__________________________________|`n `n
"@

    # AppCMenuMain
    $AppCMenuMain = @"
    `n
     ____[ DEEP BLUE CLI MAIN MENU ]____
    |                                   |
    | [Records]     | Total Event Count |
    | [Security]    | DeepBlue Query    |
    | [Application] | DeepBlue Query    |
    | [System]      | DeepBlue Query    |
    | [Application] | DeepBlue Query    |
    | [AppLocker]   | DeepBlue Query    |
    | [Powershell]  | DeepBlue Query    |
    | [Sysmon]      | DeepBlue Query    |
    | [WMI]         | DeepBlue Query    |
    | [All]         | Filters all logs  |
    | [Export]      | Export all logs   |
    | [Help]        | Syntax & Paths    |
    | [Back]        | Back to Main Menu |
    |___________________________________|`n `n
"@



# (THIS WILL BE DEPRECATED SOON)DBCLI Quick and easy variables for user to input instead of copy/pasting
    $DBCLIList = ".\DeepBlue.ps1 C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx | Format-List"
    $DBCLITable = ".\DeepBlue.ps1 C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx | Format-Table"
    $DBCLIGrid = ".\DeepBlue.ps1 C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx | Out-GridView"
    $DBCLIHtml = ".\DeepBlue.ps1 C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx | ConvertTo-Html"
    $DBCLIJson = ".\DeepBlue.ps1 C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx | ConvertTo-Json"
    $DBCLIXml = ".\DeepBlue.ps1 C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx | ConvertTo-Xml"
    $DBCLIHelp = @"

 __________________________________________________[ SYNTAX ]__________________________________________________
|                                                                                                              |
| [  <Script> ----- <Log Location> ---------------------------------------------------------- | <Switch> -- ]  |
| [ .\DeepBlue.ps1 C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx | Format-List ]  |
|______________________________________________________________________________________________________________|

         _______________________________________[ HOST LOG PATHS ]______________________________________ 
        |                                                                                               |
        |  [Security] C:\Windows\System32\winevt\Logs\Security.evtx                                     |
        |  [System] C:\Windows\System32\winevt\Logs\System.evtx                                         |
        |  [Application] C:\Windows\System32\winevt\Logs\Application.evtx                               |
        |  [AppLocker] C:\Windows\System32\winevt\Logs\Microsoft-Windows-AppLocker%4EXE and DLL.evtx    |
        |  [PowerShell] C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx  |
        |  [Sysmon] C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx          |
        |  [WMI] C:\Windows\System32\winevt\Logs\Microsoft-Windows-WMI-Activity%4Operational.evtx       |
        |_______________________________________________________________________________________________|

         ____________________________________[ EXPORTED LOG PATHS ]_____________________________________ 
        |                                                                                               |
        |  [Exported Logs] Desktop\Threat Hunters Collection\"Hostname"-Evtx-Logs                       |
        |_______________________________________________________________________________________________|
`n
"@

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

#DBCLI Gets Record Count and displays it for user to get an idea of load times for queries
function DBCLIRecords {
    Write-Host $BannerC
    Invoke-expression "get-winevent -listlog Security,System,Application,`"Microsoft-Windows-AppLocker/EXE and DLL`",`"Windows PowerShell`",`"Microsoft-Windows-Sysmon/Operational`",`"Microsoft-Windows-WMI-Activity/Operational`" | Select-Object RecordCount,LogName"
    Write-Host "`n"
    }

function ExportEvtxLogs {
    # clear
    clear

    # Welcome BannerAppC
    Write-Host $BannerC

    # Create directory and notify user of path
    function global:CreateLogFolder{
        $null = new-item -path "$($env:userprofile)\Desktop\$ParentFolder" -name "$Hostname-Evtx-Logs" -itemtype directory -Force
        Write-Host $StatusCCreatedAppCLogFolder
        }
    CreateLogFolder

    # Export Security Log & Call it (This function is reused individually elsewhere)
    function global:ExportEvtxSecurityLog{
        Write-Host ">>>>>>>>> [ Exporting Security Log ]"
        Copy-Item -Path $LogPathSecurity -Destination "$LogPathExportFolder"
        }
    ExportEvtxSecurityLog

    # Export System Log & Call it (This function is reused individually elsewhere)
    function global:ExportEvtxSystemLog{
        Write-Host ">>>>>>>>>> [ Exporting System Log ]"
        Copy-Item -Path $LogPathSystem -Destination "$LogPathExportFolder"
        }
    ExportEvtxSystemLog

    # Export Application Log & Call it (This function is reused individually elsewhere)
    function global:ExportEvtxApplicationLog{
        Write-Host ">>>>>>>>>>> [ Exporting Application Log ]"
        Copy-Item -Path $LogPathApplication -Destination "$LogPathExportFolder"
    }
    ExportEvtxApplicationLog

    # Export AppLocker log & Call it (This function is reused individually elsewhere)
    function global:ExportEvtxAppLockerLog{
        Write-Host ">>>>>>>>>>>> [ Exporting AppLocker EXE & DLL Log ]"
        Copy-Item -Path $LogPathAppLocker -Destination "$LogPathExportFolder"
    }
    ExportEvtxAppLockerLog
    
    # Export PowerShell Log & Call it (This function is reused individually elsewhere)
    function global:ExportEvtxPowerShellLog{
        Write-Host ">>>>>>>>>>>>> [ Exporting PowerShell Log ]"
        Copy-Item -Path $LogPathPowerShell -Destination "$LogPathExportFolder"
    }
    ExportEvtxPowerShellLog

    # Export Sysmon Log & Call it (This function is reused individually elsewhere)
    function global:ExportEvtxSysmonLog{
        Write-Host ">>>>>>>>>>>>>> [ Exporting Sysmon Log ]"
        Copy-Item -Path $LogPathSysmon -Destination "$LogPathExportFolder"
    }
    ExportEvtxSysmonLog

    # Export WMI Log & Call it (This function is reused individually elsewhere)
    function global:ExportEvtxWMILog{
        Write-Host ">>>>>>>>>>>>>>> [ Exporting WMI Log ]"
        Copy-Item -Path $LogPathWMI -Destination "$LogPathExportFolder"
        }
    ExportEvtxWMILog

    function global:StatusCReportExportComplete{
        Write-Host $StatusCExportComplete
        }
    StatusCReportExportComplete
}

# AppC (DBCLI) Main Menu
function DBCLIMenuMain{
    if ($HealthCheck -eq "True") 
    {   
        #place holder for another command
        do
        {
            # Placeholder for another command
            
            # MainMenu for DBCLI, not case sensitive, will take alphanumeric inputs
            $selection = Read-Host $StatusCReady $BannerC $AppCMenuMain "Waiting for your input"
            switch ($selection)
            {
                'Records' {
                    Write-Host $StatusCLoading
                    DBCLIRecords
                    } 
                'Security' {
                $global:LogTarget = "Security"
                $selection2 = Read-Host $AppCMenuSub "$global:LogTarget Menu, waiting for your input"
                switch ($selection2)
                {
                    'List' {
                        Write-Host $StatusCLoading
                        Invoke-expression $DBCLISecurityLogList
                        } 
                    'Table' {
                        Write-Host $StatusCLoading
                        Invoke-expression $DBCLISecurityLogTable
                        }
                    'Grid' {
                        Write-Host $StatusCLoading
                        Invoke-expression $DBCLISecurityLogGrid
                        } 
                    'Html' {
                        Write-Host $StatusCLoading
                        Invoke-expression $DBCLISecurityLogHTML
                        } 
                    'Json' {
                        Write-Host $StatusCLoading
                        Invoke-expression $DBCLISecurityLogJson
                        } 
                    'Xml' {
                        Write-Host $StatusCLoading
                        Invoke-expression $DBCLISecurityLogXml
                        }
                    'Export' {
                        Write-Host $StatusCLoading
                        ExportEvtxSysmonLog
                        StatusCReportExportComplete
                        }
                    'Help' {
                        Clear-Host
                        Write-Host $BannerC
                        Write-Host $DBCLIHelp      
                        }        
                    'Back' {
                        AppCMenuMain
                        } 
                }
                pause
                } 
                'System' {
                Write-Host $StatusCLoading
                Invoke-expression $DBCLITable
                } 
                'Application' {
                Write-Host $StatusCLoading
                Invoke-expression $DBCLIGrid
                } 
                'AppLocker' {
                Write-Host $StatusCLoading
                Invoke-expression $DBCLIHtml
                } 
                'PowerShell' {
                Write-Host $StatusCLoading
                Invoke-expression $DBCLIJson
                } 
                'Sysmon' {
                Write-Host $StatusCLoading
                Invoke-expression $DBCLIXml
                }
                'WMI' {
                Write-Host $StatusCLoading
                ExportEvtxLogs                   
                }
                'Export' {
                Write-Host $StatusCLoading
                ExportEvtxLogs                   
                }
                'help' {
                Clear-Host
                Write-Host $BannerC
                Write-Host $DBCLIHelp                    
                }
                'Exit' {
                Write-Host "placeholder used for exit but we will invoke $ ExportEvtxSysmonLog an encapped function for testing"
                ExportEvtxSysmonLog
                Write-Host "If this export was successfully you should see this text <<<<< also check folder..."
                }
                'Wipe' {
                # Invoke DBCLI Variable to wipe DBCLI and possibly THC
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

function StartDBCLI {   
    #Clear
    clear

    # Welcome BannerAppC
    Write-Host `n`n`n`n`n`n

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
    $null = new-item -path "$($env:userprofile)\Desktop" -name $ParentFolder -itemtype directory -Force
    Write-Host $StatusCCreatedAppCFolder

    # Change the directory to ParentAppCFolder
    set-location "$($env:userprofile)\Desktop\$ParentFolder"
    Write-Host $StatusCChangedDirToAppCFolder
   
    # Download zip file from Repo, extract zip, rename zip, delete downloaded zip file
    Write-Host $StatusCDownloadApp
    Invoke-WebRequest $AppCURL -OutFile .\$AppCName.zip
    
    
    $StatusCExtractedApp
    Expand-Archive .\$AppCName.zip .\
    Rename-Item .\$AppCName-master .\$AppCName
    Remove-Item .\$AppCName.zip
    Write-Host $StatusCRemoveDownload
    
    # Change the directory to AppCName
    set-location "$($env:userprofile)\Desktop\$ParentFolder\$AppCFolder"
    Write-Host $StatusCChangedDirToAppFolder

    # Check if staging and initialization is complete
    $HealthCheck = "True"
    
    # Call DBCLIMenu
    DBCLIMenuMain
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
    $selection = Read-Host "Waiting for your input"
    switch ($selection)
    {
        'A' {
        HostInfo
        } 
        'B' {
        'You chose option #B'
        } 
        'C' {
        StartDBCLI
        return
        } 
        'D' {
        'You chose option #D'
        } 
        'E' {
        'You chose option #E'
        } 
        'F' {
        'You chose option #F'
        }
    }
    pause
 }
 until ($selection -eq 'q')

