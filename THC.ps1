 
#(go down to execution line)
##Good quick info, implement later for hunters  https://mahim-firoj.medium.com/incident-response-and-threat-hunting-using-deepbluecli-tool-bf5d4c52c8a8

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
$UserProfilePath = $($env:userprofile)

# VARIABLES A - AppA (Host Info)
    $AppAName = "Host Info"
    $AppADescription = "Get Host Information"
    $Hostname = hostname
    $PrintWorkingDirectory = Get-Location
        #Grab IP info
        $IPAddress= $env:HostIP = (Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"}).IPv4Address.IPAddress
    $GetVolume = "Get-Volume | Select-Object @{Name='Drive';Expression='DriveLetter'}, FileSystemLabel, @{Name='Free `(GB`)';Expression={[math]::Round(`$_.SizeRemaining / 1GB, 2)}}, @{Name='Size `(GB`)';Expression={[math]::Round(`$_.Size / 1GB, 2)}}, @{Name='Type';Expression='FileSystemType'}, @{Name='Mount';Expression='DriveType'}, @{Name='Health';Expression='HealthStatus'},@{Name='Status';Expression='OperationalStatus'}| Format-Table -Wrap | Out-String"
    $GetCIM = "Get-CimInstance -ClassName Win32_Desktop | Select-Object @{Name='Name | ScreenSaver ------->';Expression='Name'}, @{Name='Active';Expression='ScreenSaverActive'}, @{Name='Secure';Expression='ScreenSaverSecure'}, @{Name='Timeout';Expression='ScreenSaverTimeout'}| Format-Table -Wrap | Out-String"

# FUNCTION A
    function HostInfo {
    #Clear
    Clear
    
    # Start transcript to capture all output, appends info if tracking changes.
    Start-Transcript -Path "$env:USERPROFILE\Desktop\$ParentFolder\$Hostname-Host-Info.txt" -Append | Out-Null
    
    # Welcome BannerAppA
    Write-Host $BannerA
    
    # Host Information
    Write-Host "----------------------------------- [ HOST INFORMATION ] -----------------------------------`n" -ForegroundColor Green

    # Get current time stamp
    Write-Host "[Date]: $(Get-Date)"
    
    # Notify hostname & IP address
    Write-Host "[Hostname]: $Hostname"
    Write-Host "[Profile]: $UserProfilePath"
    Write-Host "[IP Address]: $IPAddress" -NoNewline
    
    # More PC Info
    Get-ComputerInfo -Property "CsNetworkAdapters","CsDomain","CsUserName","LogonServer","WindowsRegisteredOwner","WindowsProductName","WindowsEditionId","OsArchitecture","OsBuildNumber","OsVersion","CsManufacturer","CsModel","BiosName","CsProcessors","CsNumberOfLogicalProcessors","TimeZone","OsInstallDate","OsLastBootUpTime","OsLocalDateTime","OsUptime"

    # Drive Information
    Write-Host "---------------------------------- [ DRIVE INFORMATION ] ------------------------------------" -ForegroundColor Green
    Invoke-Expression $GetVolume.Trim()

    # All Desktops in Use or Not
    Write-Host "-------------------------------- [ DESKTOPS | SCREENSAVER ] ---------------------------------" -ForegroundColor Green
    Invoke-Expression $GetCIM.Trim()
    
    Write-Host $StatusAExportComplete -ForegroundColor Green -NoNewline
    # Stop transcript
    Stop-Transcript | Out-Null
}

# VARIABLES B - AppB (Sysmon)
    $AppBName = "Sysmon vXX.XX"
    $AppBDescription = "Get $AppBName from MS and install"
    $AppBFolder = "$AppBName"

# VARIABLES C - AppC (DeepBlueCLI)
    $AppCName = "DeepBlueCLI"
    $AppCDescription = "Get $AppCName from offical repo, extract to desktop, remove zip"
    $AppCFolder = "DeepBlueCLI"
        # URLs
        $AppCURLMain = "https://github.com/sans-blue-team/DeepBlueCLI/archive/refs/heads/master.zip"
        $AppCURLMirror = "https://github.com/resv/DeepBlueCLI-Back-Up/archive/refs/heads/master.zip"
           
    $AppCHashMain = "2295C0E92697A8F5425F20E4119F7A049428C2A47AF48F88ABABA206309DEE51"
    $AppCHashMirror = "9B0BA2CE0752AE68C0AE8553AD14E46590A6745F9B7EAA085E20C2363B9D4CA9"

    # VARIABLES C - Status notifications
    $StatusCCreatedAppCFolder = "> [ Adding new directories ..\Desktop\$ParentFolder\$AppCFolder ]`n"
    $StatusCChangedDirToAppCFolder = ">> [ Changed working directory to ..\$AppCFolder ]`n"
    $StatusCCheckAndRemoveExisting = ">>> [ Removing any existing DeepBlue files ]`n"
    $StatusCDownloadApp = ">>>> [ Downloading `"$AppCName`" ]`n"
    $StatusCHashCheck = ">>>>> [ Checking hash ]`n"
    $StatusCExtractedApp = ">>>>>> [ Extracted `"$AppCName`" ]`n"
    $StatusCRemoveDownload =  ">>>>>>> [ Removed downloaded files for `"$AppCName`" ]`n"
    $StatusCChangedDirToAppFolder = ">>>>>>>> [ You are in the ..\Desktop\$ParentFolder\$AppCFolder ]`n"
    $StatusCReady = ">>>>>>>>> [ Ready for Hunting... ]`n"
    $StatusCLoading = ">>>>>>>>>> [ Retrieving Data... ]`n"
    $StatusCCreatedAppCLogFolder = "`n>>>>>>>>> [ Adding new directory `"$Hostname-Evtx-Logs`" ]`n"
    $StatusCCreatedAppCImportLogFolder = "`n>>>>>>>> [ Adding new directories ..\Desktop\$ParentFolder\Import-Log-Folder ]`n"
    $StatusCExportComplete = "`n>>>>>>>>>>> [ Exported Raw Logs to ..\Desktop\$ParentFolder\$Hostname-Evtx-Logs ]`n"
    $StatusAExportComplete = "`n>>>>>>>>>>> [ Exported Raw Logs to ..\Desktop\$ParentFolder\$Hostname-Host-Info ]`n"
    $DeepBlueExecute = ".\DeepBlue.ps1"
    $LogPathExportFolder = "$($UserProfilePath)\Desktop\$ParentFolder\$Hostname-Evtx-Logs"
    $LogPathImportFolder = "$($UserProfilePath)\Desktop\$ParentFolder\Import-Log-Folder"
    $LogPathSecurity = "C:\Windows\System32\winevt\Logs\Security.evtx"
    $LogPathSystem = "C:\Windows\System32\winevt\Logs\System.evtx"
    $LogPathApplication = "C:\Windows\System32\winevt\Logs\Application.evtx"
    $LogPathAppLocker = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-AppLocker%4EXE and DLL.evtx"
    $LogPathPowerShell = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx"
    $LogPathSysmon = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx"
    $LogPathWMI = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-WMI-Activity%4Operational.evtx"
    $LogPathImportSecurity = "$($UserProfilePath)\Desktop\$ParentFolder\Import-Log-Folder\Security.evtx"
    $LogPathImportSystem = "$($UserProfilePath)\Desktop\$ParentFolder\Import-Log-Folder\System.evtx"
    $LogPathImportApplication = "$($UserProfilePath)\Desktop\$ParentFolder\Import-Log-Folder\Application.evtx"
    $LogPathImportAppLocker = "$($UserProfilePath)\Desktop\$ParentFolder\Import-Log-Folder\Microsoft-Windows-AppLocker%4EXE and DLL.evtx"
    $LogPathImportPowerShell = "$($UserProfilePath)\Desktop\$ParentFolder\Import-Log-Folder\Microsoft-Windows-PowerShell%4Operational.evtx"
    $LogPathImportSysmon = "$($UserProfilePath)\Desktop\$ParentFolder\Import-Log-Folder\Microsoft-Windows-Sysmon%4Operational.evtx"
    $LogPathImportWMI = "$($UserProfilePath)\Desktop\$ParentFolder\Import-Log-Folder\Microsoft-Windows-WMI-Activity%4Operational.evtx"
    $PipeList = "|Format-List"
    $PipeTable = "|Format-Table"
    $PipeGrid = "|Out-GridView"
    $PipeHtml = "|ConvertTo-Html"
    $PipeJson = "|ConvertTo-Json"
    $PipeXml = "|ConvertTo-Xml"

    # AppCMenuImport
    $AppCMenuImportSub = @"
    `n
    $global:LogTarget
     ______[ IMPORT SUB MENU ]_______
    |                                |
    | *[List]  | Format-List view    |
    | *[Table] | Format-Table view   |
    | *[Grid]- | Out-GridView view   |
    |  [HTML] -| ConvertTo-Html view |
    |  [JSON] -| ConvertTo-Json view |
    |  [XML]  -| ConvertTo-Xml view  |
    |  [Records]| Get $global:LogTarget Count (This can take a long time)  |
    |  [Help]  |  Syntax & Paths     |
    |  [Back]  | Back to Main Menu   |
    |________________________________|`n `n
"@    

    # AppCMenuMain
    $AppCMenuImportMain = @"
    `n
     _______[ IMPORT MAIN MENU ]________
    |                                   |
    | [Security]    | $($global:LogCountImportSecurity.Count) Records
    | [System]      | $($global:LogCountImportSystem.Count) Records
    | [Application] |  Records
    | [AppLocker]   |  Records
    | [Powershell]  |  Records
    | [Sysmon]      |  Records
    | [WMI]         |  Records
    | [All]         | Filters all logs  |
    | [Help]        | Syntax & Paths    |
    | [Back]        | Back to Main Menu |
    |___________________________________|`n `n
"@

    # AppCMenuSub
    $AppCMenuSub = @"
    `n
           $global:LogTarget ($LogCount)
     _____[ DEEPBLUECLI SUB MENU ]_____
    |                                  |
    | *[List]   | Format-List view     |
    | *[Table]  | Format-Table view    |
    | *[Grid]   | Out-GridView view    |
    |  [HTML]   | ConvertTo-Html view  |
    |  [JSON]   | ConvertTo-Json view  |
    |  [XML]    | ConvertTo-Xml view   |
    |  [Help]   | Syntax & Paths       |
    |  [Export] | Export Logs          |
    |  [Back]   | Back to Main Menu    |
    |__________________________________|`n `n
"@

    # AppCMenuMain
    $AppCMenuMain = @"
    `n
     _____[ DEEPBLUECLI MAIN MENU ]_____
    |                                   |
    | [Security]    | $LogCountSecurity Records
    | [System]      | $LogCountSystem Records
    | [Application] | $LogCountApplication Records
    | [AppLocker]   | $LogCountAppLocker Records
    | [Powershell]  | $LogCountPowerShell Records
    | [Sysmon]      | $LogCountSysmon Records
    | [WMI]         | $LogCountWMI Records
    | [All]         | Filters all logs  |
    | [Import]      | Import Logs & Run |
    | [Export]      | Export all logs   |
    | [Help]        | Syntax & Paths    |
    | [Wipe]        | Wipe DeepBlueCLI  |
    | [Back]        | Back to Main Menu |
    |___________________________________|`n `n
"@

    $DBCLIHelp = @"

 __________________________________________________[ SYNTAX ]__________________________________________________
|                                                                                                              |
| [  <SCRIPT> ----- <HOST LOG PATH> --------------------------------------------------------- | <SWITCH> -- ]  |
| [ .\DeepBlue.ps1 C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx | Format-List ]  |
|______________________________________________________________________________________________________________|

         ______________________________________[ HOST LOG PATHS ]_______________________________________ 
        |                                                                                               |
        | [Security] "C:\Windows\System32\winevt\Logs\Security.evtx"                                    |
        | [System] "C:\Windows\System32\winevt\Logs\System.evtx"                                        |
        | [Application] "C:\Windows\System32\winevt\Logs\Application.evtx"                              |
        | [AppLocker] "C:\Windows\System32\winevt\Logs\Microsoft-Windows-AppLocker%4EXE and DLL.evtx"   |
        | [PowerShell] "C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx" |
        | [Sysmon] "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx"         |
        | [WMI] "C:\Windows\System32\winevt\Logs\Microsoft-Windows-WMI-Activity%4Operational.evtx"      |
        |_______________________________________________________________________________________________|

                                     ___________[ SWITCHES ]___________
                                    |                                  |
                                    | *[List]  "| Format-List view"    |
                                    | *[Table] "| Format-Table view"   |
                                    | *[Grid]  "| Out-GridView view"   |
                                    |  [HTML]  "| ConvertTo-Html view" |
                                    |  [JSON]  "| ConvertTo-Json view" |
                                    |  [XML]   "| ConvertTo-Xml view"  |
                                    |__________________________________|

                  __________________________[ IMPORTED LOG PATHS ]__________________________
                 |                                                                          |
                 | [Imported Logs] "..\Desktop\Threat Hunters Collection\Import-Log-Folder" |
                 |__________________________________________________________________________|

                 ___________________________[ EXPORTED LOG PATHS ]____________________________
                |                                                                             |
                | [Exported Logs] "..\Desktop\Threat Hunters Collection\"Hostname"-Evtx-Logs" |
                |_____________________________________________________________________________|
`n
"@

# VARIABLES - AppD (DBCLI BACKUP URL)
    $AppDName = "DeepBlueCLI Mirror"
    $AppDDescription = "Get $AppCName from mirror repo, extract to desktop, remove zip"

# VARIABLES - AppE (placeholder)
    $AppEName = "placeholder"
    $AppEDescription = "placeholder"

# VARIABLES - AppF (Autoruns)
    $AppFName = "Autoruns"
    $AppFDescription = "Scheduled tasks/persistence checker"

# VARIABLES - AppG (CTI Search Online Reputation Search)
    $AppGName = "CTI Search"
    $AppGDescription = "Online Reputation Searcher"

# VARIABLES - AppH (Wipe THC from endpoint)
    $AppHName = "Wipe THC"
    $AppHDescription = "Delete all THC folder/files"

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
  [F] $AppFName - $AppFDescription
  [G] $AppGName - $AppGDescription
  [H] $AppHName - $AppHDescription
  [X] $AppXName - $AppXDescription
  [Z] $AppZName - $AppZDescription
 [ZZ] $AppZZName - $AppZZDescription `n
"@

# Stores Record Count in variable to use and display on the AppC Menu Main
function RunRecordCount {
    $global:LogCountSecurity = Invoke-expression "get-winevent -listlog Security | Select-Object -ExpandProperty RecordCount"
    $global:LogCountSystem = Invoke-expression "get-winevent -listlog System | Select-Object -ExpandProperty RecordCount"
    $global:LogCountApplication = Invoke-expression "get-winevent -listlog Application | Select-Object -ExpandProperty RecordCount"
    $global:LogCountAppLocker = Invoke-expression "get-winevent -listlog `"Microsoft-Windows-AppLocker/EXE and DLL`" | Select-Object -ExpandProperty RecordCount"
    $global:LogCountPowerShell = Invoke-expression "get-winevent -listlog `"Windows PowerShell`" | Select-Object -ExpandProperty RecordCount"
    $global:LogCountSysmon = Invoke-expression "get-winevent -listlog `"Microsoft-Windows-Sysmon/Operational`" | Select-Object -ExpandProperty RecordCount"
    $global:LogCountWMI = Invoke-expression "get-winevent -listlog `"Microsoft-Windows-WMI-Activity/Operational`" | Select-Object -ExpandProperty RecordCount"

}
# Running record count on imported files take way too long, this is disabled for now
function RunImportRecordCount($LogTarget){

    clear
    Write-Host "`n>>>>>>>>> [ Reboot THC if you want to exit out of this process, it can take a long time...]`n"
    Write-Host ">>>>>>>>>> [ Counting records in $LogTarget log ]`n"
    
    if ($LogTarget -eq "Imported Security"){
    $global:LogCountImportSecurity = Invoke-expression "get-winevent -Path `"$($UserProfilePath)\Desktop\$ParentFolder\Import-Log-Folder\Security.evtx`" -MaxEvents 1000000"
    $ImportRecordCount = $global:LogCountImportSecurity.Count
    }

    if ($LogTarget -eq "Imported System"){
    $global:LogCountImportSystem = Invoke-expression "get-winevent -Path `"$($UserProfilePath)\Desktop\$ParentFolder\Import-Log-Folder\System.evtx`" -MaxEvents 1000000"
    $ImportRecordCount = $global:LogCountImportSystem.Count
    }

    Write-Host ">>>>>>>>>>> [ $LogTarget has ($ImportRecordCount) records ]`n"
}

# Import Folder creation, wait for import confirmation from user, then run
function RunImport{
    # Clear
    clear

    # Welcome BannerAppC
    Write-Host $BannerC
    
    # Create export log directory and notify path
    $null = new-item -path "$($UserProfilePath)\Desktop\$ParentFolder" -name "Import-Log-Folder" -itemtype directory -Force
    Write-Host $StatusCCreatedAppCImportLogFolder
    Write-Host ">>>>>>>>> [ DeepBlue will assume unchanged default evtx file names ] `n"
    Write-Host ">>>>>>>>>> [ Import evtx files to the `"Import-Log-Folder`", then run your command] `n"
     
    do
    {
        # RunImportRecordCount
        ##showmenu
        $selectionImport = Read-Host $AppCMenuImportMain "Imported main menu, Waiting for your input"
        switch ($selectionImport)
        {
            'Security' {
                $global:LogTarget = "Imported Security"
                $global:LogType = $LogPathImportSecurity
                $selection2Import = Read-Host $AppCMenuImportSub "$global:LogTarget log sub menu, waiting for your input"
                switch ($selection2Import)
                {
                    'List' {
                        $global:LogFormat = $PipeList
                        RunDeepBlue
                        } 
                    'table' {
                        $global:LogFormat = $PipeTable
                        RunDeepBlue
                        }
                    'Grid' {
                        $global:LogFormat = $PipeGrid
                        RunDeepBlueImported
                        } 
                    'Html' {
                        $global:LogFormat = $PipeHtml
                        RunDeepBlueImported
                        } 
                    'Json' {
                        $global:LogFormat = $PipeJson
                        RunDeepBlueImported
                        } 
                    'Xml' {
                        $global:LogFormat = $PipeXml
                        RunDeepBlueImported
                        }
                    'Records'{
                        $selection3Import = Read-Host "Check the imported evtx exists under the default filename, This can take a long time, are you sure you want to continue? (Yes/No)"
                        switch ($selection3Import)
                        {
                            'Yes'{RunImportRecordCount($LogTarget)} 
                            'No'{AppCMenuImportMain}
                        }
                    }
                    'Help' {
                        Clear-Host
                        Write-Host $BannerC
                        Write-Host $DBCLIHelp      
                        }        
                    'Back' {
                        AppCMenuImportMain
                        } 
                }
                pause
            }
            'System' {
                $global:LogTarget = "Imported System"
                $global:LogType = $LogPathImportSystem
                $selection2Import = Read-Host $AppCMenuImportSub "$global:LogTarget log sub menu, waiting for your input"
                switch ($selection2Import)
                {
                    'List' {
                        $global:LogFormat = $PipeList
                        RunDeepBlue
                        } 
                    'table' {
                        $global:LogFormat = $PipeTable
                        RunDeepBlue
                        }
                    'Grid' {
                        $global:LogFormat = $PipeGrid
                        RunDeepBlueImported
                        } 
                    'Html' {
                        $global:LogFormat = $PipeHtml
                        RunDeepBlueImported
                        } 
                    'Json' {
                        $global:LogFormat = $PipeJson
                        RunDeepBlueImported
                        } 
                    'Xml' {
                        $global:LogFormat = $PipeXml
                        RunDeepBlueImported
                        }
                    'Records'{
                        $selection3Import = Read-Host "Check the imported evtx exists under the default filename, This can take a long time, are you sure you want to continue? (Yes/No)"
                        switch ($selection3Import)
                        {
                            'Yes'{RunImportRecordCount($LogTarget)} 
                            'No'{AppCMenuImportMain}
                        }
                    }
                    'Help' {
                        Clear-Host
                        Write-Host $BannerC
                        Write-Host $DBCLIHelp      
                        }        
                    'Back' {
                        AppCMenuImportMain
                        } 
                }
                pause
            } 
            'Application' {
            #Applicationflow
            } 
            'AppLocker' {
            #Applockerflow
            } 
            'PowerShell' {
                #Powershellflow
            } 
            'Sysmon' {
            #Sysmonflow
            } 
            'WMI' {
            #WMI flow
            }
            'Help' {
                Clear-Host
                Write-Host $BannerC
                Write-Host $DBCLIHelp     
            } 
            'Back' {
            DBCLIMenuMain
            }
        }
        pause
    }
    until ($selection -eq 'q')
}

# Exporting DeepBlue logs will use this switchcase
function ExportLog($LogType){
    # Clear
    clear

    # Welcome BannerAppC
    Write-Host $BannerC

    # Create export log directory and notify path
    function global:CreateLogFolder{
        $null = new-item -path "$($UserProfilePath)\Desktop\$ParentFolder" -name "$Hostname-Evtx-Logs" -itemtype directory -Force
        Write-Host $StatusCCreatedAppCLogFolder
        }
    CreateLogFolder

    # Notify export status
    foreach ($Type in $LogType){
        Write-Host ">>>>>>>>> [ Exporting $Type Log ]"
    }
    
    switch ($LogType){
        'Security' {Copy-Item -Path $LogPathSecurity -Destination "$LogPathExportFolder"}
        'System' {Copy-Item -Path $LogPathSystem -Destination "$LogPathExportFolder"}
        'Application' {Copy-Item -Path $LogPathApplication -Destination "$LogPathExportFolder"}
        'AppLocker' {Copy-Item -Path $LogPathAppLocker -Destination "$LogPathExportFolder"}
        'PowerShell' {Copy-Item -Path $LogPathPowerShell -Destination "$LogPathExportFolder"}
        'Sysmon' {Copy-Item -Path $LogPathSysmon -Destination "$LogPathExportFolder"}
        'WMI' {Copy-Item -Path $LogPathWMI -Destination "$LogPathExportFolder"}
    }
    # Notify user that the export is complete
    function global:StatusCReportExportComplete{
        Write-Host $StatusCExportComplete
        }
    StatusCReportExportComplete
}

# DeepBlue Function is called from the DBCLI Submenu grabbing the logtype and logformat requested by the user
function RunDeepBlue{
    # Clear
    clear

    # Welcome BannerAppC
    Write-Host $BannerC
    
    # Switch reading what the LogTarget is then getting the explicit LogCount
    switch ($LogTarget) {
        "Security"     { $LogCount = $LogCountSecurity }
        "System"       { $LogCount = $LogCountSystem }
        "Application"  { $LogCount = $LogCountApplication }
        "AppLocker"    { $LogCount = $LogCountApplocker }
        "PowerShell"   { $LogCount = $LogCountPowerShell }
        "Sysmon"       { $LogCount = $LogCountSysmon }
        "WMI"          { $LogCount = $LogCountWMI }
        "Imported Security"     { $LogCount = $LogCountImportSecurity }
        "Imported System"       { $LogCount = $LogCountImportSystem }
        "Imported Application"  { $LogCount = $LogCountImportApplication }
        "Imported AppLocker"    { $LogCount = $LogCountImportApplocker }
        "Imported PowerShell"   { $LogCount = $LogCountImportPowerShell }
        "Imported Sysmon"       { $LogCount = $LogCountImportSysmon }
        "Imported WMI"          { $LogCount = $LogCountImportWMI }
    }

    # Notify the query is running
    Write-Host ">>>>>>>> [ Hunting Through $LogCount $LogTarget Records ]"
    
    # Store DeepBlue explicit request so we can check use this to check for blank results with the if statement
    $output = Invoke-expression ".\DeepBlue.ps1 $LogType $LogFormat"

    # Check if the results are is empty and notify user if so.
    if (-not $output) {
    Write-Host "`n>>>>>>>>> [ No Flagged Results... ]`n`n"
    } else {
    # Output the table or do whatever you need with the results
    $output
    }
}

# AppC (DBCLI) Main Menu
function DBCLIMenuMain{
    if ($HealthCheck -eq "True") 
    {   
        #place holder for another command
        do
        {
            # Executes function to grab record count to populate AppCMenuMain
            RunRecordCount
            # MainMenu for DBCLI, not case sensitive, will take alphanumeric inputs
            $selection = Read-Host $StatusCReady $BannerC $AppCMenuMain "DeepBlue main menu, waiting for your input"
            switch ($selection)
            {
                'Security' {
                    $global:LogTarget = "Security"
                    $global:LogType = $LogPathSecurity
                    $selection2 = Read-Host $AppCMenuSub "$global:LogTarget sub menu, waiting for your input"
                    switch ($selection2)
                    {
                        'List' {
                            $global:LogFormat = $PipeList
                            RunDeepBlue
                            } 
                        'table' {
                            $global:LogFormat = $PipeTable
                            RunDeepBlue
                            }
                        'Grid' {
                            $global:LogFormat = $PipeGrid
                            RunDeepBlue
                            } 
                        'Html' {
                            $global:LogFormat = $PipeHtml
                            RunDeepBlue
                            } 
                        'Json' {
                            $global:LogFormat = $PipeJson
                            RunDeepBlue
                            } 
                        'Xml' {
                            $global:LogFormat = $PipeXml
                            RunDeepBlue
                            }
                        'Export' {
                            Write-Host $StatusCLoading
                            ExportLog("Security")
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
                    $global:LogTarget = "System"
                    $global:LogType = $LogPathSystem
                    $selection2 = Read-Host $AppCMenuSub "$global:LogTarget Menu, waiting for your input"
                    switch ($selection2)
                    {
                        'List' {
                            $global:LogFormat = $PipeList
                            RunDeepBlue
                            } 
                        'table' {
                            $global:LogFormat = $PipeTable
                            RunDeepBlue
                            }
                        'Grid' {
                            $global:LogFormat = $PipeGrid
                            RunDeepBlue
                            } 
                        'Html' {
                            $global:LogFormat = $PipeHtml
                            RunDeepBlue
                            } 
                        'Json' {
                            $global:LogFormat = $PipeJson
                            RunDeepBlue
                            } 
                        'Xml' {
                            $global:LogFormat = $PipeXml
                            RunDeepBlue
                            }
                        'Export' {
                            Write-Host $StatusCLoading
                            ExportLog("System")
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
                'Application' {
                    $global:LogTarget = "Application"
                    $global:LogType = $LogPathApplication
                    $selection2 = Read-Host $AppCMenuSub "$global:LogTarget Menu, waiting for your input"
                    switch ($selection2)
                    {
                        'List' {
                            $global:LogFormat = $PipeList
                            RunDeepBlue
                            } 
                        'table' {
                            $global:LogFormat = $PipeTable
                            RunDeepBlue
                            }
                        'Grid' {
                            $global:LogFormat = $PipeGrid
                            RunDeepBlue
                            } 
                        'Html' {
                            $global:LogFormat = $PipeHtml
                            RunDeepBlue
                            } 
                        'Json' {
                            $global:LogFormat = $PipeJson
                            RunDeepBlue
                            } 
                        'Xml' {
                            $global:LogFormat = $PipeXml
                            RunDeepBlue
                            }
                        'Export' {
                            Write-Host $StatusCLoading
                            ExportLog("Application")
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
                'AppLocker' {
                    $global:LogTarget = "AppLocker"
                    $global:LogType = $LogPathAppLocker
                    $selection2 = Read-Host $AppCMenuSub "$global:LogTarget Menu, waiting for your input"
                    switch ($selection2)
                    {
                        'List' {
                            $global:LogFormat = $PipeList
                            RunDeepBlue
                            } 
                        'table' {
                            $global:LogFormat = $PipeTable
                            RunDeepBlue
                            }
                        'Grid' {
                            $global:LogFormat = $PipeGrid
                            RunDeepBlue
                            } 
                        'Html' {
                            $global:LogFormat = $PipeHtml
                            RunDeepBlue
                            } 
                        'Json' {
                            $global:LogFormat = $PipeJson
                            RunDeepBlue
                            } 
                        'Xml' {
                            $global:LogFormat = $PipeXml
                            RunDeepBlue
                            }
                        'Export' {
                            Write-Host $StatusCLoading
                            ExportLog("AppLocker")
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
                'PowerShell' {
                    $global:LogTarget = "PowerShell"
                    $global:LogType = $LogPathPowerShell
                    $selection2 = Read-Host $AppCMenuSub "$global:LogTarget Menu, waiting for your input"
                    switch ($selection2)
                    {
                        'List' {
                            $global:LogFormat = $PipeList
                            RunDeepBlue
                            } 
                        'table' {
                            $global:LogFormat = $PipeTable
                            RunDeepBlue
                            }
                        'Grid' {
                            $global:LogFormat = $PipeGrid
                            RunDeepBlue
                            } 
                        'Html' {
                            $global:LogFormat = $PipeHtml
                            RunDeepBlue
                            } 
                        'Json' {
                            $global:LogFormat = $PipeJson
                            RunDeepBlue
                            } 
                        'Xml' {
                            $global:LogFormat = $PipeXml
                            RunDeepBlue
                            }
                        'Export' {
                            Write-Host $StatusCLoading
                            ExportLog("PowerShell")
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
                'Sysmon' {
                    $global:LogTarget = "Sysmon"
                    $global:LogType = $LogPathSysmon
                    $selection2 = Read-Host $AppCMenuSub "$global:LogTarget Menu, waiting for your input"
                    switch ($selection2)
                    {
                        'List' {
                            $global:LogFormat = $PipeList
                            RunDeepBlue
                            } 
                        'table' {
                            $global:LogFormat = $PipeTable
                            RunDeepBlue
                            }
                        'Grid' {
                            $global:LogFormat = $PipeGrid
                            RunDeepBlue
                            } 
                        'Html' {
                            $global:LogFormat = $PipeHtml
                            RunDeepBlue
                            } 
                        'Json' {
                            $global:LogFormat = $PipeJson
                            RunDeepBlue
                            } 
                        'Xml' {
                            $global:LogFormat = $PipeXml
                            RunDeepBlue
                            }
                        'Export' {
                            Write-Host $StatusCLoading
                            ExportLog("Sysmon")
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
                'WMI' {
                    $global:LogTarget = "WMI"
                    $global:LogType = $LogPathWMI
                    $selection2 = Read-Host $AppCMenuSub "$global:LogTarget Menu, waiting for your input"
                    switch ($selection2)
                    {
                        'List' {
                            $global:LogFormat = $PipeList
                            RunDeepBlue
                            } 
                        'table' {
                            $global:LogFormat = $PipeTable
                            RunDeepBlue
                            }
                        'Grid' {
                            $global:LogFormat = $PipeGrid
                            RunDeepBlue
                            } 
                        'Html' {
                            $global:LogFormat = $PipeHtml
                            RunDeepBlue
                            } 
                        'Json' {
                            $global:LogFormat = $PipeJson
                            RunDeepBlue
                            } 
                        'Xml' {
                            $global:LogFormat = $PipeXml
                            RunDeepBlue
                            }
                        'Export' {
                            Write-Host $StatusCLoading
                            ExportLog("WMI")
                            }
                        'Help' {
                            Clear-Host
                            Write-Host $BannerC
                            Write-Host $DBCLIHelp      
                            }        
                        'BBack' {
                            AppCMenuMain
                            } 
                    }
                    pause
                } 
                'Export' {
                Write-Host $StatusCLoading
                ExportLog("Security","System","Application","AppLocker","PowerShell","Sysmon","WMI")                 
                }
                'Import' {
                    Write-Host $StatusCLoading
                    RunImport
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
                AppCWipe
                }
            }
            pause
        }
        until ($selection -eq 'back')
    }
    else
    {
        Write-Host "Intialization process has failed..."
    }
}

function StartDBCLI($Source) {   
    #Clear
    clear

    # Welcome BannerAppC
    Write-Host `n`n`n`n`n`n

    # Notify DBCLI Source URL and hash based on request
     if ($Source -eq "MAIN SOURCE"){
        Write-Host "[MAIN SOURCE]: " -ForegroundColor Green -NoNewline; Write-Host $AppCURLMain -ForegroundColor Yellow
        Write-Host "    [SHA-256]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppCHashMain}" -ForegroundColor Yellow `n 
    }
    if ($Source -eq "MIRROR SOURCE"){
        Write-Host "[MIRROR SOURCE]: " -ForegroundColor Green -NoNewline; Write-Host $AppCURLMirror -ForegroundColor Yellow
        Write-Host "      [SHA-256]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppCHashMirror}" -ForegroundColor Yellow `n
    }

    # Create the ParentAppCFolder in ParentFolder (Also hiding the Powershell Output)
    $null = new-item -path "$($UserProfilePath)\Desktop" -name $ParentFolder -itemtype directory -Force
    Write-Host $StatusCCreatedAppCFolder -ForegroundColor Green

    # Change the directory to ParentAppCFolder
    set-location "$($UserProfilePath)\Desktop\$ParentFolder"
    Write-Host $StatusCChangedDirToAppCFolder -ForegroundColor Green

    # Check existing DeepBlue folder, if exist, we delete to get a new untampered copy.
    if (Test-Path .\$AppCName) {
        Remove-Item .\$AppCName -Recurse
    }
    Write-Host $StatusCCheckAndRemoveExisting -ForegroundColor Green

    # Check for Download request
    if ($Source -eq "MAIN SOURCE"){
        $global:AppCURLUsed = $AppCURLMain
        $AppCHashUsed = $AppCHashMain
    }
    if ($Source -eq "MIRROR SOURCE"){
        $global:AppCURLUsed = $AppCURLMirror
        $AppCHashUsed = $AppCHashMirror
    }

    # Download zip file from Repo
    Write-Host $StatusCDownloadApp -ForegroundColor Green
    Clear-Variable -Name "Source" -Scope Global
    Invoke-WebRequest -Uri $AppCURLUsed -OutFile .\$AppCName.zip

    # Download DBCLI
    Write-Host $StatusCHashCheck -ForegroundColor Green
    $HashDownload = Get-FileHash .\$AppCName.zip | Select-Object -ExpandProperty Hash
    Write-Host "  [EXPECTED]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppCHashUsed}" -ForegroundColor Red
    Write-Host "[DOWNLOADED]: " -ForegroundColor Green -NoNewline; Write-Host "{$HashDownload}" -ForegroundColor Red

        # Hash Diff Allow/Deny Progression    
        if ($AppCHashUsed -eq $HashDownload){
            $AppCHashValid = "True"
            Write-Host "              |------------------------- [ HASH VALID ] -----------------------|`n" -ForegroundColor Green
            
        }
        else {
            $AppCHashValid = "False"
            Write-Host "Hash INVALID, URL possibly hijacked or updated. Use MIRROR SOURCE for saftey." -ForegroundColor Red
            Remove-Item .\$AppCName.zip
            pause
            
        }

        if ($AppCHashValid -eq "True"){
        # Extract, rename, delete downloaded zip file
        Write-Host $StatusCExtractedApp -ForegroundColor Green
        Expand-Archive .\$AppCName.zip .\ -Force
        Rename-Item .\$AppCName-master .\$AppCName
        Remove-Item .\$AppCName.zip
        Write-Host $StatusCRemoveDownload -ForegroundColor Green
    
    # Change the directory to AppCName
    set-location "$($UserProfilePath)\Desktop\$ParentFolder\$AppCFolder"
    Write-Host $StatusCChangedDirToAppFolder -ForegroundColor Green

    # Check if staging and initialization is complete
    $HealthCheck = "True"
    
    # Call DBCLIMenu
    DBCLIMenuMain
    }
}

function AppCWipe {
     # Confirm from user first, then check for DeepBlue folder, if exists, delete it.

    $selectionAppCWipe = Read-Host "Are you sure you want to remove the $AppCFolder Directory? (Yes/No)"
    switch ($selectionAppCWipe)
    {
        'Yes' {
            if (Test-Path "$($UserProfilePath)\Desktop\$ParentFolder\$AppCFolder") {
                set-location "$($UserProfilePath)\Desktop\$ParentFolder"
                Remove-Item -Recurse -Force "$($UserProfilePath)\Desktop\$ParentFolder\$AppCFolder"
                Show-Menu
                }
        } 
        'No' {
            AppCMenuMain
        }
    }
    pause
 }
 until ($selection -eq 'back')

function WipeTHC {
    # Confirm from user first, then check for THC folder, if exists, delete it.

    $selectionWipeTHC = Read-Host "Are you sure you want to remove $ParentFolder Directory? (Yes/No)"
    switch ($selectionWipeTHC)
    {
        'Yes' {
            if (Test-Path "$($UserProfilePath)\Desktop\$ParentFolder") {
                set-location "$($UserProfilePath)\Desktop"
                Remove-Item "$($UserProfilePath)\Desktop\$ParentFolder" -Recurse -Force
                }
        } 
        'No' {
            Show-Menu
        }
    }
    pause
 }
 until ($selection -eq 'back')


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
        $global:Source = "MAIN SOURCE"
        StartDBCLI($Source)
        
        } 
        'D' {
        $global:Source = "MIRROR SOURCE"
        StartDBCLI($Source)
        
        } 
        'E' {
        'Placeholder'
        } 
        'F' {
        'Autoruns'
        }
        'G' {
        'CTI SEARCH'
        }
        'H' {
        WipeTHC
        }
        'X' {
        'Contact'
        }
        'Z' {
        'Soft Exit'
        }
        'ZZ' {
        'Hard Exit'
        }
    }
    pause
 }
 until ($selection -eq 'back')

