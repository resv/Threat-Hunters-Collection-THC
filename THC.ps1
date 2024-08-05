 
# Enable this script only: powershell.exe -noprofile -executionpolicy bypass -file .\THC.ps1

# for quicker testing: 
    #To Get status: Get-ExecutionPolicy
    #To Set status unrestricted/remotesigned: Set-ExecutionPolicy RemoteSigned
    #To Set status back to restricted: Set-ExecutionPolicy Res

# Quick info for SYSMON policy changes required, go to for screenshots https://mahim-firoj.medium.com/incident-response-and-threat-hunting-using-deepbluecli-tool-bf5d4c52c8a8

# VARIABLES - BANNERS

$Banner1of4= @"
_________________________________________________________________________________
"@ 
$Banner2of4= @"
  ________  ______  _________  ______   __  ____  ___   __________________  _____
 /_  __/ / / / __ \/ ____/   |/_  __/  / / / / / / / | / /_  __/ ____/ __ \/ ___/
  / / / /_/ / /_/ / __/ / /| | / /    / /_/ / / / /  |/ / / / / __/ / /_/ /\__ \ 
 / / / __  / _, _/ /___/ ___ |/ /    / __  / /_/ / /|  / / / / /___/ _, _/___/ / 
/_/ /_/ /_/_/_|_/_____/_/  |_/_/   _/_/_/_/\____/_/_|_/_/_/_/_____/_/ |_|/____/  
          / ____/ __ \/ /   / /   / ____/ ____/_  __/  _/ __ \/ | / /            
         / /   / / / / /   / /   / __/ / /     / /  / // / / /  |/ /             
        / /___/ /_/ / /___/ /___/ /___/ /___  / / _/ // /_/ / /|  /              
        \____/\____/_____/_____/_____/\____/ /_/ /___/\____/_/ |_/`n
"@   
$Banner3of4= @"
                                            Catalyzed with purpose by: Adam Kim
"@   

$Banner4of4= @"
_________________________________________________________________________________`n
"@   

$HealthCheck = "False"

# VARIABLES - ParentFolder
$ParentFolder = "Threat Hunters Collection"
$UserProfilePath = $($env:userprofile)
$UserDesktopPath = [Environment]::GetFolderPath("Desktop")
$StatusLoadingLineBreak = "`n`n`n`n`n`n"
$StatusBlankSpace = "                   "
$StatusCreatedParentFolder = "> [ Adding new directory $UserDesktopPath\$ParentFolder ]`n"
$StatusChangedDirToParentFolder = ">> [ Changed directory to $UserDesktopPath\$ParentFolder ]`n"
$StatusWipeReminder = "[ Don't forget to wipe THC :) ]"

# VARIABLES A - AppA (Host Info)
$BannerA = @"
_________________________________________________________________________________
                    __  ______  ___________   _____   ____________ 
                   / / / / __ \/ ___/_  __/  /  _/ | / / ____/ __ \
                  / /_/ / / / /\__ \ / /     / //  |/ / /_  / / / /
                 / __  / /_/ /___/ // /    _/ // /|  / __/ / /_/ / 
                /_/ /_/\____//____//_/    /___/_/ |_/_/    \____/   
_________________________________________________________________________________`n
"@
    $AppAName = "HOST INFO"
    $AppADescription = "Enumerate Host Info"
    $Hostname = hostname
    $PrintWorkingDirectory = Get-Location
        #Grab IP info
        $IPAddress= $env:HostIP = (Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"}).IPv4Address.IPAddress
    $GetVolume = "Get-Volume | Select-Object @{Name='Drive';Expression='DriveLetter'}, FileSystemLabel, @{Name='Free `(GB`)';Expression={[math]::Round(`$_.SizeRemaining / 1GB, 2)}}, @{Name='Size `(GB`)';Expression={[math]::Round(`$_.Size / 1GB, 2)}}, @{Name='Type';Expression='FileSystemType'}, @{Name='Mount';Expression='DriveType'}, @{Name='Health';Expression='HealthStatus'},@{Name='Status';Expression='OperationalStatus'}| Format-Table -Wrap | Out-String"
    $GetCIM = "Get-CimInstance -ClassName Win32_Desktop | Select-Object @{Name='Name | ScreenSaver ------->';Expression='Name'}, @{Name='Active';Expression='ScreenSaverActive'}, @{Name='Secure';Expression='ScreenSaverSecure'}, @{Name='Timeout';Expression='ScreenSaverTimeout'}| Format-Table -Wrap | Out-String"
    $StatusAExportComplete = "`n>>>>>>>>>>> [ Exported raw logs to $UserDesktopPath\$ParentFolder\$Hostname-Host-Info ]`n"

# FUNCTION A
    function HostInfo {
    #Clear
    Clear
    
    #Make room for Loadingbar
    Write-Host $StatusLoadingLineBreak
    
    # Start transcript to capture all output, appends info if tracking changes.
    Start-Transcript -Path "$UserDesktopPath\$ParentFolder\$Hostname-Host-Info.txt" -Append | Out-Null
    
    # Welcome BannerAppA
    Write-Host $BannerA
    
    # Host Information
    Write-Host "----------------------------------- [ HOST INFORMATION ] -----------------------------------`n" -ForegroundColor Green

    # Get current time stamp
    Write-Host "[Date]: $(Get-Date)"
    
    # Notify hostname & IP address
    Write-Host "[Hostname]: $Hostname"
    Write-Host "[Profile]: $UserProfilePath"
    Write-Host "[Desktop Path]: $UserDesktopPath"
    Write-Host "[IP Address]: $IPAddress" -NoNewline
    
    # More PC Info
    Get-ComputerInfo -Property "CsNetworkAdapters","CsDomain","CsUserName","LogonServer","WindowsRegisteredOwner","WindowsProductName","WindowsEditionId","OsArchitecture","OsBuildNumber","OsVersion","CsManufacturer","CsModel","BiosName","CsProcessors","CsNumberOfLogicalProcessors","TimeZone","OsInstallDate","OsLastBootUpTime","OsLocalDateTime","OsUptime"

    # Drive Information
    Write-Host "---------------------------------- [ DRIVE INFORMATION ] ------------------------------------" -ForegroundColor Green
    Invoke-Expression $GetVolume.Trim()

    # All Desktops in Use or Not
    Write-Host "-------------------------------- [ DESKTOPS | SCREENSAVER ] ---------------------------------" -ForegroundColor Green
    Invoke-Expression $GetCIM.Trim()
    
    Write-Host $StatusAExportComplete -ForegroundColor Yellow
    # Stop transcript
    Stop-Transcript | Out-Null
    pause
}

# VARIABLES B - AppB (Sysmon)
$BannerB = @"
_________________________________________________________________________________
                     _______  _______ __  _______  _   __
                    / ___/\ \/ / ___//  |/  / __ \/ | / /
                    \__ \  \  /\__ \/ /|_/ / / / /  |/ / 
                   ___/ /  / /___/ / /  / / /_/ / /|  /  
                  /____/  /_//____/_/  /_/\____/_/ |_/
_________________________________________________________________________________`n
"@
$AppBName = "SYSMON"
$AppBDescription = "Log System Activity to the Windows Event Log v15.15"
$AppBVersion = "v15.15"
$AppBFolder = "Sysmon"

        # URLs
        $AppBURLMain = "https://download.sysinternals.com/files/Sysmon.zip"
        $AppBURLMirror = "https://github.com/resv/THC-MIRROR-APPS/raw/main/Sysmon/Sysmon.zip"
           
    $AppBHashMain = "0EDB284C2157562C15B2EB6F7FB0B3D1752C86DBCE782FD4E5DFEA89B10E4BA6"
    $AppBHashMirror = "0EDB284C2157562C15B2EB6F7FB0B3D1752C86DBCE782FD4E5DFEA89B10E4BA6"

        # VARIABLES H - Status notifications
    $StatusBCreatedAppBFolder = "> [ Adding directory $UserDesktopPath\$ParentFolder\$AppBFolder ]`n"
    $StatusBDetectedExisting = ">>> [ Detected existing $AppBName files in $UserDesktopPath\$ParentFolder\$AppBFolder ]`n"
    $StatusBRemoveExisting = ">>> [ Removed existing $AppBName files in $UserDesktopPath\$ParentFolder\$AppBFolder ]`n"
    $StatusBChangedDirToAppBFolder = ">> [ Changed directory to $UserDesktopPath\$ParentFolder\$AppBFolder ]`n"
    $StatusBCheckAndRemoveExisting = ">>> [ Removing any existing $AppBName files ]`n"
    $StatusBDownloadApp = ">>>> [ Downloading `"$AppBName.zip`" ]`n"
    $StatusBHashCheck = ">>>>> [ Checking hash ]`n"
    $StatusBExtractedApp = ">>>>>> [ Extracted `"$AppBName`" ]`n"
    $StatusBRemoveDownload =  ">>>>>>> [ Removed downloaded files for `"$AppBName`" ]`n"
    $StatusBChangedDirToAppFolder = ">>>>>>>> [ You are in the $UserDesktopPath\$ParentFolder\$AppBFolder ]`n"
    $StatusBBootUp = ">>>>>>>>> Booting up `"$AppBName`"`n" 
    $StatusBReady = "`n>>>>>>>>> [ $AppBName Installed and Ready for Hunting... ]`n"
    $StatusBWipe = ">>>>>>>>>> [ Wiping $AppBName ]"
    $StatusBRemoving = "Removing $AppBName"

    # AppBMenuMain
    $AppBMenu = @"
`n
         ________[ Sysmon MENU ]_________
        |                                |
        |   [Check] | Validate Sysmon    |
        |    [Wipe] | Wipe Sysmon        |
        |     [REM] | Uninstall Sysmon   |
        |    [Info] | Event ID Info      |
        |    [Exit] | Exit Hard          |
        |    [Back] | Back to Main Menu  |
        |________________________________|`n `n
"@

function StartSysmon($Source) {   
    #Clear
    clear

    # Make space for download status bar
    Write-Host $StatusLoadingLineBreak

    # Notify Sysmon Source URL and hash based on request
    if ($Source -eq "MAIN SOURCE"){
        Write-Host "[MAIN SOURCE]: " -ForegroundColor Green -NoNewline; Write-Host $AppBURLMain -ForegroundColor Yellow
        Write-Host "    [SHA-256]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppBHashMain}" -ForegroundColor Yellow `n 
    }
    if ($Source -eq "MIRROR SOURCE"){
        Write-Host "[MIRROR SOURCE]: " -ForegroundColor Green -NoNewline; Write-Host $AppBURLMirror -ForegroundColor Yellow
        Write-Host "      [SHA-256]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppBHashMirror}" -ForegroundColor Yellow `n
    }

    # Create ParentFolder (Also hiding the Powershell Output)
    $null = new-item -path "$UserDesktopPath" -name $ParentFolder -itemtype directory -Force

    # Change the directory to ParentFolder
    set-location "$UserDesktopPath\$ParentFolder"

    # Check existing Sysmon folder, if exist, we delete for a fresh start.
    if (Test-Path .\$AppBName) {
        Write-Host $StatusBDetectedExisting -ForegroundColor Green
        Remove-Item .\$AppBName -Recurse -Force
        Write-Host $StatusBRemoveExisting -ForegroundColor Green
    }

    # Create new Sysmon Folder, change dir to Sysmon folder
    $null = New-Item -Path .\ -Name "$AppBName" -ItemType "directory" -Force
    Write-Host $StatusBCreatedAppBFolder -ForegroundColor Green
    set-location "$UserDesktopPath\$ParentFolder\$AppBName"
    Write-Host $StatusBChangedDirToAppBFolder -ForegroundColor Green        

    # Check for Download request
    if ($Source -eq "MAIN SOURCE"){
        $global:AppBURLUsed = $AppBURLMain
        $AppBHashUsed = $AppBHashMain
    }
    if ($Source -eq "MIRROR SOURCE"){
        $global:AppBURLUsed = $AppBURLMirror
        $AppBHashUsed = $AppBHashMirror
    }

    # Download zip file from Repo
    Write-Host $StatusBDownloadApp -ForegroundColor Green
    Clear-Variable -Name "Source" -Scope Global
    Invoke-WebRequest -Uri $AppBURLUsed -OutFile .\$AppBName.zip

    # Download Sysmon
    Write-Host $StatusBHashCheck -ForegroundColor Green
    $HashDownload = Get-FileHash .\$AppBName.zip | Select-Object -ExpandProperty Hash
 

        # Hash Diff Allow/Deny Progression    
        if ($AppBHashUsed -eq $HashDownload){
            $AppBHashValid = "True"
            Write-Host "  [EXPECTED]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppBHashUsed}" -ForegroundColor Green
            Write-Host "[DOWNLOADED]: " -ForegroundColor Green -NoNewline; Write-Host "{$HashDownload}" -ForegroundColor Green
            Write-Host "              |------------------------ [ HASH VALID ] ------------------------|`n" -ForegroundColor Yellow
            
        }
        else {
            $AppBHashValid = "False"
            Write-Host "  [EXPECTED]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppBHashUsed}" -ForegroundColor Green
            Write-Host "[DOWNLOADED]: " -ForegroundColor Green -NoNewline; Write-Host "{$HashDownload}" -ForegroundColor Red
            Write-Host "              |----------------------- [ HASH INVALID ] -----------------------|`n" -ForegroundColor Red
            Write-Host "Hash INVALID, URL possibly hijacked or updated. Removed $AppBName.zip, Use MIRROR SOURCE for saftey." -ForegroundColor Red
            set-location "$UserDesktopPath\$ParentFolder"
            Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppBName.zip"
            Read-Host "Press any key to return to the main menu"
        }

        if ($AppBHashValid -eq "True"){
        # Extract, rename, delete downloaded zip file
        Write-Host $StatusBExtractedApp -ForegroundColor Green
        Expand-Archive .\$AppBName.zip .\ -Force
        Write-Host $StatusBRemoveDownload -ForegroundColor Green
        Remove-Item .\$AppBName.zip
        set-location "$UserDesktopPath\$ParentFolder\$AppBFolder"
        Remove-Item .\Sysmon.exe
        Remove-Item .\Sysmon64a.exe
        Remove-Item .\Eula.txt
        Write-Host $StatusBBootUp -ForegroundColor Green
        Invoke-Expression "./Sysmon64.exe -accepteula -i"
        Write-Host $StatusBReady -ForegroundColor Cyan
        AppBMenuMain
        }

        if ($AppBHashValid -eq "False"){
        # Exit back to main menu
        Show-Menu
        }
}

#AppB Sysmon main menu
function AppBMenuMain{      
    do
    {  
        $selectionAppB = Read-Host $BannerB $AppBMenu "$AppBName main menu, waiting for your input"
        switch ($selectionAppB)
        {
            'Check' {
                AppBCheck
                Show-Menu
            }
            'Wipe' {
                AppBWipe
                Show-Menu
            }
            'REM' {
                AppBRemove
                Show-Menu
            }
            'Info' {
                Clear-Host
                AppBInfo
                pause
                Clear-Host
            }
            'Exit' {
                ExitHard
            }
            'Back' {
                clear
                Show-Menu
            }
            '' {
            clear
            AppBMenuMain
            }
        }
    }
    until ($selectionAppB -eq 'Check' -or $selectionAppB -eq 'Wipe' -or $selectionAppB -eq 'REM' -or $selectionAppB -eq 'Back' -or $selectionAppB -eq '')
}

# Validate Sysmon (Different format due to exe)
function AppBCheck {
    # Check if Sysmon is installed
    $SysmonOutput = sysmon64 2> $null

    # Define expected output for installed Sysmon (adjust as needed)
    $Output1 = "System Monitor v15.15"
    $Output2 = "The operation completed successfully."

    if ($SysmonOutput -match $Output1 -and $SysmonOutput -match $Output2) {
        Write-Host `n $StatusBlankSpace "Sysmon v15.15 is INSTALLED."`n -ForegroundColor Green
    } else {
        Write-Host `n $StatusBlankSpace "Sysmon v15.15 is not installed (Other versions are not checked)"`n -ForegroundColor Red
    }
    pause
    AppBMenuMain
}     

# Wipe Sysmon (Different format due to exe)
function AppBWipe {
    do
    {
    # Confirm user, then implement
    $selectionAppBWipe = Read-Host "Are you sure you want to close & wipe $AppBName (Y/N)"
    switch ($selectionAppBWipe)
    {
        'Y' {
            if (Test-Path "$UserDesktopPath\$ParentFolder\$AppBFolder") {
                Write-Host $StatusBWipe`n
                Write-Host $StatusWipeReminder -ForegroundColor DarkMagenta -Background Yellow
                set-location "$UserDesktopPath\$ParentFolder"
                Start-Sleep -Seconds 2
                Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppBFolder"
                }
        } 
        'N' {
            clear
            AppBMenuMain
        }
        '' {
            AppBWipe
        }
    }
 }
until ($selectionAppBWipe -eq 'Y' -or $selectionAppBWipe -eq 'N' -or $selectionAppBWipe -eq '')
}     

# Uninstall Sysmon cd (Invoke-expression cmd line can be anywhere)
function AppBRemove {
    do
    {
    # Confirm user, then implement
    $selectionAppBRemove = Read-Host "Are you sure you want to remove $AppBName (Y/N)"
    switch ($selectionAppBRemove)
    {
        'Y' {
            Write-Host $StatusBWipe`n
            Write-Host $StatusWipeReminder -ForegroundColor DarkMagenta -Background Yellow
            set-location "$UserDesktopPath\$ParentFolder"
            Write-Host $StatusBRemoving`n
            Invoke-Expression "sysmon64 -u"
            Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppBFolder"
            AppBMenuMain
        } 
        'N' {
            clear
            AppBMenuMain
        }
        '' {
            AppBRemove
        }
    }
 }
until ($selectionAppBRemove -eq 'Y' -or $selectionAppBRemove -eq 'N' -or $selectionAppBRemove -eq '')
}     

function AppBInfo {
    Write-Host $BannerB
    Write-Host $AppBEventIDs -ForegroundColor Green
}

$AppBEventIDs = @"
Event ID 1: Process creation
Event ID 2: A process changed a file creation time
Event ID 3: Network connection
Event ID 4: Sysmon service state changed
Event ID 5: Process terminated
Event ID 6: Driver loaded
Event ID 7: Image loaded
Event ID 8: CreateRemoteThread
Event ID 9: RawAccessRead
Event ID 10: ProcessAccess
Event ID 11: FileCreate
Event ID 12: RegistryEvent (Object create and delete)
Event ID 13: RegistryEvent (Value Set)
Event ID 14: RegistryEvent (Key and Value Rename)
Event ID 15: FileCreateStreamHash
Event ID 16: ServiceConfigurationChange
Event ID 17: PipeEvent (Pipe Created)
Event ID 18: PipeEvent (Pipe Connected)
Event ID 19: WmiEvent (WmiEventFilter activity detected)
Event ID 20: WmiEvent (WmiEventConsumer activity detected)
Event ID 21: WmiEvent (WmiEventConsumerToFilter activity detected)
Event ID 22: DNSEvent (DNS query)
Event ID 23: FileDelete (File Delete archived)
Event ID 24: ClipboardChange (New content in the clipboard)
Event ID 25: ProcessTampering (Process image change)
Event ID 26: FileDeleteDetected (File Delete logged)
Event ID 27: FileBlockExecutable
Event ID 28: FileBlockShredding
Event ID 29: FileExecutableDetected
Event ID 255: Error
"@

# VARIABLES C - AppC (DeepBlueCLI)
$BannerC = @"
_________________________________________________________________________________
        ____  ________________     ____  __    __  ________   ________    ____
       / __ \/ ____/ ____/ __ \   / __ )/ /   / / / / ____/  / ____/ /   /  _/
      / / / / __/ / __/ / /_/ /  / __  / /   / / / / __/    / /   / /    / /  
     / /_/ / /___/ /___/ ____/  / /_/ / /___/ /_/ / /___   / /___/ /____/ /   
    /_____/_____/_____/_/      /_____/_____/\____/_____/   \____/_____/___/
_________________________________________________________________________________`n
"@
    $AppCName = "DEEPBLUECLI"
    $AppCDescription = "Hunt via Windows Event Logs"
    $AppCFolder = "DeepBlueCLI"
        # URLs
        $AppCURLMain = "https://github.com/sans-blue-team/DeepBlueCLI/archive/refs/heads/master.zip"
        $AppCURLMirror = "https://github.com/resv/THC-MIRROR-APPS/raw/main/DeepBlueCLI-master.zip"
           
    $AppCHashMain = "2295C0E92697A8F5425F20E4119F7A049428C2A47AF48F88ABABA206309DEE51"
    $AppCHashMirror = "A86D97A25D790F860B89887C241961C60BBCD12C13D47C31FA4125CBF30E8C1E"

    # VARIABLES C - Status notifications
    $StatusCCreatedAppCFolder = "> [ Adding directory $UserDesktopPath\$ParentFolder\$AppCFolder ]`n"
    $StatusCChangedDirToAppCFolder = ">> [ Changed directory to ..\$AppCFolder ]`n"
    $StatusCCheckAndRemoveExisting = ">>> [ Removing any existing DeepBlue files ]`n"
    $StatusCDownloadApp = ">>>> [ Downloading `"$AppCName`" ]`n"
    $StatusCHashCheck = ">>>>> [ Checking hash ]`n"
    $StatusCExtractedApp = ">>>>>> [ Extracted `"$AppCName`" ]`n"
    $StatusCRemoveDownload =  ">>>>>>> [ Removed downloaded files for `"$AppCName`" ]`n"
    $StatusCChangedDirToAppFolder = ">>>>>>>> [ You are in the $UserDesktopPath\$ParentFolder\$AppCFolder ]`n"
    $StatusCReady = ">>>>>>>>> [ Ready for Hunting... ]`n"
    $StatusCLoading = ">>>>>>>>>> [ Retrieving Data... ]`n"
    $StatusCCreatedAppCLogFolder = "`n>>>>>>>>> [ Adding new directory `"$Hostname-Evtx-Logs`" ]`n"
    $StatusCCreatedAppCImportLogFolder = "`n>>>>>>>> [ Adding new directories $UserDesktopPath\$ParentFolder\Import-Log-Folder ]`n"
    $StatusCExportComplete = "`n>>>>>>>>>>> [ Exported raw logs to $UserDesktopPath\$ParentFolder\$Hostname-Evtx-Logs ]`n"
    $DeepBlueExecute = ".\DeepBlue.ps1"
    $LogPathExportFolder = "$UserDesktopPath\$ParentFolder\$Hostname-Evtx-Logs"
    $LogPathImportFolder = "$UserDesktopPath\$ParentFolder\Import-Log-Folder"
    $LogPathSecurity = "C:\Windows\System32\winevt\Logs\Security.evtx"
    $LogPathSystem = "C:\Windows\System32\winevt\Logs\System.evtx"
    $LogPathApplication = "C:\Windows\System32\winevt\Logs\Application.evtx"
    $LogPathAppLocker = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-AppLocker%4EXE and DLL.evtx"
    $LogPathPowerShell = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx"
    $LogPathSysmon = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx"
    $LogPathWMI = "C:\Windows\System32\winevt\Logs\Microsoft-Windows-WMI-Activity%4Operational.evtx"
    $LogPathImportSecurity = "$UserDesktopPath\$ParentFolder\Import-Log-Folder\Security.evtx"
    $LogPathImportSystem = "$UserDesktopPath\$ParentFolder\Import-Log-Folder\System.evtx"
    $LogPathImportApplication = "$UserDesktopPath\$ParentFolder\Import-Log-Folder\Application.evtx"
    $LogPathImportAppLocker = "$UserDesktopPath\$ParentFolder\Import-Log-Folder\Microsoft-Windows-AppLocker%4EXE and DLL.evtx"
    $LogPathImportPowerShell = "$UserDesktopPath\$ParentFolder\Import-Log-Folder\Microsoft-Windows-PowerShell%4Operational.evtx"
    $LogPathImportSysmon = "$UserDesktopPath\$ParentFolder\Import-Log-Folder\Microsoft-Windows-Sysmon%4Operational.evtx"
    $LogPathImportWMI = "$UserDesktopPath\$ParentFolder\Import-Log-Folder\Microsoft-Windows-WMI-Activity%4Operational.evtx"
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
    | *[Grid]  | Out-GridView view   |
    |  [HTML]  | ConvertTo-Html view |
    |  [JSON]  | ConvertTo-Json view |
    |  [XML]   | ConvertTo-Xml view  |
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
    | [Application] | $($global:LogCountImportApplication.Count) Records
    | [AppLocker]   | $($global:LogCountImportAppLocker.Count) Records
    | [Powershell]  | $($global:LogCountImportPowershell.Count) Records
    | [Sysmon]      | $($global:LogCountImportSysmon.Count) Records
    | [WMI]         | $($global:LogCountImportWMI.Count) Records
    | [All]         | Filters all logs  |
    | [Help]        | Syntax & Paths    |
    | [Back]        | Back to Main Menu |
    |___________________________________|`n `n
"@

    # AppCMenuSub
    $AppCMenuSub = @"
    `n
           $global:LogTarget ($LogCount)
     _______[ DEEPBLUECLI SUB MENU ]______
    |                                     |
    | *[List]      | Format-List view     |
    | *[Table]     | Format-Table view    |
    | *[Grid]      | Out-GridView view    |
    |  [HTML]      | ConvertTo-Html view  |
    |  [JSON]      | ConvertTo-Json view  |
    |  [XML]       | ConvertTo-Xml view   |
    |  [Help]      | Syntax & Paths       |
    |  [Export]    | Export Logs          |
    |  [Exit]      | Hard Exit            |
    |  [Back]      | Back to Main Menu    |
    |_____________________________________|`n `n
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
    | [Exit]        | Hard Exit         |
    | [Back]        | Back to Main Menu |
    |___________________________________|`n `n
"@

    $DBCLIHelp = @"
`n
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
    $global:LogCountImportSecurity = Invoke-expression "get-winevent -Path `"$UserDesktopPath\$ParentFolder\Import-Log-Folder\Security.evtx`" -MaxEvents 1000000"
    $ImportRecordCount = $global:LogCountImportSecurity.Count
    }

    if ($LogTarget -eq "Imported System"){
    $global:LogCountImportSystem = Invoke-expression "get-winevent -Path `"$UserDesktopPath\$ParentFolder\Import-Log-Folder\System.evtx`" -MaxEvents 1000000"
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
    $null = new-item -path "$UserDesktopPath\$ParentFolder" -name "Import-Log-Folder" -itemtype directory -Force
    Write-Host $StatusCCreatedAppCImportLogFolder
    Write-Host ">>>>>>>>> [ DeepBlue will assume unchanged default evtx file names ] `n"
    Write-Host ">>>>>>>>>> [ DROP EXTERNAL EVTX FILES TO `"Import-Log-Folder`", DO NOT CHANGE FILENAMES ]`n`n`n" -ForegroundColor Yellow
    Write-Host "                                       Press enter to continue...                                       `n`n" -ForegroundColor Yellow
    
    # Give user time to import file to the import folder, wait for the user to press Enter
    Read-Host
    # Notify user that this will take a long time..and it will..These global variables can be commented to remove this wait time but you won't get the record count.
    Write-Host "                            Checking record count, this can take a long time...                                       " -ForegroundColor Yellow

    # This part does the record count for Import Menu
    $global:LogCountImportSecurity = Invoke-expression "get-winevent -Path `"$LogPathImportSecurity`" -MaxEvents 500000"
    #$global:LogCountImportSystem = Invoke-expression "get-winevent -Path `"$UserDesktopPath\$ParentFolder\Import-Log-Folder\System.evtx`" -MaxEvents 500000"
    #$global:LogCountImportApplication = Invoke-expression "get-winevent -Path `"$UserDesktopPath\$ParentFolder\Import-Log-Folder\Application.evtx`" -MaxEvents 500000"
    $global:LogCountImportAppLocker = Invoke-expression "get-winevent -Path `"$LogPathImportAppLocker`" -MaxEvents 500000"
    #$global:LogCountImportPowerShell = Invoke-expression "get-winevent -Path `"$UserDesktopPath\$ParentFolder\Import-Log-Folder\Microsoft-Windows-PowerShell%4Operational.evtx`" -MaxEvents 500000"
    #$global:LogCountImportSysmon = Invoke-expression "get-winevent -Path `"$UserDesktopPath\$ParentFolder\Import-Log-Folder\Microsoft-Windows-Sysmon%4Operational.evtx`" -MaxEvents 500000"
    #$global:LogCountImportWMI = Invoke-expression "get-winevent -Path `"$UserDesktopPath\$ParentFolder\Import-Log-Folder\Microsoft-Windows-WMI-Activity%4Operational.evtx`" -MaxEvents 500000"

    do
    {
        $selectionImport = Read-Host $AppCMenuImportMain "Imported main menu, Waiting for your input"
        switch ($selectionImport)
        {
            'Security' {
                clear
                Write-Host $BannerC
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
                        $selection3Import = Read-Host "Check the imported evtx exists under the default filename, This can take a long time, are you sure you want to continue? (Y/N)"
                        switch ($selection3Import)
                        {
                            'Y'{RunImportRecordCount($LogTarget)} 
                            'N'{AppCMenuImportMain}
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
                clear
                Write-Host $BannerC
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
                        $selection3Import = Read-Host "Check the imported evtx exists under the default filename, This can take a long time, are you sure you want to continue? (Y/N)"
                        switch ($selection3Import)
                        {
                            'Y'{RunImportRecordCount($LogTarget)} 
                            'N'{AppCMenuImportMain}
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
        $null = new-item -path "$UserDesktopPath\$ParentFolder" -name "$Hostname-Evtx-Logs" -itemtype directory -Force
        Write-Host $StatusCCreatedAppCLogFolder -ForegroundColor Yellow
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
    Write-host $StatusCExportComplete -ForegroundColor Yellow
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
                        'Exit' {
                            ExitHard     
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
                        'Exit' {
                            ExitHard
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
                        'Exit' {
                            ExitHard  
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
                        'Exit' {
                            ExitHard  
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
                        'Exit' {
                            ExitHard   
                            }           
                        'Back' {
                            DBCLIMenuMain
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
                        'Exit' {
                            ExitHard   
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
                        'Exit' {
                            ExitHard  
                            }           
                        'Back' {
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
                'Wipe' {
                AppCWipe
                }
                'Exit' {
                ExitHard
                }
                'Back' {
                Show-Menu
                }
                '' {
                clear
                DBCLIMenuMain
                }
            }
            pause
        }
        until ($selection -eq 'Back' -or $selection -eq '')
    }
    else
    {
        Write-Host "Intialization process has failed..."
    }
}

function StartDBCLI($Source) {   
    #Clear
    clear

    # Make space for download status bar
    Write-Host $StatusLoadingLineBreak

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
    $null = new-item -path "$UserDesktopPath" -name $ParentFolder -itemtype directory -Force
    Write-Host $StatusCCreatedAppCFolder -ForegroundColor Green

    # Change the directory to ParentAppCFolder
    set-location "$UserDesktopPath\$ParentFolder"
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
 

        # Hash Diff Allow/Deny Progression    
        if ($AppCHashUsed -eq $HashDownload){
            $AppCHashValid = "True"
            Write-Host "  [EXPECTED]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppCHashUsed}" -ForegroundColor Green
            Write-Host "[DOWNLOADED]: " -ForegroundColor Green -NoNewline; Write-Host "{$HashDownload}" -ForegroundColor Green
            Write-Host "              |------------------------ [ HASH VALID ] ------------------------|`n" -ForegroundColor Yellow
            
        }
        else {
            $AppCHashValid = "False"
            Write-Host "  [EXPECTED]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppCHashUsed}" -ForegroundColor Green
            Write-Host "[DOWNLOADED]: " -ForegroundColor Green -NoNewline; Write-Host "{$HashDownload}" -ForegroundColor Red
            Write-Host "              |----------------------- [ HASH INVALID ] -----------------------|`n" -ForegroundColor Red
            Write-Host "Hash INVALID, URL possibly hijacked or updated. Removed $AppCName.zip, Use MIRROR SOURCE for saftey." -ForegroundColor Red
            set-location "$UserDesktopPath\$ParentFolder"
            Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppCName.zip"
            Read-Host "Press any key to return to the main menu"
        }

        if ($AppCHashValid -eq "True"){
        # Extract, rename, delete downloaded zip file
        Write-Host $StatusCExtractedApp -ForegroundColor Green
        Expand-Archive .\$AppCName.zip .\ -Force
        Rename-Item .\$AppCName-master .\$AppCName
        Remove-Item .\$AppCName.zip
        Write-Host $StatusCRemoveDownload -ForegroundColor Green

        if ($AppCHashValid -eq "False"){
        Show-Menu
        }
    
    # Change the directory to AppCName
    set-location "$UserDesktopPath\$ParentFolder\$AppCFolder"
    Write-Host $StatusCChangedDirToAppFolder -ForegroundColor Green

    # Check if staging and initialization is complete
    $HealthCheck = "True"
    
    # Call DBCLIMenu
    DBCLIMenuMain
    }
}

function AppCWipe {
    do {
     # Confirm from user first, then check for DeepBlue folder, if exists, delete it.
    $selectionAppCWipe = Read-Host "Are you sure you want wipe $AppCFolder? (Y/N)"
    switch ($selectionAppCWipe)
    {
        'Y' {
            if (Test-Path "$UserDesktopPath\$ParentFolder\$AppCFolder") {
                set-location "$UserDesktopPath\$ParentFolder"
                Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppCFolder"
                Show-Menu
                return
                }
        } 
        'N' {
            return
            DBCLIMenuMain
        }
        '' {
            AppCWipe
        }
    }
 }
 until ($selection -eq 'Y' -or $selection -eq 'N' -or $selection -eq '')
}

# VARIABLES - AppF (Autoruns)
$BannerF = @"
_________________________________________________________________________________
                 ___   __  ____________  ____  __  ___   _______
                /   | / / / /_  __/ __ \/ __ \/ / / / | / / ___/
               / /| |/ / / / / / / / / / /_/ / / / /  |/ /\__ \ 
              / ___ / /_/ / / / / /_/ / _, _/ /_/ / /|  /___/ / 
             /_/  |_\____/ /_/  \____/_/ |_|\____/_/ |_//____/
_________________________________________________________________________________`n
"@

$AppFName = "AUTORUNS"
$AppFDescription = "Scheduled Tasks/Persistence Check v14.11" 
    $AppFFolder = "Autoruns"
        # URLs
        $AppFURLMain = "https://live.sysinternals.com/autoruns.exe"
        $AppFURLMirror = "https://github.com/resv/THC-MIRROR-APPS/raw/main/Autoruns/autoruns.exe"
           
    $AppFHashMain = "F41051697B220757F3612ECD00749B952CE7BCAADD9DC782D79EF0338E45C3B6"
    $AppFHashMirror = "F41051697B220757F3612ECD00749B952CE7BCAADD9DC782D79EF0338E45C3B6"

    # VARIABLES F - Status notifications
    $StatusFDetectedExisting = ">>> [ Detected existing $AppFName files in $UserDesktopPath\$ParentFolder\$AppFFolder ]`n"
    $StatusFRemoveExisting = ">>> [ Removed existing $AppFName files in $UserDesktopPath\$ParentFolder\$AppFFolder ]`n"
    $StatusFCreatedAppFFolder = ">>>> [ Adding new directory $UserDesktopPath\$ParentFolder\$AppFFolder ]`n"
    $StatusFChangedDirToAppFFolder = ">>>>> [ Changed working directory to $UserDesktopPath\$ParentFolder\$AppFFolder ]`n"
    $StatusFDownloadApp = ">>>>>> [ Downloading `"$AppFName.exe`" ]`n"
    $StatusFHashCheck = ">>>>>>> [ Checking hash ]`n"
    $StatusFBootUp = ">>>>>>>> [ Booting up `"$AppFName`" ]`n"
    $StatusFReady = ">>>>>>>>> [ $AppFName is Ready for Hunting... ]`n"
    $StatusFWipe = ">>>>>>>>>> [ Wiping $AppFName ]"
    $StatusFCreatedAppFLogFolder = "`n10 [ Adding new directory `"$Hostname-Evtx-Logs`" ]`n"
    $StatusFCreatedAppFImportLogFolder = "`n11 [ Adding new directories $UserDesktopPath\$ParentFolder\Import-Log-Folder ]`n"
    $StatusFExportComplete = "`n12 [ Exported raw logs to $UserDesktopPath\$ParentFolder\$Hostname-Evtx-Logs ]`n"
    #$DeepBlueExecute = ".\DeepBlue.ps1"
    #$LogPathExportFolder = "$UserDesktopPath\$ParentFolder\$Hostname-Evtx-Logs"
    #$LogPathImportFolder = "$UserDesktopPath\$ParentFolder\Import-Log-Folder"

    # AppFMenu
$AppFMenu = @"
`n
         _______[ AUTORUNS MENU ]________
        |                                |
        |    [Wipe] | Wipe Autoruns      |
        |    [Exit] | Exit Hard          |
        |    [Back] | Back to Main Menu  |
        |________________________________|`n `n
"@

function StartAutoruns($Source){   
    #Clear
    clear

    # Make space for download status bar
    Write-Host $StatusLoadingLineBreak

    # Notify Autoruns Source URL and hash based on request
     if ($Source -eq "MAIN SOURCE"){
        Write-Host "[MAIN SOURCE]: " -ForegroundColor Green -NoNewline; Write-Host $AppFURLMain -ForegroundColor Yellow
        Write-Host "    [SHA-256]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppFHashMain}" -ForegroundColor Yellow `n 
    }
    if ($Source -eq "MIRROR SOURCE"){
        Write-Host "[MIRROR SOURCE]: " -ForegroundColor Green -NoNewline; Write-Host $AppFURLMirror -ForegroundColor Yellow
        Write-Host "      [SHA-256]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppFHashMirror}" -ForegroundColor Yellow `n
    }

    # Create the in ParentFolder (Also hiding the Powershell Output)
    $null = new-item -path "$UserDesktopPath" -name $ParentFolder -itemtype directory -Force
    Write-Host $StatusCreatedParentFolder -ForegroundColor Green

    # Change the directory to ParentFolder
    set-location "$UserDesktopPath\$ParentFolder"
    Write-Host $StatusChangedDirToParentFolder -ForegroundColor Green

    # Check existing Autoruns folder, if exist, we delete for a fresh start.
    if (Test-Path .\$AppFName) {
        Write-Host $StatusFDetectedExisting -ForegroundColor Green
        $null = taskkill /F /IM Autoruns.exe /T 
        Start-Sleep -Seconds 2
        Remove-Item .\$AppFName -Recurse
        Write-Host $StatusFRemoveExisting -ForegroundColor Green
    }

    # Create new Autoruns Folder, change dir to Autoruns folder
    $null = New-Item -Path .\ -Name "$AppFName" -ItemType "directory" -Force
    Write-Host $StatusFCreatedAppFFolder -ForegroundColor Green
    set-location "$UserDesktopPath\$ParentFolder\$AppFName"
    Write-Host $StatusFChangedDirToAppFFolder -ForegroundColor Green        

    # Check for Download request
    if ($Source -eq "MAIN SOURCE"){
        $global:AppFURLUsed = $AppFURLMain
        $AppFHashUsed = $AppFHashMain
    }
    if ($Source -eq "MIRROR SOURCE"){
        $global:AppFURLUsed = $AppFURLMirror
        $AppFHashUsed = $AppFHashMirror
    }

    # Download zip file from Repo
    Write-Host $StatusFDownloadApp -ForegroundColor Green
    Clear-Variable -Name "Source" -Scope Global
    Invoke-WebRequest -Uri $AppFURLUsed -OutFile .\$AppFName.exe

    # Download Autoruns
    Write-Host $StatusFHashCheck -ForegroundColor Green
    $HashDownload = Get-FileHash .\$AppFName.exe | Select-Object -ExpandProperty Hash
   

        # Hash Diff Allow/Deny Progression    
        if ($AppFHashUsed -eq $HashDownload){
            $AppFHashValid = "True"
            Write-Host "  [EXPECTED]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppFHashUsed}" -ForegroundColor Green
            Write-Host "[DOWNLOADED]: " -ForegroundColor Green -NoNewline; Write-Host "{$HashDownload}" -ForegroundColor Green
            Write-Host "              |------------------------ [ HASH VALID ] ------------------------|`n" -ForegroundColor Yellow
        }
        else {
            $AppFHashValid = "False"
            Write-Host "  [EXPECTED]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppFHashUsed}" -ForegroundColor Green
            Write-Host "[DOWNLOADED]: " -ForegroundColor Green -NoNewline; Write-Host "{$HashDownload}" -ForegroundColor Red
            Write-Host "              |---------------------- [ HASH INVALID ] ----------------------|`n" -ForegroundColor Red
            Write-Host "Hash INVALID, URL possibly hijacked or updated. Removed $AppFName.exe, use MIRROR SOURCE for saftey." -ForegroundColor Red
            set-location "$UserDesktopPath\$ParentFolder"
            Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppFFolder"
            Read-Host "Press any key to return to the main menu"
        }

        if ($AppFHashValid -eq "True"){
        # Change the directory to AppFName
        set-location "$UserDesktopPath\$ParentFolder\$AppFFolder"
        $HealthCheck = "True"
        Write-Host $StatusFBootUp -ForegroundColor Green
        Invoke-Expression .\$AppFName.exe
        Write-Host $StatusFReady -ForegroundColor Cyan
        AppFMenuMain
        }

        if ($AppFHashValid -eq "False"){
        # Exit back to main menu
        Show-Menu
        }
}

#AppF Autoruns main menu
function AppFMenuMain{      
    do
    {  
        $selectionAppF = Read-Host $BannerF $AppFmenu "$AppFName main menu, waiting for your input"
        switch ($selectionAppF)
        {
            'Wipe' {
                AppFWipe
                Show-Menu
            }
            'Exit' {
                ExitHard
            }
            'Back' {
                clear
                Show-Menu
            }
            '' {
            clear
            AppFMenuMain
            }
        }
    }
    until ($selectionAppF -eq 'Wipe'-or $selectionAppF -eq 'Back' -or $selectionAppF -eq '')
}
        
# Wipe AutoRuns (Different format due to exe)
function AppFWipe {
    do
    {
    # Confirm user, then implement
    $selectionAppFWipe = Read-Host "Are you sure you want to close & wipe $AppFName (Y/N)"
    switch ($selectionAppFWipe)
    {
        'Y' {
            if (Test-Path "$UserDesktopPath\$ParentFolder\$AppFFolder") {
                Write-Host $StatusFWipe`n
                Write-Host $StatusWipeReminder -ForegroundColor DarkMagenta -Background Yellow
                set-location "$UserDesktopPath\$ParentFolder"
                $null = taskkill /F /IM Autoruns.exe /T
                Start-Sleep -Seconds 2
                Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppFFolder"
                }
        } 
        'N' {
            clear
            AppFMenuMain
        }
        '' {
            AppFWipe
        }
    }
 }
until ($selectionAppFWipe -eq 'Y' -or $selectionAppFWipe -eq 'N' -or $selectionAppFWipe -eq '')
}
 

# VARIABLES - AppG (ProcMon) -----------------------------------------------------------------------------------------------------------------------------------------------------
$BannerG = @"
_________________________________________________________________________________
                 ____  ____  ____  ______   __  _______  _   __
                / __ \/ __ \/ __ \/ ____/  /  |/  / __ \/ | / /
               / /_/ / /_/ / / / / /      / /|_/ / / / /  |/ / 
              / ____/ _, _/ /_/ / /___   / /  / / /_/ / /|  /  
             /_/   /_/ |_|\____/\____/  /_/  /_/\____/_/ |_/
_________________________________________________________________________________`n
"@                     
$AppGName = "PROCMON"
$AppGDescription = "Real-time File System, Registry, & Process/Thread Activity v4.01"

$AppGFolder = "Procmon"
        # URLs
        $AppGURLMain = "https://live.sysinternals.com/Procmon.exe"
        $AppGURLMirror = "https://github.com/resv/THC-MIRROR-APPS/raw/main/Procmon/Procmon.exe"
           
    $AppGHashMain = "3B7EA4318C3C1508701102CF966F650E04F28D29938F85D74EC0EC2528657B6E"
    $AppGHashMirror = "3B7EA4318C3C1508701102CF966F650E04F28D29938F85D74EC0EC2528657B6E"

    # VARIABLES G - Status notifications
    $StatusGDetectedExisting = ">>> [ Detected existing $AppGName files in $UserDesktopPath\$ParentFolder\$AppGFolder ]`n"
    $StatusGRemoveExisting = ">>> [ Removed existing $AppGName files in $UserDesktopPath\$ParentFolder\$AppGFolder ]`n"
    $StatusGCreatedAppFFolder = ">>>> [ Adding new directory $UserDesktopPath\$ParentFolder\$AppGFolder ]`n"
    $StatusGChangedDirToAppFFolder = ">>>>> [ Changed working directory to $UserDesktopPath\$ParentFolder\$AppGFolder ]`n"
    $StatusGDownloadApp = ">>>>>> [ Downloading `"$AppGName.exe`" ]`n"
    $StatusGHashCheck = ">>>>>>> [ Checking hash ]`n"
    $StatusGBootUp = ">>>>>>>> [ Booting up `"$AppGName`" ]`n"
    $StatusGReady = ">>>>>>>>> [ $AppGName is Ready for Hunting... ]`n"
    $StatusGWipe = ">>>>>>>>>> [ Wiping $AppGName ]"

# AppGMenu
$AppGMenu = @"
`n
         ________[ Procmon MENU ]________
        |                                |
        |    [Wipe] | Wipe Procmon     |
        |    [Exit] | Exit Hard          |
        |    [Back] | Back to Main Menu  |
        |________________________________|`n `n
"@

function StartProcmon($Source){   
    #Clear
    clear

    # Make space for download status bar
    Write-Host $StatusLoadingLineBreak

    # Notify Procmon Source URL and hash based on request
     if ($Source -eq "MAIN SOURCE"){
        Write-Host "[MAIN SOURCE]: " -ForegroundColor Green -NoNewline; Write-Host $AppGURLMain -ForegroundColor Yellow
        Write-Host "    [SHA-256]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppGHashMain}" -ForegroundColor Yellow `n 
    }
    if ($Source -eq "MIRROR SOURCE"){
        Write-Host "[MIRROR SOURCE]: " -ForegroundColor Green -NoNewline; Write-Host $AppGURLMirror -ForegroundColor Yellow
        Write-Host "      [SHA-256]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppGHashMirror}" -ForegroundColor Yellow `n
    }

    # Create the in ParentFolder (Also hiding the Powershell Output)
    $null = new-item -path "$UserDesktopPath" -name $ParentFolder -itemtype directory -Force
    Write-Host $StatusCreatedParentFolder -ForegroundColor Green

    # Change the directory to ParentFolder
    set-location "$UserDesktopPath\$ParentFolder"
    Write-Host $StatusChangedDirToParentFolder -ForegroundColor Green

    # Check existing Procmon folder, if exist, we delete for a fresh start.
    if (Test-Path .\$AppGName) {
        Write-Host $StatusGDetectedExisting -ForegroundColor Green
        $null = taskkill /F /IM Procmon.exe /T
        Start-Sleep -Seconds 2
        Remove-Item .\$AppGName -Recurse
        Write-Host $StatusGRemoveExisting -ForegroundColor Green
    }

    # Create new Procmon Folder, change dir to Procmon folder
    $null = New-Item -Path .\ -Name "$AppGName" -ItemType "directory" -Force
    Write-Host $StatusGCreatedAppFFolder -ForegroundColor Green
    set-location "$UserDesktopPath\$ParentFolder\$AppGName"
    Write-Host $StatusFChangedDirToAppGFolder -ForegroundColor Green        

    # Check for Download request
    if ($Source -eq "MAIN SOURCE"){
        $global:AppGURLUsed = $AppGURLMain
        $AppGHashUsed = $AppGHashMain
    }
    if ($Source -eq "MIRROR SOURCE"){
        $global:AppGURLUsed = $AppGURLMirror
        $AppGHashUsed = $AppGHashMirror
    }

    # Download zip file from Repo
    Write-Host $StatusGDownloadApp -ForegroundColor Green
    Clear-Variable -Name "Source" -Scope Global
    Invoke-WebRequest -Uri $AppGURLUsed -OutFile .\$AppGName.exe

    # Download Procmon
    Write-Host $StatusGHashCheck -ForegroundColor Green
    $HashDownload = Get-FileHash .\$AppGName.exe | Select-Object -ExpandProperty Hash
   

        # Hash Diff Allow/Deny Progression    
        if ($AppGHashUsed -eq $HashDownload){
            $AppGHashValid = "True"
            Write-Host "  [EXPECTED]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppGHashUsed}" -ForegroundColor Green
            Write-Host "[DOWNLOADED]: " -ForegroundColor Green -NoNewline; Write-Host "{$HashDownload}" -ForegroundColor Green
            Write-Host "              |------------------------ [ HASH VALID ] ------------------------|`n" -ForegroundColor Yellow
        }
        else {
            $AppFHashValid = "False"
            Write-Host "  [EXPECTED]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppGHashUsed}" -ForegroundColor Green
            Write-Host "[DOWNLOADED]: " -ForegroundColor Green -NoNewline; Write-Host "{$HashDownload}" -ForegroundColor Red
            Write-Host "              |---------------------- [ HASH INVALID ] ----------------------|`n" -ForegroundColor Red
            Write-Host "Hash INVALID, URL possibly hijacked or updated. Removed $AppGName.exe, use MIRROR SOURCE for saftey." -ForegroundColor Red
            set-location "$UserDesktopPath\$ParentFolder"
            Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppGFolder"
            Read-Host "Press any key to return to the main menu"
        }

        if ($AppGHashValid -eq "True"){
        # Change the directory to AppGName
        set-location "$UserDesktopPath\$ParentFolder\$AppGFolder"
        $HealthCheck = "True"
        Write-Host $StatusGBootUp -ForegroundColor Green
        Invoke-Expression .\$AppGName.exe
        Write-Host $StatusGReady -ForegroundColor Cyan
        AppGMenuMain
        }

        if ($AppGHashValid -eq "False"){
        # Exit back to main menu
        Show-Menu
        }
}

#AppG Procmon main menu
function AppGMenuMain{      
    do
    {  
        $selectionAppG = Read-Host $BannerG $AppGmenu "$AppGName main menu, waiting for your input"
        switch ($selectionAppG)
        {
            'Wipe' {
                AppGWipe
                Show-Menu
            }
            'Exit' {
                ExitHard
            }
            'Back' {
                clear
                Show-Menu
            }
            '' {
            clear
            AppGMenuMain
            }
        }
    }
    until ($selectionAppG -eq 'Wipe'-or $selectionAppG -eq 'Back' -or $selectionAppG -eq '')
}
        
# Wipe Procmon (Different format due to exe)
function AppGWipe {
    do
    {
    # Confirm user, then implement
    $selectionAppGWipe = Read-Host "Are you sure you want to close & wipe $AppGName (Y/N)"
    switch ($selectionAppGWipe)
    {
        'Y' {
            if (Test-Path "$UserDesktopPath\$ParentFolder\$AppGFolder") {
                Write-Host $StatusHWipe`n
                Write-Host $StatusWipeReminder -ForegroundColor DarkMagenta -Background Yellow
                set-location "$UserDesktopPath\$ParentFolder"
                $null = taskkill /F /IM Procmon.exe /T  
                Start-Sleep -Seconds 2
                Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppGFolder"
                }
        } 
        'N' {
            clear
            AppGMenuMain
        }
        '' {
            AppGWipe
        }
    }
 }
until ($selectionAppGWipe -eq 'Y' -or $selectionAppGWipe -eq 'N' -or $selectionAppGWipe -eq '')
}                         

# VARIABLES - AppH (ProcExp) -----------------------------------------------------------------------------------------------------------------------------------------------------
$BannerH = @"
_________________________________________________________________________________
                   ____  ____  ____  ______   _______  __ ____ 
                  / __ \/ __ \/ __ \/ ____/  / ____/ |/ // __ \
                 / /_/ / /_/ / / / / /      / __/  |   // /_/ /
                / ____/ _, _/ /_/ / /___   / /___ /   |/ ____/ 
               /_/   /_/ |_|\____/\____/  /_____//_/|_/_/
_________________________________________________________________________________`n
"@                     
$AppHName = "PROCEXP"
$AppHDescription = "DLLs Processes v17.06"

$AppHFolder = "ProcExp"
        # URLs
        $AppHURLMain = "https://download.sysinternals.com/files/ProcessExplorer.zip"
        $AppHURLMirror = "https://github.com/resv/THC-MIRROR-APPS/raw/main/ProcExp/ProcessExplorer.zip"
           
    $AppHHashMain = "54336CD4F4608903B1F89A43CA88F65C2F209F4512A5201CEBD2B38DDC855F24"
    $AppHHashMirror = "54336CD4F4608903B1F89A43CA88F65C2F209F4512A5201CEBD2B38DDC855F24"

        # VARIABLES H - Status notifications
    $StatusHCreatedAppHFolder = "> [ Adding directory $UserDesktopPath\$ParentFolder\$AppHFolder ]`n"
    $StatusHDetectedExisting = ">>> [ Detected existing $AppHName files in $UserDesktopPath\$ParentFolder\$AppHFolder ]`n"
    $StatusHRemoveExisting = ">>> [ Removed existing $AppHName files in $UserDesktopPath\$ParentFolder\$AppHFolder ]`n"
    $StatusHChangedDirToAppHFolder = ">> [ Changed directory to $UserDesktopPath\$ParentFolder\$AppHFolder ]`n"
    $StatusHCheckAndRemoveExisting = ">>> [ Removing any existing $AppHName files ]`n"
    $StatusHDownloadApp = ">>>> [ Downloading `"$AppHName.zip`" ]`n"
    $StatusHHashCheck = ">>>>> [ Checking hash ]`n"
    $StatusHExtractedApp = ">>>>>> [ Extracted `"$AppHName`" ]`n"
    $StatusHRemoveDownload =  ">>>>>>> [ Removed downloaded files for `"$AppHName`" ]`n"
    $StatusHChangedDirToAppFolder = ">>>>>>>> [ You are in the $UserDesktopPath\$ParentFolder\$AppHFolder ]`n"
    $StatusHBootUp = ">>>>>>>>> Booting up `"$AppHName`"`n" 
    $StatusHReady = ">>>>>>>>> [ $AppHName is Ready for Hunting... ]`n"
    $StatusHWipe = ">>>>>>>>>> [ Wiping $AppHName ]"

    # AppHMenuMain
    $AppHMenu = @"
`n
         ________[ ProcExp MENU ]________
        |                                |
        |    [Wipe] | Wipe ProcExp       |
        |    [Exit] | Exit Hard          |
        |    [Back] | Back to Main Menu  |
        |________________________________|`n `n
"@

function StartProcExp($Source) {   
    #Clear
    clear

    # Make space for download status bar
    Write-Host $StatusLoadingLineBreak

    # Notify ProcExp Source URL and hash based on request
    if ($Source -eq "MAIN SOURCE"){
        Write-Host "[MAIN SOURCE]: " -ForegroundColor Green -NoNewline; Write-Host $AppHURLMain -ForegroundColor Yellow
        Write-Host "    [SHA-256]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppHHashMain}" -ForegroundColor Yellow `n 
    }
    if ($Source -eq "MIRROR SOURCE"){
        Write-Host "[MIRROR SOURCE]: " -ForegroundColor Green -NoNewline; Write-Host $AppHURLMirror -ForegroundColor Yellow
        Write-Host "      [SHA-256]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppHHashMirror}" -ForegroundColor Yellow `n
    }

    # Create ParentFolder (Also hiding the Powershell Output)
    $null = new-item -path "$UserDesktopPath" -name $ParentFolder -itemtype directory -Force

    # Change the directory to ParentFolder
    set-location "$UserDesktopPath\$ParentFolder"

    # Check existing ProcExp folder, if exist, we delete for a fresh start.
    if (Test-Path .\$AppHName) {
        Write-Host $StatusHDetectedExisting -ForegroundColor Green
        $null = taskkill /F /IM ProcExp64.exe /T
        Start-Sleep -Seconds 2
        Remove-Item .\$AppHName -Recurse -Force
        Write-Host $StatusHRemoveExisting -ForegroundColor Green
    }

    # Create new ProcExp Folder, change dir to ProcExp folder
    $null = New-Item -Path .\ -Name "$AppHName" -ItemType "directory" -Force
    Write-Host $StatusHCreatedAppHFolder -ForegroundColor Green
    set-location "$UserDesktopPath\$ParentFolder\$AppHName"
    Write-Host $StatusHChangedDirToAppHFolder -ForegroundColor Green        

    # Check for Download request
    if ($Source -eq "MAIN SOURCE"){
        $global:AppHURLUsed = $AppHURLMain
        $AppHHashUsed = $AppHHashMain
    }
    if ($Source -eq "MIRROR SOURCE"){
        $global:AppHURLUsed = $AppHURLMirror
        $AppHHashUsed = $AppHHashMirror
    }

    # Download zip file from Repo
    Write-Host $StatusHDownloadApp -ForegroundColor Green
    Clear-Variable -Name "Source" -Scope Global
    Invoke-WebRequest -Uri $AppHURLUsed -OutFile .\$AppHName.zip

    # Download ProcExp
    Write-Host $StatusHHashCheck -ForegroundColor Green
    $HashDownload = Get-FileHash .\$AppHName.zip | Select-Object -ExpandProperty Hash
 

        # Hash Diff Allow/Deny Progression    
        if ($AppHHashUsed -eq $HashDownload){
            $AppHHashValid = "True"
            Write-Host "  [EXPECTED]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppHHashUsed}" -ForegroundColor Green
            Write-Host "[DOWNLOADED]: " -ForegroundColor Green -NoNewline; Write-Host "{$HashDownload}" -ForegroundColor Green
            Write-Host "              |------------------------ [ HASH VALID ] ------------------------|`n" -ForegroundColor Yellow
            
        }
        else {
            $AppHHashValid = "False"
            Write-Host "  [EXPECTED]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppHHashUsed}" -ForegroundColor Green
            Write-Host "[DOWNLOADED]: " -ForegroundColor Green -NoNewline; Write-Host "{$HashDownload}" -ForegroundColor Red
            Write-Host "              |----------------------- [ HASH INVALID ] -----------------------|`n" -ForegroundColor Red
            Write-Host "Hash INVALID, URL possibly hijacked or updated. Removed $AppHName.zip, Use MIRROR SOURCE for saftey." -ForegroundColor Red
            set-location "$UserDesktopPath\$ParentFolder"
            Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppHName.zip"
            Read-Host "Press any key to return to the main menu"
        }

        if ($AppHHashValid -eq "True"){
        # Extract, rename, delete downloaded zip file
        Write-Host $StatusHExtractedApp -ForegroundColor Green
        Expand-Archive .\$AppHName.zip .\ -Force
        Write-Host $StatusHRemoveDownload -ForegroundColor Green
        Remove-Item .\$AppHName.zip
        set-location "$UserDesktopPath\$ParentFolder\$AppHFolder"
        Remove-Item .\ProcExp.exe
        Remove-Item .\ProcExp64a.exe
        Remove-Item .\Eula.txt
        Write-Host $StatusHBootUp -ForegroundColor Green
        Invoke-Expression ./ProcExp64.exe
        Write-Host $StatusHReady -ForegroundColor Cyan
        AppHMenuMain
        }

        if ($AppHHashValid -eq "False"){
        # Exit back to main menu
        Show-Menu
        }
}

#AppH ProcExp main menu
function AppHMenuMain{      
    do
    {  
        $selectionAppH = Read-Host $BannerH $AppHMenu "$AppHName main menu, waiting for your input"
        switch ($selectionAppH)
        {
            'Wipe' {
                AppHWipe
                Show-Menu
            }
            'Exit' {
                ExitHard
            }
            'Back' {
                clear
                Show-Menu
            }
            '' {
            clear
            AppHMenuMain
            }
        }
    }
    until ($selectionAppH -eq 'Wipe'-or $selectionAppH -eq 'Back' -or $selectionAppH -eq '')
}

# Wipe ProcExp (Different format due to exe)
function AppHWipe {
    do
    {
    # Confirm user, then implement
    $selectionAppHWipe = Read-Host "Are you sure you want to close & wipe $AppHName (Y/N)"
    switch ($selectionAppHWipe)
    {
        'Y' {
            if (Test-Path "$UserDesktopPath\$ParentFolder\$AppHFolder") {
                Write-Host $StatusHWipe`n
                Write-Host $StatusHipeReminder -ForegroundColor DarkMagenta -Background Yellow
                set-location "$UserDesktopPath\$ParentFolder"
                $null = taskkill /F /IM ProcExp64.exe /T  
                Start-Sleep -Seconds 2
                Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppHFolder"
                }
        } 
        'N' {
            clear
            AppHMenuMain
        }
        '' {
            AppHWipe
        }
    }
 }
until ($selectionAppHWipe -eq 'Y' -or $selectionAppHWipe -eq 'N' -or $selectionAppHWipe -eq '')
}                 

# VARIABLES - AppI (TCPView) -----------------------------------------------------------------------------------------------------------------------------------------------------
$BannerI = @"
_________________________________________________________________________________
                  ________________     _    _____________       __
                 /_  __/ ____/ __ \   | |  / /  _/ ____/ |     / /
                  / / / /   / /_/ /   | | / // // __/  | | /| / / 
                 / / / /___/ ____/    | |/ // // /___  | |/ |/ /  
                /_/  \____/_/         |___/___/_____/  |__/|__/   
_________________________________________________________________________________`n
"@                     
$AppIName = "TCPVIEW"
$AppIDescription = "List All TCP and UDP Connections v4.19"

$AppIFolder = "TCPView"
        # URLs
        $AppIURLMain = "https://download.sysinternals.com/files/TCPView.zip"
        $AppIURLMirror = "https://github.com/resv/THC-MIRROR-APPS/raw/main/TCPView/TCPView.zip"
           
    $AppIHashMain = "4FC5CEBA3E1B27AD95A24DF35D094B454EC5F9478E12A8CA2B1B222705B9683B"
    $AppIHashMirror = "4FC5CEBA3E1B27AD95A24DF35D094B454EC5F9478E12A8CA2B1B222705B9683B"

        # VARIABLES I - Status notifications
    $StatusICreatedAppIFolder = "> [ Adding directory $UserDesktopPath\$ParentFolder\$AppIFolder ]`n"
    $StatusIDetectedExisting = ">>> [ Detected existing $AppIName files in $UserDesktopPath\$ParentFolder\$AppIFolder ]`n"
    $StatusIRemoveExisting = ">>> [ Removed existing $AppIName files in $UserDesktopPath\$ParentFolder\$AppIFolder ]`n"
    $StatusIChangedDirToAppIFolder = ">> [ Changed directory to $UserDesktopPath\$ParentFolder\$AppIFolder ]`n"
    $StatusICheckAndRemoveExisting = ">>> [ Removing any existing $AppIName files ]`n"
    $StatusIDownloadApp = ">>>> [ Downloading `"$AppIName.zip`" ]`n"
    $StatusIHashCheck = ">>>>> [ Checking hash ]`n"
    $StatusIExtractedApp = ">>>>>> [ Extracted `"$AppIName`" ]`n"
    $StatusIRemoveDownload =  ">>>>>>> [ Removed downloaded files for `"$AppIName`" ]`n"
    $StatusIChangedDirToAppFolder = ">>>>>>>> [ You are in the $UserDesktopPath\$ParentFolder\$AppIFolder ]`n"
    $StatusIBootUp = ">>>>>>>>> Booting up `"$AppIName`"`n" 
    $StatusIReady = ">>>>>>>>> [ $AppIName is Ready for Hunting... ]`n"
    $StatusIWipe = ">>>>>>>>>> [ Wiping $AppIName ]"

    # AppIMenuMain
    $AppIMenu = @"
`n
         ________[ TCPVIEW MENU ]________
        |                                |
        |    [Wipe] | Wipe TCPVIEW       |
        |    [Exit] | Exit Hard          |
        |    [Back] | Back to Main Menu  |
        |________________________________|`n `n
"@

function StartTCPView($Source) {   
    #Clear
    clear

    # Make space for download status bar
    Write-Host $StatusLoadingLineBreak

    # Notify TCPVIEW Source URL and hash based on request
    if ($Source -eq "MAIN SOURCE"){
        Write-Host "[MAIN SOURCE]: " -ForegroundColor Green -NoNewline; Write-Host $AppIURLMain -ForegroundColor Yellow
        Write-Host "    [SHA-256]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppIHashMain}" -ForegroundColor Yellow `n 
    }
    if ($Source -eq "MIRROR SOURCE"){
        Write-Host "[MIRROR SOURCE]: " -ForegroundColor Green -NoNewline; Write-Host $AppIURLMirror -ForegroundColor Yellow
        Write-Host "      [SHA-256]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppIHashMirror}" -ForegroundColor Yellow `n
    }

    # Create ParentFolder (Also hiding the Powershell Output)
    $null = new-item -path "$UserDesktopPath" -name $ParentFolder -itemtype directory -Force

    # Change the directory to ParentFolder
    set-location "$UserDesktopPath\$ParentFolder"

    # Check existing TCPVIEW folder, if exist, we delete for a fresh start.
    if (Test-Path .\$AppIName) {
        Write-Host $StatusIDetectedExisting -ForegroundColor Green
        $null = taskkill /F /IM TCPVIEW64.exe /T
        Start-Sleep -Seconds 2
        Remove-Item .\$AppIName -Recurse -Force
        Write-Host $StatusIRemoveExisting -ForegroundColor Green
    }

    # Create new TCPVIEW Folder, change dir to TCPVIEW folder
    $null = New-Item -Path .\ -Name "$AppIName" -ItemType "directory" -Force
    Write-Host $StatusICreatedAppIFolder -ForegroundColor Green
    set-location "$UserDesktopPath\$ParentFolder\$AppIName"
    Write-Host $StatusIChangedDirToAppIFolder -ForegroundColor Green        

    # Check for Download request
    if ($Source -eq "MAIN SOURCE"){
        $global:AppIURLUsed = $AppIURLMain
        $AppIHashUsed = $AppIHashMain
    }
    if ($Source -eq "MIRROR SOURCE"){
        $global:AppIURLUsed = $AppIURLMirror
        $AppIHashUsed = $AppIHashMirror
    }

    # Download zip file from Repo
    Write-Host $StatusIDownloadApp -ForegroundColor Green
    Clear-Variable -Name "Source" -Scope Global
    Invoke-WebRequest -Uri $AppIURLUsed -OutFile .\$AppIName.zip

    # Download TCPVIEW
    Write-Host $StatusIHashCheck -ForegroundColor Green
    $HashDownload = Get-FileHash .\$AppIName.zip | Select-Object -ExpandProperty Hash
 

        # Hash Diff Allow/Deny Progression    
        if ($AppIHashUsed -eq $HashDownload){
            $AppIHashValid = "True"
            Write-Host "  [EXPECTED]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppIHashUsed}" -ForegroundColor Green
            Write-Host "[DOWNLOADED]: " -ForegroundColor Green -NoNewline; Write-Host "{$HashDownload}" -ForegroundColor Green
            Write-Host "              |------------------------ [ HASH VALID ] ------------------------|`n" -ForegroundColor Yellow
            
        }
        else {
            $AppIHashValid = "False"
            Write-Host "  [EXPECTED]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppIHashUsed}" -ForegroundColor Green
            Write-Host "[DOWNLOADED]: " -ForegroundColor Green -NoNewline; Write-Host "{$HashDownload}" -ForegroundColor Red
            Write-Host "              |----------------------- [ HASH INVALID ] -----------------------|`n" -ForegroundColor Red
            Write-Host "Hash INVALID, URL possibly hijacked or updated. Removed $AppIName.zip, Use MIRROR SOURCE for saftey." -ForegroundColor Red
            set-location "$UserDesktopPath\$ParentFolder"
            Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppIName.zip"
            Read-Host "Press any key to return to the main menu"
        }

        if ($AppIHashValid -eq "True"){
        # Extract, rename, delete downloaded zip file
        Write-Host $StatusIExtractedApp -ForegroundColor Green
        Expand-Archive .\$AppIName.zip .\ -Force
        Write-Host $StatusIRemoveDownload -ForegroundColor Green
        Remove-Item .\$AppIName.zip
        set-location "$UserDesktopPath\$ParentFolder\$AppIFolder"
        Remove-Item .\Eula.txt
        Remove-Item .\tcpvcon.exe
        Remove-Item .\tcpvcon64.exe
        Remove-Item .\tcpvcon64a.exe
        Remove-Item .\tcpview.chm
        Remove-Item .\tcpview.exe
        Remove-Item .\tcpview64a.exe
        Write-Host $StatusIBootUp -ForegroundColor Green
        Invoke-Expression ./tcpview64.exe
        Write-Host $StatusIReady -ForegroundColor Cyan
        AppIMenuMain
        }

        if ($AppIHashValid -eq "False"){
        # Exit back to main menu
        Show-Menu
        }
}

#AppI TCPVIEW main menu
function AppIMenuMain{      
    do
    {  
        $selectionAppI = Read-Host $BannerI $AppIMenu "$AppIName main menu, waiting for your input"
        switch ($selectionAppI)
        {
            'Wipe' {
                AppIWipe
                Show-Menu
            }
            'Exit' {
                ExitHard
            }
            'Back' {
                clear
                Show-Menu
            }
            '' {
            clear
            AppIMenuMain
            }
        }
    }
    until ($selectionAppI -eq 'Wipe'-or $selectionAppI -eq 'Back' -or $selectionAppI -eq '')
}

# Wipe TCPVIEW (Different format due to exe)
function AppIWipe {
    do
    {
    # Confirm user, then implement
    $selectionAppIWipe = Read-Host "Are you sure you want to close & wipe $AppIName (Y/N)"
    switch ($selectionAppIWipe)
    {
        'Y' {
            if (Test-Path "$UserDesktopPath\$ParentFolder\$AppIFolder") {
                Write-Host $StatusIWipe`n
                Write-Host $StatusIipeReminder -ForegroundColor DarkMagenta -Background Yellow
                set-location "$UserDesktopPath\$ParentFolder"
                $null = taskkill /F /IM TCPVIEW64.exe /T  
                Start-Sleep -Seconds 2
                Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppIFolder"
                }
        } 
        'N' {
            clear
            AppIMenuMain
        }
        '' {
            AppIWipe
        }
    }
 }
until ($selectionAppIWipe -eq 'Y' -or $selectionAppIWipe -eq 'N' -or $selectionAppIWipe -eq '')
}                 

# VARIABLES - AppJ (AccessEnum) -----------------------------------------------------------------------------------------------------------------------------------------------------
$BannerJ = @"
_________________________________________________________________________________
            ___   ____________________________    _______   ____  ____  ___
           /   | / ____/ ____/ ____/ ___/ ___/   / ____/ | / / / / /  |/  /
          / /| |/ /   / /   / __/  \__ \\__ \   / __/ /  |/ / / / / /|_/ / 
         / ___ / /___/ /___/ /___ ___/ /__/ /  / /___/ /|  / /_/ / /  / /  
        /_/  |_\____/\____/_____//____/____/  /_____/_/ |_/\____/_/  /_/                                                                    
_________________________________________________________________________________`n
"@                     
$AppJName = "ACCESSENUM"
$AppJDescription = "View File System, Registry, Permissions Security Settings v1.35"

$AppJFolder = "AccessEnum"
        # URLs
        $AppJURLMain = "https://download.sysinternals.com/files/AccessEnum.zip"
        $AppJURLMirror = "https://github.com/resv/THC-MIRROR-APPS/raw/main/AccessEnum/AccessEnum.zip"
           
    $AppJHashMain = "FD7D370447E83F17C7C33668401E619BEF4E7D1EFF4818AED6D8A6B17E1DF208"
    $AppJHashMirror = "FD7D370447E83F17C7C33668401E619BEF4E7D1EFF4818AED6D8A6B17E1DF208"

        # VARIABLES J - Status notifications
    $StatusJCreatedAppJFolder = "> [ Adding directory $UserDesktopPath\$ParentFolder\$AppJFolder ]`n"
    $StatusJDetectedExisting = ">>> [ Detected existing $AppJName files in $UserDesktopPath\$ParentFolder\$AppJFolder ]`n"
    $StatusJRemoveExisting = ">>> [ Removed existing $AppJName files in $UserDesktopPath\$ParentFolder\$AppJFolder ]`n"
    $StatusJChangedDirToAppJFolder = ">> [ Changed directory to $UserDesktopPath\$ParentFolder\$AppJFolder ]`n"
    $StatusJCheckAndRemoveExisting = ">>> [ Removing any existing $AppJName files ]`n"
    $StatusJDownloadApp = ">>>> [ Downloading `"$AppJName.zip`" ]`n"
    $StatusJHashCheck = ">>>>> [ Checking hash ]`n"
    $StatusJExtractedApp = ">>>>>> [ Extracted `"$AppJName`" ]`n"
    $StatusJRemoveDownload =  ">>>>>>> [ Removed downloaded files for `"$AppJName`" ]`n"
    $StatusJChangedDirToAppFolder = ">>>>>>>> [ You are in the $UserDesktopPath\$ParentFolder\$AppJFolder ]`n"
    $StatusJBootUp = ">>>>>>>>> Booting up `"$AppJName`"`n" 
    $StatusJReady = ">>>>>>>>> [ $AppJName is Ready for Hunting... ]`n"
    $StatusJWipe = ">>>>>>>>>> [ Wiping $AppJName ]"

    # AppJMenuMain
    $AppJMenu = @"
`n
         ______[ AccessEnum MENU ]_______
        |                                |
        |    [Wipe] | Wipe AccessEnum    |
        |    [Exit] | Exit Hard          |
        |    [Back] | Back to Main Menu  |
        |________________________________|`n `n
"@

function StartAccessEnum($Source) {   
    #Clear
    clear

    # Make space for download status bar
    Write-Host $StatusLoadingLineBreak

    # Notify AccessEnum Source URL and hash based on request
    if ($Source -eq "MAIN SOURCE"){
        Write-Host "[MAIN SOURCE]: " -ForegroundColor Green -NoNewline; Write-Host $AppJURLMain -ForegroundColor Yellow
        Write-Host "    [SHA-256]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppJHashMain}" -ForegroundColor Yellow `n 
    }
    if ($Source -eq "MIRROR SOURCE"){
        Write-Host "[MIRROR SOURCE]: " -ForegroundColor Green -NoNewline; Write-Host $AppJURLMirror -ForegroundColor Yellow
        Write-Host "      [SHA-256]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppJHashMirror}" -ForegroundColor Yellow `n
    }

    # Create ParentFolder (Also hiding the Powershell Output)
    $null = new-item -path "$UserDesktopPath" -name $ParentFolder -itemtype directory -Force

    # Change the directory to ParentFolder
    set-location "$UserDesktopPath\$ParentFolder"

    # Check existing AccessEnum folder, if exist, we delete for a fresh start.
    if (Test-Path .\$AppJName) {
        Write-Host $StatusJDetectedExisting -ForegroundColor Green
        $null = taskkill /F /IM AccessEnum.exe /T
        Start-Sleep -Seconds 2
        Remove-Item .\$AppJName -Recurse -Force
        Write-Host $StatusJRemoveExisting -ForegroundColor Green
    }

    # Create new AccessEnum Folder, change dir to AccessEnum folder
    $null = New-Item -Path .\ -Name "$AppJName" -ItemType "directory" -Force
    Write-Host $StatusJCreatedAppJFolder -ForegroundColor Green
    set-location "$UserDesktopPath\$ParentFolder\$AppJName"
    Write-Host $StatusJChangedDirToAppJFolder -ForegroundColor Green        

    # Check for Download request
    if ($Source -eq "MAIN SOURCE"){
        $global:AppJURLUsed = $AppJURLMain
        $AppJHashUsed = $AppJHashMain
    }
    if ($Source -eq "MIRROR SOURCE"){
        $global:AppJURLUsed = $AppJURLMirror
        $AppJHashUsed = $AppJHashMirror
    }

    # Download zip file from Repo
    Write-Host $StatusJDownloadApp -ForegroundColor Green
    Clear-Variable -Name "Source" -Scope Global
    Invoke-WebRequest -Uri $AppJURLUsed -OutFile .\$AppJName.zip

    # Download AccessEnum
    Write-Host $StatusJHashCheck -ForegroundColor Green
    $HashDownload = Get-FileHash .\$AppJName.zip | Select-Object -ExpandProperty Hash
 

        # Hash Diff Allow/Deny Progression    
        if ($AppJHashUsed -eq $HashDownload){
            $AppJHashValid = "True"
            Write-Host "  [EXPECTED]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppJHashUsed}" -ForegroundColor Green
            Write-Host "[DOWNLOADED]: " -ForegroundColor Green -NoNewline; Write-Host "{$HashDownload}" -ForegroundColor Green
            Write-Host "              |------------------------ [ HASH VALID ] ------------------------|`n" -ForegroundColor Yellow
            
        }
        else {
            $AppJHashValid = "False"
            Write-Host "  [EXPECTED]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppJHashUsed}" -ForegroundColor Green
            Write-Host "[DOWNLOADED]: " -ForegroundColor Green -NoNewline; Write-Host "{$HashDownload}" -ForegroundColor Red
            Write-Host "              |----------------------- [ HASH INVALID ] -----------------------|`n" -ForegroundColor Red
            Write-Host "Hash INVALID, URL possibly hijacked or updated. Removed $AppJName.zip, Use MIRROR SOURCE for saftey." -ForegroundColor Red
            set-location "$UserDesktopPath\$ParentFolder"
            Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppJName.zip"
            Read-Host "Press any key to return to the main menu"
        }

        if ($AppJHashValid -eq "True"){
        # Extract, rename, delete downloaded zip file
        Write-Host $StatusJExtractedApp -ForegroundColor Green
        Expand-Archive .\$AppJName.zip .\ -Force
        Write-Host $StatusJRemoveDownload -ForegroundColor Green
        Remove-Item .\$AppJName.zip
        set-location "$UserDesktopPath\$ParentFolder\$AppJFolder"
        Remove-Item .\Eula.txt
        Write-Host $StatusJBootUp -ForegroundColor Green
        Invoke-Expression ./AccessEnum.exe
        Write-Host $StatusJReady -ForegroundColor Cyan
        AppJMenuMain
        }

        if ($AppJHashValid -eq "False"){
        # Exit back to main menu
        Show-Menu
        }
}

#AppJ AccessEnum main menu
function AppJMenuMain{      
    do
    {  
        $selectionAppJ = Read-Host $BannerJ $AppJMenu "$AppJName main menu, waiting for your input"
        switch ($selectionAppJ)
        {
            'Wipe' {
                AppJWipe
                Show-Menu
            }
            'Exit' {
                ExitHard
            }
            'Back' {
                clear
                Show-Menu
            }
            '' {
            clear
            AppJMenuMain
            }
        }
    }
    until ($selectionAppJ -eq 'Wipe'-or $selectionAppJ -eq 'Back' -or $selectionAppJ -eq '')
}

# Wipe AccessEnum (Different format due to exe)
function AppJWipe {
    do
    {
    # Confirm user, then implement
    $selectionAppJWipe = Read-Host "Are you sure you want to close & wipe $AppJName (Y/N)"
    switch ($selectionAppJWipe)
    {
        'Y' {
            if (Test-Path "$UserDesktopPath\$ParentFolder\$AppJFolder") {
                Write-Host $StatusJWipe`n
                Write-Host $StatusJipeReminder -ForegroundColor DarkMagenta -Background Yellow
                set-location "$UserDesktopPath\$ParentFolder"
                $null = taskkill /F /IM AccessEnum.exe /T  
                Start-Sleep -Seconds 2
                Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppJFolder"
                }
        } 
        'N' {
            clear
            AppJMenuMain
        }
        '' {
            AppJWipe
        }
    }
 }
until ($selectionAppJWipe -eq 'Y' -or $selectionAppJWipe -eq 'N' -or $selectionAppJWipe -eq '')
}

# VARIABLES W - AppW (WizTree)
$BannerW = @"
_________________________________________________________________________________
                 _       ___________  __________  ____________
                | |     / /  _/__  / /_  __/ __ \/ ____/ ____/
                | | /| / // /  / /    / / / /_/ / __/ / __/   
                | |/ |/ // /  / /_   / / / _, _/ /___/ /___   
                |__/|__/___/ /___/  /_/ /_/ |_/_____/_____/                                                                                                  
_________________________________________________________________________________`n
"@
    $AppWName = "WIZTREE"
    $AppWDescription = "Enumerate File Structure v4.19"
    $AppWFolder = "WizTree"
        # URLs
        $AppWURLMain = "https://diskanalyzer.com/files/wiztree_4_19_portable.zip"
        $AppWURLMirror = "https://github.com/resv/THC-MIRROR-APPS/raw/main/WizTree/wiztree_4_19_portable.zip"
           
    $AppWHashMain = "013917C5FB72E32FA1FCC4D1D6B57D130DA3E112DEF7ADE4429C8D23DC9B792B"
    $AppWHashMirror = "013917C5FB72E32FA1FCC4D1D6B57D130DA3E112DEF7ADE4429C8D23DC9B792B"

    # VARIABLES W - Status notifications
    $StatusWCreatedAppWFolder = "> [ Adding directory $UserDesktopPath\$ParentFolder\$AppWFolder ]`n"
    $StatusWDetectedExisting = ">>> [ Detected existing $AppWName files in $UserDesktopPath\$ParentFolder\$AppWFolder ]`n"
    $StatusWRemoveExisting = ">>> [ Removed existing $AppWName files in $UserDesktopPath\$ParentFolder\$AppWFolder ]`n"
    $StatusWChangedDirToAppWFolder = ">> [ Changed directory to $UserDesktopPath\$ParentFolder\$AppWFolder ]`n"
    $StatusWCheckAndRemoveExisting = ">>> [ Removing any existing $AppWName files ]`n"
    $StatusWDownloadApp = ">>>> [ Downloading `"$AppWName.zip`" ]`n"
    $StatusWHashCheck = ">>>>> [ Checking hash ]`n"
    $StatusWExtractedApp = ">>>>>> [ Extracted `"$AppWName`" ]`n"
    $StatusWRemoveDownload =  ">>>>>>> [ Removed downloaded files for `"$AppWName`" ]`n"
    $StatusWChangedDirToAppFolder = ">>>>>>>> [ You are in the $UserDesktopPath\$ParentFolder\$AppWFolder ]`n"
    $StatusWBootUp = ">>>>>>>>> Booting up `"$AppWName`"`n" 
    $StatusWReady = ">>>>>>>>> [ $AppWName is Ready for Hunting... ]`n"
    $StatusWWipe = ">>>>>>>>>> [ Wiping $AppWName ]"

    # AppWMenuMain
    $AppWMenu = @"
`n
         ________[ WIZTREE MENU ]________
        |                                |
        |    [Wipe] | Wipe WizTree       |
        |    [Exit] | Exit Hard          |
        |    [Back] | Back to Main Menu  |
        |________________________________|`n `n
"@

function StartWizTree($Source) {   
    #Clear
    clear

    # Make space for download status bar
    Write-Host $StatusLoadingLineBreak

    # Notify WizTree Source URL and hash based on request
    if ($Source -eq "MAIN SOURCE"){
        Write-Host "[MAIN SOURCE]: " -ForegroundColor Green -NoNewline; Write-Host $AppWURLMain -ForegroundColor Yellow
        Write-Host "    [SHA-256]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppWHashMain}" -ForegroundColor Yellow `n 
    }
    if ($Source -eq "MIRROR SOURCE"){
        Write-Host "[MIRROR SOURCE]: " -ForegroundColor Green -NoNewline; Write-Host $AppWURLMirror -ForegroundColor Yellow
        Write-Host "      [SHA-256]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppWHashMirror}" -ForegroundColor Yellow `n
    }

    # Create ParentFolder (Also hiding the Powershell Output)
    $null = new-item -path "$UserDesktopPath" -name $ParentFolder -itemtype directory -Force

    # Change the directory to ParentFolder
    set-location "$UserDesktopPath\$ParentFolder"

    # Check existing WizTree folder, if exist, we delete for a fresh start.
    if (Test-Path .\$AppWName) {
        Write-Host $StatusWDetectedExisting -ForegroundColor Green
        $null = taskkill /F /IM WizTree64.exe /T
        Start-Sleep -Seconds 5
        Remove-Item .\$AppWName -Recurse -Force
        Write-Host $StatusWRemoveExisting -ForegroundColor Green
    }

    # Create new WizTree Folder, change dir to WizTree folder
    $null = New-Item -Path .\ -Name "$AppWName" -ItemType "directory" -Force
    Write-Host $StatusWCreatedAppWFolder -ForegroundColor Green
    set-location "$UserDesktopPath\$ParentFolder\$AppWName"
    Write-Host $StatusWChangedDirToAppWFolder -ForegroundColor Green        

    # Check for Download request
    if ($Source -eq "MAIN SOURCE"){
        $global:AppWURLUsed = $AppWURLMain
        $AppWHashUsed = $AppWHashMain
    }
    if ($Source -eq "MIRROR SOURCE"){
        $global:AppWURLUsed = $AppWURLMirror
        $AppWHashUsed = $AppWHashMirror
    }

    # Download zip file from Repo
    Write-Host $StatusWDownloadApp -ForegroundColor Green
    Clear-Variable -Name "Source" -Scope Global
    Invoke-WebRequest -Uri $AppWURLUsed -OutFile .\$AppWName.zip

    # Download WizTree
    Write-Host $StatusWHashCheck -ForegroundColor Green
    $HashDownload = Get-FileHash .\$AppWName.zip | Select-Object -ExpandProperty Hash
 

        # Hash Diff Allow/Deny Progression    
        if ($AppWHashUsed -eq $HashDownload){
            $AppWHashValid = "True"
            Write-Host "  [EXPECTED]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppWHashUsed}" -ForegroundColor Green
            Write-Host "[DOWNLOADED]: " -ForegroundColor Green -NoNewline; Write-Host "{$HashDownload}" -ForegroundColor Green
            Write-Host "              |------------------------ [ HASH VALID ] ------------------------|`n" -ForegroundColor Yellow
            
        }
        else {
            $AppWHashValid = "False"
            Write-Host "  [EXPECTED]: " -ForegroundColor Green -NoNewline; Write-Host "{$AppWHashUsed}" -ForegroundColor Green
            Write-Host "[DOWNLOADED]: " -ForegroundColor Green -NoNewline; Write-Host "{$HashDownload}" -ForegroundColor Red
            Write-Host "              |----------------------- [ HASH INVALID ] -----------------------|`n" -ForegroundColor Red
            Write-Host "Hash INVALID, URL possibly hijacked or updated. Removed $AppWName.zip, Use MIRROR SOURCE for saftey." -ForegroundColor Red
            set-location "$UserDesktopPath\$ParentFolder"
            Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppWName.zip"
            Read-Host "Press any key to return to the main menu"
        }

        if ($AppWHashValid -eq "True"){
        # Extract, rename, delete downloaded zip file
        Write-Host $StatusWExtractedApp -ForegroundColor Green
        Expand-Archive .\$AppWName.zip .\ -Force
        Write-Host $StatusWRemoveDownload -ForegroundColor Green
        Remove-Item .\$AppWName.zip
        set-location "$UserDesktopPath\$ParentFolder\$AppWFolder"
        Remove-Item .\WizTree.exe
        Remove-Item .\locale -Recurse
        Remove-Item .\license.txt
        Write-Host $StatusWBootUp -ForegroundColor Green
        Invoke-Expression ./WizTree64.exe
        Write-Host $StatusWReady -ForegroundColor Cyan
        AppWMenuMain
        }

        if ($AppWHashValid -eq "False"){
        # Exit back to main menu
        Show-Menu
        }
}

#AppW WizTree main menu
function AppWMenuMain{      
    do
    {  
        $selectionAppW = Read-Host $BannerW $AppWMenu "$AppWName main menu, waiting for your input"
        switch ($selectionAppW)
        {
            'Wipe' {
                AppWWipe
                Show-Menu
            }
            'Exit' {
                ExitHard
            }
            'Back' {
                clear
                Show-Menu
            }
            '' {
            clear
            AppWMenuMain
            }
        }
    }
    until ($selectionAppW -eq 'Wipe'-or $selectionAppW -eq 'Back' -or $selectionAppW -eq '')
}

# Wipe WizTree (Different format due to exe)
function AppWWipe {
    do
    {
    # Confirm user, then implement
    $selectionAppWWipe = Read-Host "Are you sure you want to close & wipe $AppWName (Y/N)"
    switch ($selectionAppWWipe)
    {
        'Y' {
            if (Test-Path "$UserDesktopPath\$ParentFolder\$AppWFolder") {
                Write-Host $StatusWWipe`n
                Write-Host $StatusWipeReminder -ForegroundColor DarkMagenta -Background Yellow
                set-location "$UserDesktopPath\$ParentFolder"
                $null = taskkill /F /IM WizTree64.exe /T  
                Start-Sleep -Seconds 5
                Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppWFolder"
                }
        } 
        'N' {
            clear
            AppWMenuMain
        }
        '' {
            AppWWipe
        }
    }
 }
until ($selectionAppWWipe -eq 'Y' -or $selectionAppWWipe -eq 'N' -or $selectionAppWWipe -eq '')
}

# VARIABLES - AppX (More Info & Contact)
$BannerX = @"
_________________________________________________________________________________
                   __________  _   ___________   ____________
                  / ____/ __ \/ | / /_  __/   | / ____/_  __/
                 / /   / / / /  |/ / / / / /| |/ /     / /   
                / /___/ /_/ / /|  / / / / ___ / /___  / /    
                \____/\____/_/ |_/ /_/ /_/  |_\____/ /_/
_________________________________________________________________________________`n
"@
$AppXName = "CONTACT"
$AppXDescription = "Contact & More Information"
$AppXVersion = "v1.0"
$AppxReleaseDate = "8/5/24"
$AppXNotes = @"
All mirrors are direct copies from official sources and hosted on my github. 
Use a mirror if the main source is down or if they have updated their APP/URL`n
"@

$AppXConactInfo= @" 
     ___________________[ ADAM KIM ]_____________________
    |                                                    |
    | [Linkedin] https://www.linkedin.com/in/adamkim456/ |
    | [Discord]  https://discord.gg/HXNprdRD             |
    | [GitHub]   https://github.com/resv                 |
    | [Email]    adam@atomkim.com                        |
    |____________________________________________________|`n
"@

$AppXCreditsInfo= @" 
     ____________________[ CREDITS ]________________________
    |                                                       |
    | [Powershell] Microsoft Sysinternals                   |
    | [Sysmon] Microsoft Sysinternals                       |  
    | [DeepBlueCLI] Eric Conrad https://www.ericconrad.com/ |
    | [Autoruns] Microsoft Sysinternals                     |
    | [ProcMon] Microsoft Sysinternals                      |
    | [ProcExp] Microsoft Sysinternals                      |
    | [TCPView] Microsoft Sysinternals                      |
    | [WizTree] https://diskanalyzer.com/                   |
    |_______________________________________________________|`n
"@

function AppXShowContact {
    Write-Host $BannerX
    Write-Host $StatusBlankSpace [ $AppXVersion $AppXReleaseDate ] `n 
    Write-Host $AppXNotes -ForegroundColor Yellow
    Write-Host $AppXConactInfo -ForegroundColor Cyan
    Write-Host $AppXCreditsInfo -ForegroundColor DarkGray
}

# VARIABLES - AppY (Wipe THC from endpoint) ------------------------------------------------------------------------------------------------------------------------------------------------------------------
$AppYName = "WIPE THC & EXIT"
$AppYDescription = "Close & Wipe All Apps, Exit THC"
$StatusYWipe = ">>>>>>>>>> [ Wiping THC Folder ]"
$StatusYWipeComplete = ">>>>>>>>>> [ Success, THC.ps1 requires manual deletion ]"
$StatusYAppState = ""
$StatusYError = ">>>>>>>>>> [ Something went wrong with $StatusAppYState, something holding ownership? ]"

function WipeTHC {
    do
    {
    # Confirm Wipe with user
    $selectionWipeTHC = Read-Host "Are you sure you want wipe THC (Y/N)"
    switch ($selectionWipeTHC)
    {
        'Y' {
            # Closes AppB - If exists, we set state to AppB, if wipe is successful, we reset state and progress to next if.
            if (Test-Path "$UserDesktopPath\$ParentFolder\$AppBFolder") {
                $StatusYAppState = "$AppBName"
                Write-Host "`n$StatusBWipe"
                set-location "$UserDesktopPath\$ParentFolder"  
                Start-Sleep -Seconds 1
                Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppBFolder"
                $StatusYAppState = ""
            }
            # Closes AppC - If exists, we set state to AppC, if wipe is successful, we reset state and progress to next if.
            if (Test-Path "$UserDesktopPath\$ParentFolder\$AppCFolder") {
                $StatusYAppState = "$AppCName"
                Write-Host "`n$StatusCWipe"
                set-location "$UserDesktopPath\$ParentFolder"
                Start-Sleep -Seconds 2
                Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppCFolder"
                $StatusYAppState = ""
            }
            # Closes AppD - If exists, we set state to AppD, if wipe is successful, we reset state and progress to next if.
            if (Test-Path "$UserDesktopPath\$ParentFolder\$AppDFolder") {
                $StatusYAppState = "$AppDName"
                Write-Host "`n$StatusDWipe"
                set-location "$UserDesktopPath\$ParentFolder"
                Start-Sleep -Seconds 2
                Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppDFolder"
                $StatusYAppState = ""
            }
            # Closes AppF - If exists, we set state to AppF, if wipe is successful, we reset state and progress to next if.
            if (Test-Path "$UserDesktopPath\$ParentFolder\$AppFFolder") {
                $StatusYAppState = "$AppFName"
                Write-Host "`n$StatusFWipe"
                set-location "$UserDesktopPath\$ParentFolder"
                $null = taskkill /F /IM Autoruns.exe /T  
                Start-Sleep -Seconds 2
                Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppFFolder"
                $StatusYAppState = ""
            }
            # Closes AppG - If exists, we set state to AppG, if wipe is successful, we reset state and progress to next if.
            if (Test-Path "$UserDesktopPath\$ParentFolder\$AppGFolder") {
                $StatusYAppState = "$AppGName"
                Write-Host "`n$StatusGWipe"
                set-location "$UserDesktopPath\$ParentFolder"
                $null = taskkill /F /IM Procmon.exe /T  
                Start-Sleep -Seconds 2
                Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppGFolder"
                $StatusYAppState = ""
            }
            # Closes AppH - If exists, we set state to AppH, if wipe is successful, we reset state and progress to next if.
            if (Test-Path "$UserDesktopPath\$ParentFolder\$AppHFolder") {
                $StatusYAppState = "$AppHName"
                Write-Host "`n$StatusHWipe"
                set-location "$UserDesktopPath\$ParentFolder"
                $null = taskkill /F /IM ProcExp64.exe /T  
                Start-Sleep -Seconds 2
                Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppHFolder"
                $StatusYAppState = ""
            }
            # Closes AppI - If exists, we set state to AppI, if wipe is successful, we reset state and progress to next if.
            if (Test-Path "$UserDesktopPath\$ParentFolder\$AppIFolder") {
                $StatusYAppState = "$AppIName"
                Write-Host "`n$StatusIWipe"
                set-location "$UserDesktopPath\$ParentFolder"
                $null = taskkill /F /IM TCPVIEW64.exe /T  
                Start-Sleep -Seconds 2
                Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppIFolder"
                $StatusYAppState = ""
            }
            # Closes AppJ - If exists, we set state to AppJ, if wipe is successful, we reset state and progress to next if.
            if (Test-Path "$UserDesktopPath\$ParentFolder\$AppJFolder") {
                $StatusYAppState = "$AppJName"
                Write-Host "`n$StatusJWipe"
                set-location "$UserDesktopPath\$ParentFolder"
                $null = taskkill /F /IM AccessEnum.exe /T  
                Start-Sleep -Seconds 2
                Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppJFolder"
                $StatusYAppState = ""
            }
            # Closes AppW - If exists, we set state to AppW, if wipe is successful, we reset state and progress to next if.
            if (Test-Path "$UserDesktopPath\$ParentFolder\$AppWFolder") {
                $StatusYAppState = "$AppWName"
                Write-Host "`n$StatusWWipe"
                set-location "$UserDesktopPath\$ParentFolder"
                $null = taskkill /F /IM WizTree64.exe /T  
                Start-Sleep -Seconds 5
                Remove-Item -Recurse -Force "$UserDesktopPath\$ParentFolder\$AppWFolder"
                $StatusYAppState = ""
            }
            # Remove ParentFolder - If exists, we set state to ParentFolder, if wipe is successful, we reset state and progress to next if.
            if (Test-Path "$UserDesktopPath\$ParentFolder") {
                $StatusYAppState = "$ParentFolder"
                Write-Host "$StatusYWipe"
                set-location "$UserDesktopPath"
                Remove-Item "$UserDesktopPath\$ParentFolder" -Recurse -Force
                $StatusYAppState = ""
            }
            # Condition of state satisfied? - If state is blank, all wipes are successful, we can quit.
            if ($StatusYAppState -eq ""){
                Write-Host $StatusYWipeComplete
                [System.Environment]::Exit(0)
            }
            # Condition NOT satisfied to quit, display state of where error occurred.
            if ($StatusYAppState -ne ""){
                Write-Host $StatusYError
                pause
            }
        }
        'N' {
            Show-Menu
            return
        }
    }
 }
 until ($selection -eq 'N')
}

# VARIABLES - AppZ -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
$AppZName = "HARD EXIT"
$AppZDescription = "Exit THC and Close Shell"
$AppZExitingNotification = "`n`n >>>>>>>>>>>>> Exiting, don't forget to wipe :)`n`n"
$ExitHard = "[System.Environment]::Exit(0)"

function ExitHard{
    Write-Host $AppZExitingNotification -ForegroundColor Yellow
    [System.Environment]::Exit(0)
}

# MainMenu ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
$MenuMain = @" 
       [*] Double letter will use mirror if main source is down `n
 [ WORKING ]       $AppAName  [A] $AppADescription
 [ WORKING ]          $AppBName [*B] $AppBDescription 
 [ WORKING ]     $AppCName [*C] $AppCDescription 
 [ WORKING ]        $AppFName [*F] $AppFDescription
 [ WORKING ]         $AppGName [*G] $AppGDescription
 [ WORKING ]         $AppHName [*H] $AppHDescription
 [ WORKING ]         $AppIName [*I] $AppIDescription
 [ WORKING ]      $AppJName [*J] $AppJDescription        
 [ WORKING ]         $AppWName [*W] $AppWDescription  
 [ WORKING ]         $AppXName  [X] $AppXDescription
 [ WORKING ] $AppYName  [Y] $AppYDescription
 [ WORKING ]       $AppZName  [Z] $AppZDescription `n
"@


# Execution starts here:
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
function Show-Menu {
    Clear-Host
    Write-Host $Banner1of4 
    Write-Host $Banner2of4 -ForegroundColor Yellow
    Write-Host $Banner3of4 -ForegroundColor Cyan
    Write-Host $Banner4of4 
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
        $global:Source = "MAIN SOURCE"
        StartSysmon($Source)
        } 
        'BB' {
        $global:Source = "MIRROR SOURCE"
        StartSysmon($Source)
        }
        'C' {
        $global:Source = "MAIN SOURCE"
        StartDBCLI($Source)
        } 
        'CC' {
        $global:Source = "MIRROR SOURCE"
        StartDBCLI($Source)
        }
        'F' {
        $global:Source = "MAIN SOURCE"
        StartAutoruns($Source)
        }
        'FF'{
        $global:Source = "MIRROR SOURCE"
        StartAutoruns($Source)
        }
        'G' {
        $global:Source = "MAIN SOURCE"
        StartProcMon($Source)
        }
        'GG'{
        $global:Source = "MIRROR SOURCE"
        StartProcMon($Source)
        }
        'H' {
        $global:Source = "MAIN SOURCE"
        StartProcExp($Source)
        }
        'HH'{
        $global:Source = "MIRROR SOURCE"
        StartProcExp($Source)
        }
        'I' {
        $global:Source = "MAIN SOURCE"
        StartTCPView($Source)
        }
        'II'{
        $global:Source = "MIRROR SOURCE"
        StartTCPView($Source)
        }
        'J' {
        $global:Source = "MAIN SOURCE"
        StartAccessEnum($Source)
        }
        'JJ'{
        $global:Source = "MIRROR SOURCE"
        StartAccessEnum($Source)
        }
        'W'{
        $global:Source = "MAIN SOURCE"
        StartWizTree($Source)
        }
        'WW'{
        $global:Source = "MIRROR SOURCE"
        StartWizTree($Source)
        }
        'X' {
            Clear-Host
            AppXShowContact
            pause    
        }
        'Y' {
        WipeTHC
        }
        'Z' {
        ExitHard
        }
        '' {
        Show-Menu
        }
    }
 }
 until ($selection -eq 'zz')

