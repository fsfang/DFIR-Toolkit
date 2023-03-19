@echo off
:: --------------------------------------------------------------------------------------------------------------------------
:: Name:     IR_Script.cmd
:: Purpose:  Collect artifacts in a incident response case based on Windows operating system.
:: Author:   FS FANG
:: Version:  1.4.6
:: Revision: Sep 2020 v1.0.0 - initial version
::           Oct 2020 v1.0.1 - add:    UsrClass.dat
::           Nov 2020 v1.1.0 - compatible with 32/64-bit operation system
::                             add:    acquire memory, schtasks Tasks folder, prefetch files
::                             modify: collect all winevt logs by robocopy
::                             modify: collect each user's ntuser.dat, usrclass.dat, and recent folder
::           Dec 2020 v1.1.1 - add:    create collection folder automatically
::                             modify: collect each fixed disk's MFT
::           Jan 2021 v1.2.0 - add:    collect bitmap cache, shellbags, Windows.edb, Recycle Bin files, Amcache.hve and SRUM folder
::           Aug 2021 v1.3.0 - add:    define legacy platform collection procedure
::           Sep 2021 v1.4.0 - add:    collect Antivirus logs, browsing history, web server logs, powershell console logs and FTP related logs
::           Nov 2021 v1.4.1 - add:    collect Win10 Timeline ActivitiesCache.db
::           Sep 2022 v1.4.2 - add:    add Collection.log
::                             modify: bug fixes
::           Nov 2022 v1.4.3 - modify: bug fixes
::           Dec 2022 v1.4.4 - add:    collect and parse UsnJrnl
::                             modify: collect each fixed disk's NTFS timeline
::           Jan 2023 v1.4.5 - modify: digital signature tool replaced 
::                             modify: bug fixes
::           Mar 2023 v1.4.6 - add:    collect registry transaction logs to handle unreconciled data (dirty hive)
::                             add:    7zip tool for archive collection
::                             add:    collect recent execution, open files log and scan common directories where malware hide in
::                             modify: listdll shows version information
::                             modify: autoruns version update and collect more information
::                             modify: improved display of messages 
:: --------------------------------------------------------------------------------------------------------------------------
:: --------------------------------------------------------------------------------------------------------------------------
:: Set Setting Script Variables
:: --------------------------------------------------------------------------------------------------------------------------
:header
call :setESC

echo.
echo %ESC%%G% ___ ___  ___         _      _  %ESC%%END%
echo %ESC%%G%^|_ _^| _ \/ __^| __ _ _(_)_ __^| ^|_   %ESC%%END%
echo %ESC%%G% ^| ^|^|   /\__ \/ _^| '_^| ^| '_ \  _^|  %ESC%%END%
echo %ESC%%G%^|___^|_^|_\^|___/\__^|_^| ^|_^| .__/\__^|  Windows Ver.      %ESC%%END%
echo %ESC%%G%                       ^|_^|         v1.4.6  @FFS   %ESC%%END%                               

echo.
echo %ESC%%C%Developed by: FS FANG %ESC%%END%
echo %ESC%%C%Collect artifacts in a incident response case based on Windows operating system. %ESC%%END%
echo.

call :main

:setESC
:Console color
set G=[92m
set Y=[93m
set P=[95m
set C=[96m
set END=[0m

for /F "tokens=1,2 delims=#" %%a in ('"prompt #$H#$E# & echo on & for %%b in (1) do rem"') do (
  set ESC=%%b
  exit /B 0
)
exit /B 0

:main
REM Setting System Drive (default C:)
set SYSTEM_DRIVE=%1
if "%1" == "" (
    set SYSTEM_DRIVE=%SYSTEMDRIVE%
)

REM Setting Batch Script Drive
set SCRIPT_DRIVE=%~d0

REM Setting Collection Folder
set COLLECTION_FOLDER=%SCRIPT_DRIVE%\Collection_%COMPUTERNAME%

REM Setting CollectFilesTools Path
set COLLECTFILESTOOLS_FOLDER=%SCRIPT_DRIVE%\Windows\Tools\EvidenceCollection

REM Setting AnalysisTools Path
set ANALYSISTOOLS_FOLDER=%SCRIPT_DRIVE%\Windows\Tools\EvidenceAnalysis

:: --------------------------------------------------------------------------------------------------------------------------
:: Operating System Environment Variables
:: --------------------------------------------------------------------------------------------------------------------------
REM Determining the System Architecture
if "%PROCESSOR_ARCHITECTURE%" == "x86" set ARCH=32
if "%PROCESSOR_ARCHITECTURE%" == "AMD64" set ARCH=64

REM XP/2003/2000 (legacy operating system)
ver | find "5.0" > nul
if %ERRORLEVEL% == 0 set OS=legacy
ver | find  "5.1" > nul
if %ERRORLEVEL% == 0 set OS=legacy
ver | find  "5.2" > nul
if %ERRORLEVEL% == 0 set OS=legacy

echo %ESC%%Y%[+] Start running IR_Script.cmd for %COMPUTERNAME% %ESC%%END%

if not exist %COLLECTION_FOLDER% (

    REM Create Collection Folder
    echo %ESC%%Y%[+] Creating Collection Folders for %COMPUTERNAME% %ESC%%END%
    
    mkdir %COLLECTION_FOLDER%
    mkdir %COLLECTION_FOLDER%\MBR
    mkdir %COLLECTION_FOLDER%\NTFS
    mkdir %COLLECTION_FOLDER%\MemoryInfo
    mkdir %COLLECTION_FOLDER%\AccountInfo
    mkdir %COLLECTION_FOLDER%\EventLog
    mkdir %COLLECTION_FOLDER%\NetworkInfo
    mkdir %COLLECTION_FOLDER%\Prefetch
    mkdir %COLLECTION_FOLDER%\BrowsingHistory
    mkdir %COLLECTION_FOLDER%\PowerShell
    mkdir %COLLECTION_FOLDER%\WebServer
    mkdir %COLLECTION_FOLDER%\ProcessInfo
    mkdir %COLLECTION_FOLDER%\RecentExecution
    mkdir %COLLECTION_FOLDER%\Registry
    mkdir %COLLECTION_FOLDER%\Recent
    mkdir %COLLECTION_FOLDER%\SignInfo
    mkdir %COLLECTION_FOLDER%\TaskInfo
    mkdir %COLLECTION_FOLDER%\Timeline
    mkdir %COLLECTION_FOLDER%\BMC
    mkdir %COLLECTION_FOLDER%\Shellbags
    mkdir %COLLECTION_FOLDER%\Windows.edb
    mkdir %COLLECTION_FOLDER%\RecycleBin
    mkdir %COLLECTION_FOLDER%\SRUM
    mkdir %COLLECTION_FOLDER%\FTP
    mkdir %COLLECTION_FOLDER%\Antivirus
    mkdir %COLLECTION_FOLDER%\Suspect
    
    REM Recording the time and date of the data collection
    echo [+] Logging initiated for %COMPUTERNAME% on %DATE% %TIME% > %COLLECTION_FOLDER%\Collection.log    
    echo %ESC%%Y%[+] Logging initiated for %COMPUTERNAME% on %DATE% %TIME%
    
    REM Collecting SystemInfo
    echo [+] Collecting SystemInfo on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting SystemInfo on %DATE% %TIME% %ESC%%END%
    
    systeminfo > %COLLECTION_FOLDER%\%COMPUTERNAME%_Systeminfo.txt 2>&1

    REM Making System Timeline
    echo [+] Making System Timeline on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Making System Timeline on %DATE% %TIME% %ESC%%END%

    for /f "skip=1 delims=" %%i in ('wmic logicaldisk where "DriveType='3'" get DeviceID') do @for /f "tokens=1 delims=:" %%j in ("%%i") do (    
        dir %%j:\ /a/s/od/ta > %COLLECTION_FOLDER%\Timeline\%COMPUTERNAME%_%%j_AccessTime.txt 2>&1
        dir %%j:\ /a/s/od/tc/q > %COLLECTION_FOLDER%\Timeline\%COMPUTERNAME%_%%j_CreationTime.txt 2>&1
        dir %%j:\ /a/s/od/tw > %COLLECTION_FOLDER%\Timeline\%COMPUTERNAME%_%%j_WriteTime.txt 2>&1
    )

    REM Collecting Network Activity Information
    echo [+] Collecting Network Activity Information on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting Network Activity Information on %DATE% %TIME% %ESC%%END%
    
    ipconfig /all > %COLLECTION_FOLDER%\NetworkInfo\%COMPUTERNAME%_NIC.txt 2>&1
    route print > %COLLECTION_FOLDER%\NetworkInfo\%COMPUTERNAME%_Route.txt 2>&1
    nbtstat -c > %COLLECTION_FOLDER%\NetworkInfo\%COMPUTERNAME%_NetNameCache.txt 2>&1
    nbtstat -rn > %COLLECTION_FOLDER%\NetworkInfo\%COMPUTERNAME%_NetRoute.txt 2>&1
    netstat -ano > %COLLECTION_FOLDER%\NetworkInfo\%COMPUTERNAME%_NetStat.txt 2>&1
    arp.exe -a > %COLLECTION_FOLDER%\NetworkInfo\%COMPUTERNAME%_Arp.txt 2>&1
    net session > %COLLECTION_FOLDER%\NetworkInfo\%COMPUTERNAME%_Session.txt 2>&1
    net share > %COLLECTION_FOLDER%\NetworkInfo\%COMPUTERNAME%_SharedDrives.txt 2>&1
    if %ARCH% == 32 (
        %COLLECTFILESTOOLS_FOLDER%\psfile\psfile.exe /accepteula /nobanner > %COLLECTION_FOLDER%\NetworkInfo\%COMPUTERNAME%_Openfileremote.txt 2>&1
    )
    if %ARCH% == 64 (
        %COLLECTFILESTOOLS_FOLDER%\psfile\psfile64.exe /accepteula /nobanner > %COLLECTION_FOLDER%\NetworkInfo\%COMPUTERNAME%_Openfileremote.txt 2>&1
    )
    %COLLECTFILESTOOLS_FOLDER%\promqry.exe > %COLLECTION_FOLDER%\NetworkInfo\%COMPUTERNAME%_NSniff.txt

    REM Collecting User Information, Logon users
    echo [+] Collecting User Information, Logon users on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting User Information, Logon users on %DATE% %TIME% %ESC%%END%

    net user > %COLLECTION_FOLDER%\AccountInfo\%COMPUTERNAME%_AccountInfo.txt
    net user Administrator > %COLLECTION_FOLDER%\AccountInfo\%COMPUTERNAME%_LocalAdminInfo.txt
    net localgroup > %COLLECTION_FOLDER%\AccountInfo\%COMPUTERNAME%_GroupInfo.txt
    net localgroup Administrators > %COLLECTION_FOLDER%\AccountInfo\%COMPUTERNAME%_AdminGroupInfo.txt
    if %ARCH% == 32 (
        %COLLECTFILESTOOLS_FOLDER%\PsLoggedon\PsLoggedon.exe /accepteula /nobanner > %COLLECTION_FOLDER%\AccountInfo\%COMPUTERNAME%_LoggedUsers.txt 2>&1
        %COLLECTFILESTOOLS_FOLDER%\logonsessions\logonsessions.exe /accepteula /nobanner -p > %COLLECTION_FOLDER%\AccountInfo\%COMPUTERNAME%_LoggedOnUsers.txt 2>&1
    )
    if %ARCH% == 64 (
        %COLLECTFILESTOOLS_FOLDER%\PsLoggedon\PsLoggedon64.exe /accepteula /nobanner > %COLLECTION_FOLDER%\AccountInfo\%COMPUTERNAME%_LoggedUsers.txt 2>&1
        %COLLECTFILESTOOLS_FOLDER%\logonsessions\logonsessions64.exe /accepteula /nobanner -p > %COLLECTION_FOLDER%\AccountInfo\%COMPUTERNAME%_LoggedOnUsers.txt 2>&1
    )

    REM Collecting Running Processes Information
    echo [+] Collecting Running Processes Information on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting Running Processes Information on %DATE% %TIME% %ESC%%END%

    tasklist /svc > %COLLECTION_FOLDER%\ProcessInfo\%COMPUTERNAME%_Taskserv.txt 2>&1
    tasklist /v > %COLLECTION_FOLDER%\ProcessInfo\%COMPUTERNAME%_Taskinfo.txt 2>&1
    if %ARCH% == 32 (
        %COLLECTFILESTOOLS_FOLDER%\pslist\pslist.exe /accepteula /nobanner /t > %COLLECTION_FOLDER%\ProcessInfo\%COMPUTERNAME%_Tasktree.txt 2>&1
        %COLLECTFILESTOOLS_FOLDER%\Listdlls\Listdlls.exe /accepteula /nobanner -v > %COLLECTION_FOLDER%\ProcessInfo\%COMPUTERNAME%_Lstdlls.txt 2>&1
        %COLLECTFILESTOOLS_FOLDER%\handle\handle.exe /accepteula /nobanner -a > %COLLECTION_FOLDER%\ProcessInfo\%COMPUTERNAME%_Lsthandles.txt 2>&1
        %COLLECTFILESTOOLS_FOLDER%\PsService\PsService.exe /accepteula /nobanner config > %COLLECTION_FOLDER%\ProcessInfo\%COMPUTERNAME%_Tasklst.txt 2>&1
    )
    if %ARCH% == 64 (
        %COLLECTFILESTOOLS_FOLDER%\pslist\pslist64.exe /accepteula /nobanner /t > %COLLECTION_FOLDER%\ProcessInfo\%COMPUTERNAME%_Tasktree.txt 2>&1
        %COLLECTFILESTOOLS_FOLDER%\Listdlls\Listdlls64.exe /accepteula /nobanner -v > %COLLECTION_FOLDER%\ProcessInfo\%COMPUTERNAME%_Lstdlls.txt 2>&1
        %COLLECTFILESTOOLS_FOLDER%\handle\handle64.exe /accepteula /nobanner -a > %COLLECTION_FOLDER%\ProcessInfo\%COMPUTERNAME%_Lsthandles.txt 2>&1
        %COLLECTFILESTOOLS_FOLDER%\PsService\PsService64.exe /accepteula /nobanner config > %COLLECTION_FOLDER%\ProcessInfo\%COMPUTERNAME%_Tasklst.txt 2>&1
    )

    REM Collecting Automatically Start Programs
    echo [+] Collecting Automatically Start Programs on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log    
    echo %ESC%%Y%[+] Collecting Automatically Start Programs on %DATE% %TIME% %ESC%%END%
    
    if %ARCH% == 32 (
        %COLLECTFILESTOOLS_FOLDER%\autoruns\autorunsc.exe /accepteula /nobanner -a * -c -h -s -t * > %COLLECTION_FOLDER%\TaskInfo\%COMPUTERNAME%_Autoruns.txt 2>&1
        %COLLECTFILESTOOLS_FOLDER%\autoruns\Autoruns.exe -e -a %COLLECTION_FOLDER%\TaskInfo\%COMPUTERNAME%_Autoruns.arn 
    )
    if %ARCH% == 64 (
        %COLLECTFILESTOOLS_FOLDER%\autoruns\autorunsc64.exe /accepteula /nobanner -a * -c -h -s -t * > %COLLECTION_FOLDER%\TaskInfo\%COMPUTERNAME%_Autoruns.txt 2>&1
        %COLLECTFILESTOOLS_FOLDER%\autoruns\Autoruns64.exe -e -a %COLLECTION_FOLDER%\TaskInfo\%COMPUTERNAME%_Autoruns.arn >> %COLLECTION_FOLDER%\Collection.log 2>&1
    )
    at > %COLLECTION_FOLDER%\TaskInfo\%COMPUTERNAME%_At.txt 2>&1
    schtasks /query > %COLLECTION_FOLDER%\TaskInfo\%COMPUTERNAME%_Schtask.txt 2>&1
    %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %SYSTEM_DRIVE%\Windows\Tasks %COLLECTION_FOLDER%\TaskInfo\Tasks\ /ZB /copy:DAT /r:0 /ts /FP /np >> %COLLECTION_FOLDER%\Collection.log 2>&1

    REM Collecting Registry
    echo [+] Collecting Registry on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting Registry on %DATE% %TIME% %ESC%%END%
    
    if %ARCH% == 32 (
        "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SYSTEM /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1 
        "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SYSTEM.LOG1 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SYSTEM.LOG2 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SOFTWARE /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SOFTWARE.LOG1 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SOFTWARE.LOG2 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SECURITY /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SECURITY.LOG1 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SECURITY.LOG2 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SAM /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SAM.LOG1 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SAM.LOG2 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    ) 
    if %ARCH% == 64 (
        "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SYSTEM /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SYSTEM.LOG1 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SYSTEM.LOG2 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SOFTWARE /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SOFTWARE.LOG1 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SOFTWARE.LOG2 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SECURITY /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SECURITY.LOG1 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SECURITY.LOG2 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SAM /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SAM.LOG1 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SAM.LOG2 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    )
    
    REM Collecting Amcache.hve
    echo [+] Collecting Amcache.hve on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting Amcache.hve on %DATE% %TIME% %ESC%%END%
    
    if %ARCH% == 32 (
        %COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\appcompat\Programs\Amcache.hve /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\appcompat\Programs\Amcache.hve.LOG1 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\appcompat\Programs\Amcache.hve.LOG2 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    )
    if %ARCH% == 64 (
        %COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\appcompat\Programs\Amcache.hve /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\appcompat\Programs\Amcache.hve.LOG1 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\appcompat\Programs\Amcache.hve.LOG2 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    )
    %ANALYSISTOOLS_FOLDER%\AmcacheParser.exe -f %COLLECTION_FOLDER%\Registry\Amcache.hve --csv %COLLECTION_FOLDER%\RecentExecution\ --csvf Amcache.csv -i >> %COLLECTION_FOLDER%\Collection.log 2>&1

    REM Collecting Each User's Registry Hive (NTUSER.DAT, USRCLASS.DAT)
    echo [+] Collecting Each User's Registry Hive on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting Each User's Registry Hive on %DATE% %TIME% %ESC%%END%
    
    if NOT %OS% == legacy (set USERPATH=%SYSTEM_DRIVE%\Users) else set (USERPATH="%SYSTEM_DRIVE%\Documents and Settings")
    
    REM Change Path To %USERPATH%
    %SYSTEM_DRIVE%
    cd %USERPATH%
    
    REM start collecting ntuser.dat and usrclass.dat
    for /f "tokens=*" %%i in ('dir /ah /b /s NTUSER.DAT.*') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
        if not exist %COLLECTION_FOLDER%\Registry\%%j (
            mkdir %COLLECTION_FOLDER%\Registry\%%j            
        )
        if %ARCH% == 32 (
            %COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe /FileNamePath:"%%i" /OutputPath:%COLLECTION_FOLDER%\Registry\%%j\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
        )
        if %ARCH% == 64 (
            %COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:"%%i" /OutputPath:%COLLECTION_FOLDER%\Registry\%%j\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
        )
    )
    
    for /f "tokens=*" %%i in ('dir /ah /b /s UsrClass.dat.*') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
            
        if %ARCH% == 32 (
            %COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe /FileNamePath:"%%i" /OutputPath:%COLLECTION_FOLDER%\Registry\%%j\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
        )
        if %ARCH% == 64 (
            %COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:"%%i" /OutputPath:%COLLECTION_FOLDER%\Registry\%%j\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
        )        
    )

    REM Collecting Each User's Recent Folder
    echo [+] Collecting Each User's Recent Folder on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting Each User's Recent Folder on %DATE% %TIME% %ESC%%END%

    for /f "tokens=*" %%i in ('dir /ah /b /s Recent') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
        if not exist %COLLECTION_FOLDER%\Recent\%%j (
            mkdir %COLLECTION_FOLDER%\Recent\%%j
            mkdir %COLLECTION_FOLDER%\Recent\%%j\JLECmd-output
            %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%%i" %COLLECTION_FOLDER%\Recent\%%j /ZB /copy:DAT /r:0 /ts /FP /np /E /A-:SH >> %COLLECTION_FOLDER%\Collection.log 2>&1
            %ANALYSISTOOLS_FOLDER%\JLECmd.exe -d %COLLECTION_FOLDER%\Recent\%%j\AutomaticDestinations --csv %COLLECTION_FOLDER%\Recent\%%j\JLECmd-output --csvf JLECmd_AutomaticDestinations.csv -q >> %COLLECTION_FOLDER%\Collection.log 2>&1
            %ANALYSISTOOLS_FOLDER%\JLECmd.exe -d %COLLECTION_FOLDER%\Recent\%%j\CustomDestinations --csv %COLLECTION_FOLDER%\Recent\%%j\JLECmd-output --csvf JLECmd_CustomDestinations.csv -q >> %COLLECTION_FOLDER%\Collection.log 2>&1
        )
    )
    
    %ANALYSISTOOLS_FOLDER%\lastactivityview\LastActivityView.exe /scomma %COLLECTION_FOLDER%\Recent\%COMPUTERNAME%_LastActivity.csv >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %ANALYSISTOOLS_FOLDER%\recentfilesview\RecentFilesView.exe /shtml %COLLECTION_FOLDER%\Recent\%COMPUTERNAME%_RecentFilesView.html /sort ~3 >> %COLLECTION_FOLDER%\Collection.log 2>&1
    
    REM Collecting Each User's Bitmap Cache
    echo [+] Collecting Each User's Bitmap Cache on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting Each User's Bitmap Cache on %DATE% %TIME% %ESC%%END%
    
    for /f "tokens=*" %%i in ('dir /ad /b /s "Terminal Server Client"') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
        if not exist %COLLECTION_FOLDER%\BMC\%%j (
            mkdir %COLLECTION_FOLDER%\BMC\%%j
            %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%%i\Cache" %COLLECTION_FOLDER%\BMC\%%j /ZB /copy:DAT /r:0 /ts /FP /np /E /A-:SH >> %COLLECTION_FOLDER%\Collection.log 2>&1            
        )
        mkdir %COLLECTION_FOLDER%\BMC\%%j\bmc-tools-output
        %ANALYSISTOOLS_FOLDER%\bmc-tools.exe -s %COLLECTION_FOLDER%\BMC\%%j -d %COLLECTION_FOLDER%\BMC\%%j\bmc-tools-output -b >> %COLLECTION_FOLDER%\Collection.log 2>&1
    )
    
    REM Collecting PowerShell Console logs
    echo [+] Collecting PowerShell Console logs on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting PowerShell Console logs on %DATE% %TIME% %ESC%%END%

    for /f "tokens=*" %%i in ('dir /ad /b /s PSReadLine') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
        if not exist %COLLECTION_FOLDER%\PowerShell\%%j (
            mkdir %COLLECTION_FOLDER%\PowerShell\%%j
            %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %%i %COLLECTION_FOLDER%\PowerShell\%%j ConsoleHost_history.txt >> %COLLECTION_FOLDER%\Collection.log 2>&1
        )
    )
    
    REM Collecting Win10 timeline ActivitiesCache.db
    echo [+] Collecting Win10 timeline ActivitiesCache.db on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting Win10 timeline ActivitiesCache.db on %DATE% %TIME% %ESC%%END%
    
    for /f "tokens=*" %%i in ('dir /ad /b /s ConnectedDevicesPlatform') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
        if not exist %COLLECTION_FOLDER%\ActivitiesCache\%%j (
            mkdir %COLLECTION_FOLDER%\ActivitiesCache\%%j
            %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %%i\L.%%j\ %COLLECTION_FOLDER%\ActivitiesCache\%%j /ZB /copy:DAT /r:0 /ts /FP /np /E /A-:SH >> %COLLECTION_FOLDER%\Collection.log 2>&1
        )
        mkdir %COLLECTION_FOLDER%\ActivitiesCache\%%j\WxT-output
        %ANALYSISTOOLS_FOLDER%\WxTCmd.exe -f %COLLECTION_FOLDER%\ActivitiesCache\%%j\ActivitiesCache.db --csv %COLLECTION_FOLDER%\ActivitiesCache\%%j\WxT-output >> %COLLECTION_FOLDER%\Collection.log 2>&1
    )
    
    REM Collecting FTP related logs
    echo [+] Collecting FTP related logs on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting FTP related logs on %DATE% %TIME% %ESC%%END%

    REM FileZilla Client
    for /f "tokens=*" %%i in ('dir /ad /b /s FileZilla*') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
        if not exist %COLLECTION_FOLDER%\FTP\%%j (
            mkdir %COLLECTION_FOLDER%\FTP\%%j
            %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %%i %COLLECTION_FOLDER%\FTP\%%j *.xml >> %COLLECTION_FOLDER%\Collection.log 2>&1
        )
    )
    
    REM FileZilla Server logs
    %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\Windows\Program Files (x86)\FileZilla Server\Logs\" %COLLECTION_FOLDER%\FTP *.log >> %COLLECTION_FOLDER%\Collection.log 2>&1
    
    REM WinSCP ini file
    %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %SYSTEM_DRIVE%\Windows\ %COLLECTION_FOLDER%\FTP WinSCP.ini >> %COLLECTION_FOLDER%\Collection.log 2>&1

    REM switch back to script path
    %SCRIPT_DRIVE%

    REM Collecting Windows Event Logs
    echo [+] Collecting Windows Event Logs on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting Windows Event Logs on %DATE% %TIME% %ESC%%END%
    
    "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\System32\config\AppEvent.Evt /OutputPath:%COLLECTION_FOLDER%\EventLog >> %COLLECTION_FOLDER%\Collection.log 2>&1
    "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\System32\config\SecEvent.Evt /OutputPath:%COLLECTION_FOLDER%\EventLog >> %COLLECTION_FOLDER%\Collection.log 2>&1
    "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\System32\config\SysEvent.Evt /OutputPath:%COLLECTION_FOLDER%\EventLog >> %COLLECTION_FOLDER%\Collection.log 2>&1
    robocopy "%SYSTEM_DRIVE%\Windows\System32\winevt\Logs" "%COLLECTION_FOLDER%\EventLog" /ZB /copy:DAT /r:0 /ts /FP /np /E >> %COLLECTION_FOLDER%\Collection.log 2>&1
    
    REM if %OS% == "legacy" (        
        REM if %ARCH% == 32 (
            REM "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\System32\config\AppEvent.Evt /OutputPath:%COLLECTION_FOLDER%\EventLog
            REM "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\System32\config\SecEvent.Evt /OutputPath:%COLLECTION_FOLDER%\EventLog
            REM "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\System32\config\SysEvent.Evt /OutputPath:%COLLECTION_FOLDER%\EventLog
        REM )
        REM if %ARCH% == 64 (
            REM "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\System32\config\AppEvent.Evt /OutputPath:%COLLECTION_FOLDER%\EventLog
            REM "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\System32\config\SecEvent.Evt /OutputPath:%COLLECTION_FOLDER%\EventLog
            REM "%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\System32\config\SysEvent.Evt /OutputPath:%COLLECTION_FOLDER%\EventLog
        REM )
    REM ) else (
        REM robocopy "%SYSTEM_DRIVE%\Windows\System32\winevt\Logs" "%COLLECTION_FOLDER%\EventLog" /ZB /copy:DAT /r:0 /ts /FP /np /E
    REM )    
    
    REM Collecting MBR
    echo [+] Collecting MBR on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting MBR on %DATE% %TIME% %ESC%%END%

    %COLLECTFILESTOOLS_FOLDER%\dd.exe if=\\.\PhysicalDrive0 of=%COLLECTION_FOLDER%\MBR\%COMPUTERNAME%_MBR.dump bs=512 count=32 >> %COLLECTION_FOLDER%\Collection.log 2>&1

    REM Collecting Each Fixed Disk's MFT and parsing to csv
    echo [+] Collecting Each Fixed Disk's $MFT, $LogFile and parsing to csv on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting Each Fixed Disk's MFT, LogFile, UsnJrnl and parsing to csv on %DATE% %TIME% %ESC%%END%

    for /f "skip=1 delims=" %%i in ('wmic logicaldisk where "DriveType='3'" get DeviceID') do @for /f "tokens=1 delims=:" %%j in ("%%i") do (
    
        if %ARCH% == 32 (
            %COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe /FileNamePath:%%j:0 /OutputPath:%COLLECTION_FOLDER%\NTFS\ /OutputName:%COMPUTERNAME%_$MFT_%%j >> %COLLECTION_FOLDER%\Collection.log 2>&1
        )
        if %ARCH% == 64 (
            %COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:%%j:0 /OutputPath:%COLLECTION_FOLDER%\NTFS\ /OutputName:%COMPUTERNAME%_$MFT_%%j >> %COLLECTION_FOLDER%\Collection.log 2>&1
        )
        %ANALYSISTOOLS_FOLDER%\MFTECmd.exe -f %COLLECTION_FOLDER%\NTFS\%COMPUTERNAME%_$MFT_%%j --csv %COLLECTION_FOLDER%\NTFS\ --csvf %COMPUTERNAME%_MFT_%%j.csv >> %COLLECTION_FOLDER%\Collection.log 2>&1
    )
    
    REM Collecting Each Fixed Disk's $LogFile
    for /f "skip=1 delims=" %%i in ('wmic logicaldisk where "DriveType='3'" get DeviceID') do @for /f "tokens=1 delims=:" %%j in ("%%i") do (
    
        if %ARCH% == 32 (
            %COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe /FileNamePath:%%j:2 /OutputPath:%COLLECTION_FOLDER%\NTFS\ /OutputName:%COMPUTERNAME%_$LogFile_%%j >> %COLLECTION_FOLDER%\Collection.log 2>&1            
        )
        if %ARCH% == 64 (
            %COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:%%j:2 /OutputPath:%COLLECTION_FOLDER%\NTFS\ /OutputName:%COMPUTERNAME%_$LogFile_%%j >> %COLLECTION_FOLDER%\Collection.log 2>&1
        )
        REM %ANALYSISTOOLS_FOLDER%\MFTECmd.exe -f %COLLECTION_FOLDER%\NTFS\%COMPUTERNAME%_$LogFile_%%j --csv %COLLECTION_FOLDER%\NTFS\ --csvf %COMPUTERNAME%_LogFile_%%j.csv --not supported yet
    )
    
    REM Collecting Each Fixed Disk's $UsnJrnl and parsing to csv
    for /f "skip=1 delims=" %%i in ('wmic logicaldisk where "DriveType='3'" get DeviceID') do @for /f "tokens=1 delims=:" %%j in ("%%i") do (
        if %ARCH% == 32 (
            %COLLECTFILESTOOLS_FOLDER%\ExtractUsnJrnl\ExtractUsnJrnl.exe /DevicePath:%%j: /OutputPath:%COLLECTION_FOLDER%\NTFS\ /OutputName:%COMPUTERNAME%_$J_%%j >> %COLLECTION_FOLDER%\Collection.log 2>&1
        )
        if %ARCH% == 64 (
            %COLLECTFILESTOOLS_FOLDER%\ExtractUsnJrnl\ExtractUsnJrnl64.exe /DevicePath:%%j: /OutputPath:%COLLECTION_FOLDER%\NTFS\ /OutputName:%COMPUTERNAME%_$J_%%j >> %COLLECTION_FOLDER%\Collection.log 2>&1
        )
        %ANALYSISTOOLS_FOLDER%\MFTECmd.exe -f %COLLECTION_FOLDER%\NTFS\%COMPUTERNAME%_$J_%%j --csv %COLLECTION_FOLDER%\NTFS\ --csvf %COMPUTERNAME%_J_%%j.csv >> %COLLECTION_FOLDER%\Collection.log 2>&1
    )
    
    REM Collecting Shellbags InformSation
    echo [+] Collecting Shellbags Information on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting Shellbags Information on %DATE% %TIME% %ESC%%END%

    %ANALYSISTOOLS_FOLDER%\SBECmd.exe -l --csv %COLLECTION_FOLDER%\Shellbags -q >> %COLLECTION_FOLDER%\Collection.log 2>&1
    
    REM Collecting AppCompatCache Information
    echo [+] Collecting AppCompatCache Information on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting AppCompatCache Information on %DATE% %TIME% %ESC%%END%
    
    %ANALYSISTOOLS_FOLDER%\AppCompatCacheParser.exe -t --csv %COLLECTION_FOLDER%\RecentExecution\ --csvf AppCompatCacheParser_output.csv >> %COLLECTION_FOLDER%\Collection.log 2>&1

    REM Collecting Prefetch File
    echo [+] Collecting Prefetch File on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting Prefetch File on %DATE% %TIME% %ESC%%END%
    
    %ANALYSISTOOLS_FOLDER%\PECmd.exe -d %SYSTEM_DRIVE%\Windows\Prefetch --csv %COLLECTION_FOLDER%\Prefetch --csvf %COMPUTERNAME%_pf.csv -q >> %COLLECTION_FOLDER%\Collection.log 2>&1
    
    if %ARCH% == 32 (
        %ANALYSISTOOLS_FOLDER%\winprefetchview\x86\WinPrefetchView.exe /sort "Last Run Time" /scomma %COLLECTION_FOLDER%\Prefetch\%COMPUTERNAME%_Prefetch.csv >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %SYSTEM_DRIVE%\Windows\Prefetch %COLLECTION_FOLDER%\Prefetch\ *.pf /ZB /copy:DAT /r:0 /ts /FP /np >> %COLLECTION_FOLDER%\Collection.log 2>&1
    )
    if %ARCH% == 64 (
        %ANALYSISTOOLS_FOLDER%\winprefetchview\x64\WinPrefetchView.exe /sort "Last Run Time" /scomma %COLLECTION_FOLDER%\Prefetch\%COMPUTERNAME%_Prefetch.csv >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %SYSTEM_DRIVE%\Windows\Prefetch %COLLECTION_FOLDER%\Prefetch\ *.pf /ZB /copy:DAT /r:0 /ts /FP /np >> %COLLECTION_FOLDER%\Collection.log 2>&1
    )

    REM Collecting Browsing history
    echo [+] Collecting Browsing History on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting Browsing History on %DATE% %TIME% %ESC%%END%
    
    if %ARCH% == 32 (
        %COLLECTFILESTOOLS_FOLDER%\browsinghistoryview\BrowsingHistoryView.exe /HistorySource 1 /LoadIE 1 /LoadFirefox 1 /LoadChrome 1 /LoadSafari 1 /sort "Visit Time" /scomma %COLLECTION_FOLDER%\BrowsingHistory\%COMPUTERNAME%_BrowsingHistory.csv
    )
    if %ARCH% == 64 (
        %COLLECTFILESTOOLS_FOLDER%\browsinghistoryview\BrowsingHistoryView64.exe /HistorySource 1 /LoadIE 1 /LoadFirefox 1 /LoadChrome 1 /LoadSafari 1 /sort "Visit Time" /scomma %COLLECTION_FOLDER%\BrowsingHistory\%COMPUTERNAME%_BrowsingHistory.csv
    )
    
    REM Collecting Web Servers logs
    echo [+] Collecting Web Servers logs on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting Web Servers logs on %DATE% %TIME% %ESC%%END%

    %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %SYSTEM_DRIVE%\inetpub\logs\LogFiles\ %COLLECTION_FOLDER%\WebServer\ *.log /E /ZB /copy:DAT /r:0 /ts /FP /np >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %SYSTEM_DRIVE%\Windows\nginx\logs\ %COLLECTION_FOLDER%\WebServer\ *.log /E /ZB /copy:DAT /r:0 /ts /FP /np >> %COLLECTION_FOLDER%\Collection.log 2>&1
    
    REM Collecting Sign InformSation
    echo [+] Collecting Sign InformSation on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting Sign InformSation on %DATE% %TIME% %ESC%%END%
    
    if %ARCH% == 32 (
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck.exe" /accepteula /nobanner -h -c -w %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_Windows_exe.csv C:\Windows\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck.exe" /accepteula /nobanner -h -c -w %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_Windows_dll.csv C:\Windows\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck.exe" /accepteula /nobanner -h -c -w %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_System32_exe.csv C:\Windows\System32\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck.exe" /accepteula /nobanner -h -c -w %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_System32_dll.csv C:\Windows\System32\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck.exe" /accepteula /nobanner -h -c -w %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_Syswow64_exe.csv C:\Windows\syswow64\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck.exe" /accepteula /nobanner -h -c -w %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_Syswow64_dll.csv C:\Windows\syswow64\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    )
    if %ARCH% == 64 (
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -w %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_Windows_exe.csv C:\Windows\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -w %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_Windows_dll.csv C:\Windows\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -w %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_System32_exe.csv C:\Windows\System32\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -w %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_System32_dll.csv C:\Windows\System32\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -w %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_Syswow64_exe.csv C:\Windows\syswow64\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -w %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_Syswow64_dll.csv C:\Windows\syswow64\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    )
    REM "%COLLECTFILESTOOLS_FOLDER%\signtool\x64\signtool.exe" verify /pa /q C:\Windows\*.exe 2> %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_Windows_exe.txt
    REM "%COLLECTFILESTOOLS_FOLDER%\signtool\x64\signtool.exe" verify /pa /q C:\Windows\*.dll 2> %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_Windows_dll.txt
    REM "%COLLECTFILESTOOLS_FOLDER%\signtool\x64\signtool.exe" verify /pa /q C:\Windows\System32\*.exe 2> %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_System32_exe.txt
    REM "%COLLECTFILESTOOLS_FOLDER%\signtool\x64\signtool.exe" verify /pa /q C:\Windows\System32\*.dll 2> %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_System32_dll.txt
    REM "%COLLECTFILESTOOLS_FOLDER%\signtool\x64\signtool.exe" verify /pa /q C:\Windows\syswow64\*.exe 2> %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_Syswow64_exe.txt
    REM "%COLLECTFILESTOOLS_FOLDER%\signtool\x64\signtool.exe" verify /pa /q C:\Windows\syswow64\*.dll 2> %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_Syswow64_dll.txt
    
    REM Collecting Recycle Bin files
    echo [+] Collecting Recycle Bin files on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting Recycle Bin files on %DATE% %TIME% %ESC%%END%
    
    %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %SYSTEM_DRIVE%\$Recycle.Bin %COLLECTION_FOLDER%\RecycleBin /ZB /copy:DAT /r:0 /ts /FP /np /E /A-:SH >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %SYSTEM_DRIVE%\RECYCLER %COLLECTION_FOLDER%\RecycleBin /ZB /copy:DAT /r:0 /ts /FP /np /E /A-:SH >> %COLLECTION_FOLDER%\Collection.log 2>&1
    
    REM if NOT %OS% == "legacy" (

        REM %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %SYSTEM_DRIVE%\$Recycle.Bin %COLLECTION_FOLDER%\RecycleBin /ZB /copy:DAT /r:0 /ts /FP /np /E /A-:SH
        
    REM ) else (
        REM %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %SYSTEM_DRIVE%\RECYCLER %COLLECTION_FOLDER%\RecycleBin /ZB /copy:DAT /r:0 /ts /FP /np /E /A-:SH
    REM )
    
    REM Collecting Windows.edb
    echo [+] Collecting Windows.edb on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting Windows.edb on %DATE% %TIME% %ESC%%END%
    
    if %ARCH% == 32 (
        %COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe /FileNamePath:%SYSTEM_DRIVE%\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb /OutputPath:%COLLECTION_FOLDER%\Windows.edb\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    )
    if %ARCH% == 64 (
        %COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb /OutputPath:%COLLECTION_FOLDER%\Windows.edb\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    )
    
    REM Collecting SRUM
    echo [+] Collecting SRUM on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting SRUM on %DATE% %TIME% %ESC%%END%

    if %ARCH% == 32 (
        %COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\sru\SRUDB.dat /OutputPath:%COLLECTION_FOLDER%\SRUM >> %COLLECTION_FOLDER%\Collection.log 2>&1
    )
    if %ARCH% == 64 (
        %COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\sru\SRUDB.dat /OutputPath:%COLLECTION_FOLDER%\SRUM >> %COLLECTION_FOLDER%\Collection.log 2>&1
    )
    
    %ANALYSISTOOLS_FOLDER%\SrumECmd.exe -f %COLLECTION_FOLDER%\SRUM\SRUDB.dat -r %COLLECTION_FOLDER%\Registry\SOFTWARE --csv  %COLLECTION_FOLDER%\SRUM\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    
    REM Collecting AntiVirus logs
    echo [+] Collecting AntiVirus logs on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting AntiVirus logs on %DATE% %TIME% %ESC%%END%
    
    if %OS% == legacy (

        %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\Documents And Settings\All Users\Application Data\Avast Software\Avast\Log\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\AVG\Antivirus\log\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\AVG\Antivirus\report\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\ESET\ESET NOD32 Antivirus\Logs\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\ESET\ESET NOD32 Antivirus\Logs\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\McAfee\DesktopProtection\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\Sophos\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\Symantec\Symantec Endpoint Protection\Logs\AV\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\Symantec\Symantec Endpoint Protection\Quarantine\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E >> %COLLECTION_FOLDER%\Collection.log 2>&1
        
    ) else (
        
        %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\Avast Software\Avast\Log\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\Avast Software\Avast\Chest\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\AVG\Antivirus\log\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\AVG\Antivirus\report\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\Avira\Antivirus\LOGFILES\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\ESET\ESET NOD32 Antivirus\Logs\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\F-Secure\Log\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\F-Secure\Antivirus\ScheduledScanReports\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\McAfee\DesktopProtection\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\McAfee\Endpoint Security\Logs\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\McAfee\Endpoint Security\Logs_Old\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\Mcafee\VirusScan\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\Sophos\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\Symantec\Symantec Endpoint Protection\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\Trend Micro\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\Microsoft\Microsoft AntiMalware\Support\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\Microsoft\Windows Defender\Support\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E >> %COLLECTION_FOLDER%\Collection.log 2>&1
    )
    
    REM Scan common directories where malware hide in
    echo [+] Scan common directories where malware hide in on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Scan common directories where malware hide in on %DATE% %TIME% %ESC%%END%
    
    if %ARCH% == 32 (
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_RecycleBin_exe.csv C:\$Recycle.bin\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_RecycleBin_dll.csv C:\$Recycle.bin\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_Recycler_exe.csv C:\RECYCLER\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_Recycler_dll.csv C:\RECYCLER\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_PerfLogs_exe.csv C:\PerfLogs\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_PerfLogs_dll.csv C:\PerfLogs\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_Temp_exe.csv C:\Windows\Temp\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_Temp_dll.csv C:\Windows\Temp\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_INF_exe.csv C:\Windows\INF\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_INF_dll.csv C:\Windows\INF\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_Help_exe.csv C:\Windows\Help\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_Help_dll.csv C:\Windows\Help\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_Font_exe.csv C:\Windows\Font\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_Font_dll.csv C:\Windows\Font\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_ProgramData_exe.csv C:\ProgramData\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_ProgramData_dll.csv C:\ProgramData\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_Intel_exe.csv C:\Intel\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_Intel_dll.csv C:\Intel\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
        
    )
    if %ARCH% == 64 (
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_RecycleBin_exe.csv C:\$Recycle.bin\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_RecycleBin_dll.csv C:\$Recycle.bin\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_Recycler_exe.csv C:\RECYCLER\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_Recycler_dll.csv C:\RECYCLER\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_PerfLogs_exe.csv C:\PerfLogs\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_PerfLogs_dll.csv C:\PerfLogs\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_Temp_exe.csv C:\Windows\Temp\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_Temp_dll.csv C:\Windows\Temp\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_INF_exe.csv C:\Windows\INF\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_INF_dll.csv C:\Windows\INF\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_Help_exe.csv C:\Windows\Help\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_Help_dll.csv C:\Windows\Help\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_Font_exe.csv C:\Windows\Font\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_Font_dll.csv C:\Windows\Font\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_ProgramData_exe.csv C:\ProgramData\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_ProgramData_dll.csv C:\ProgramData\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_Intel_exe.csv C:\Intel\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
        "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%COMPUTERNAME%_Intel_dll.csv C:\Intel\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    )

    REM REM Acquiring Memory
    REM echo [+] Acquiring Memory on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    REM echo %ESC%%Y%[+] Acquiring Memory on %DATE% %TIME% %ESC%%END%
    
    REM if %ARCH% == 32 (
        REM %COLLECTFILESTOOLS_FOLDER%\winpmem\winpmem_mini_x86.exe %COLLECTION_FOLDER%\MemoryInfo\%COMPUTERNAME%_physmem.raw >> %COLLECTION_FOLDER%\Collection.log 2>&1
    REM )
    REM if %ARCH% == 64 (
        REM %COLLECTFILESTOOLS_FOLDER%\winpmem\winpmem_mini_x64_rc2.exe %COLLECTION_FOLDER%\MemoryInfo\%COMPUTERNAME%_physmem.raw >> %COLLECTION_FOLDER%\Collection.log 2>&1
    REM )
    
    echo [+] Finished collecting on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Finished collecting on %DATE% %TIME% %ESC%%END%
    
    REM Archiving collection
    echo [+] Start archiving for %COMPUTERNAME% on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Start archiving for %COMPUTERNAME% on %DATE% %TIME% %ESC%%END%
    
    %COLLECTFILESTOOLS_FOLDER%\7z\7za.exe a %SCRIPT_DRIVE%\Collection_%COMPUTERNAME%.zip %SCRIPT_DRIVE%\Collection_%COMPUTERNAME%\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    
    echo [+] Finished archiving for %COMPUTERNAME% on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%P%[+] Finished archiving for %COMPUTERNAME% on %DATE% %TIME% %ESC%%END%
    
) else echo %ESC%%P%%[-] COMPUTERNAME% has already collected. %ESC%%END%

pause