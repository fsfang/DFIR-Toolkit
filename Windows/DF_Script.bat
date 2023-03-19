@echo off
:: --------------------------------------------------------------------------------------------------------------------------
:: Name:     DF_Script.cmd
:: Purpose:  Collect artifacts in a incident response case with image file based on Windows operating system.
:: Author:   FS FANG
:: Version:  1.0.4
:: Revision: Nov 2021 v1.0.0 - initial version
::           Aug 2022 v1.0.1 - modify: bug fixes
::           Dec 2022 v1.0.2 - add:    collect and parse UsnJrnl
::           Jan 2023 v1.0.3 - modify: digital signature tool replaced
::           Mar 2023 v1.0.4 - add:    collect registry transaction logs to handle unreconciled data (dirty hive)
::                             add:    scan common directories where malware hide in
::                             modify: improved display of messages and bug fixes
:: --------------------------------------------------------------------------------------------------------------------------

:header
call :setESC

echo.
echo %ESC%%G% ___  ___ ___         _      _     %ESC%%END%
echo %ESC%%G%^|   \^| __/ __^| __ _ _(_)_ __^| ^|_   %ESC%%END%
echo %ESC%%G%^| ^|) ^| _^|\__ \/ _^| '_^| ^| '_ \  _^|  %ESC%%END%
echo %ESC%%G%^|___/^|_^| ^|___/\__^|_^| ^|_^| .__/\__^|  Windows Ver.      %ESC%%END%
echo %ESC%%G%                       ^|_^|         v1.0.4  @FFS   %ESC%%END%                                   

echo.
echo %ESC%%C%Developed by: FS FANG %ESC%%END%
echo %ESC%%C%Collect artifacts in a incident response case with image file based on Windows operating system. %ESC%%END%
echo.
set /p  CASE_NAME=%ESC%%P%Case Name: %ESC%%END%
set /p  SYSTEM_DRIVE=%ESC%%P%System Drive Letter(C:): %ESC%%END%
set /p  OS=%ESC%%P%Enter 1 if image file is legacy OS. Otherwise, leave blank: %ESC%%END%
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

if %OS% == 1 (
    set OS=legacy
)

:main
:: --------------------------------------------------------------------------------------------------------------------------
:: Set Setting Script Variables
:: --------------------------------------------------------------------------------------------------------------------------
REM Setting Batch Script Drive
set SCRIPT_DRIVE=%~d0

REM Setting Collection Folder
set COLLECTION_FOLDER=%SCRIPT_DRIVE%\Collection_%CASE_NAME%

REM Setting CollectFilesTools Path
set COLLECTFILESTOOLS_FOLDER=%SCRIPT_DRIVE%\Windows\Tools\EvidenceCollection

REM Setting AnalysisTools Path
set ANALYSISTOOLS_FOLDER=%SCRIPT_DRIVE%\Windows\Tools\EvidenceAnalysis
:: --------------------------------------------------------------------------------------------------------------------------
:: --------------------------------------------------------------------------------------------------------------------------

echo %ESC%%Y%[+] Start running DF_Script.cmd for %CASE_NAME% %ESC%%END%

if not exist %COLLECTION_FOLDER% (

    REM Create Collection Folder
    echo %ESC%%Y%[+] Creating Collection Folders for %CASE_NAME% %ESC%%END%
    
    mkdir %COLLECTION_FOLDER%
    mkdir %COLLECTION_FOLDER%\Timeline
    mkdir %COLLECTION_FOLDER%\Tasks
    mkdir %COLLECTION_FOLDER%\MBR
    mkdir %COLLECTION_FOLDER%\NTFS
    mkdir %COLLECTION_FOLDER%\EventLog
    mkdir %COLLECTION_FOLDER%\Prefetch
    mkdir %COLLECTION_FOLDER%\PowerShell
    mkdir %COLLECTION_FOLDER%\WebServer
    mkdir %COLLECTION_FOLDER%\RecentExecution
    mkdir %COLLECTION_FOLDER%\Registry
    mkdir %COLLECTION_FOLDER%\Recent
    mkdir %COLLECTION_FOLDER%\SignInfo
    mkdir %COLLECTION_FOLDER%\BMC
    mkdir %COLLECTION_FOLDER%\Windows.edb
    mkdir %COLLECTION_FOLDER%\RecycleBin
    mkdir %COLLECTION_FOLDER%\SRUM
    mkdir %COLLECTION_FOLDER%\FTP
    mkdir %COLLECTION_FOLDER%\Antivirus
    mkdir %COLLECTION_FOLDER%\Suspect
    
    REM Recording the time and date of the data collection
    echo [+] Logging initiated for %CASE_NAME% on %DATE% %TIME% > %COLLECTION_FOLDER%\Collection.log    
    echo %ESC%%Y%[+] Logging initiated for %CASE_NAME% on %DATE% %TIME%

    REM Making System Timeline
    echo [+] Making System Timeline on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Making System Timeline on %DATE% %TIME% %ESC%%END%

    dir %SYSTEM_DRIVE%\ /a/s/od/ta > %COLLECTION_FOLDER%\Timeline\%CASE_NAME%_AccessTime.txt 2>&1
    dir %SYSTEM_DRIVE%\ /a/s/od/tc/q > %COLLECTION_FOLDER%\Timeline\%CASE_NAME%_CreationTime.txt 2>&1
    dir %SYSTEM_DRIVE%\ /a/s/od/tw > %COLLECTION_FOLDER%\Timeline\%CASE_NAME%_WriteTime.txt 2>&1

    REM Collecting Automatically Start Programs
    echo [+] Collecting Task files on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting Task files %DATE% %TIME% %ESC%%END%

    %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %SYSTEM_DRIVE%\Windows\Tasks %COLLECTION_FOLDER%\Tasks\ /ZB /copy:DAT /r:0 /ts /FP /np >> %COLLECTION_FOLDER%\Collection.log 2>&1

    REM Collecting Registry
    echo [+] Collecting Registry on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting Registry on %DATE% %TIME% %ESC%%END%

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
    
    REM Collecting Amcache.hve
    echo [+] Collecting Amcache.hve on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting Amcache.hve on %DATE% %TIME% %ESC%%END%
    
    %COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\appcompat\Programs\Amcache.hve /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\appcompat\Programs\Amcache.hve.LOG1 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\appcompat\Programs\Amcache.hve.LOG2 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1

    %ANALYSISTOOLS_FOLDER%\AmcacheParser.exe -f %COLLECTION_FOLDER%\Registry\Amcache.hve --csv %COLLECTION_FOLDER%\RecentExecution\ --csvf Amcache.csv -i >> %COLLECTION_FOLDER%\Collection.log 2>&1

    REM Collecting Each User's Registry Hive (NTUSER.DAT, USRCLASS.DAT)
    echo [+] Collecting Each User's Registry Hive on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting Each User's Registry Hive on %DATE% %TIME% %ESC%%END%
    
    if NOT %OS% == legacy (set USERPATH=%SYSTEM_DRIVE%\Users) else set (USERPATH="%SYSTEM_DRIVE%\Documents and Settings")
    
    REM Change Path To %USERPATH%
    %SYSTEM_DRIVE%
    cd %USERPATH%
    
    REM Start collecting ntuser.dat and usrclass.dat
    for /f "tokens=*" %%i in ('dir /ah /b /s NTUSER.DAT.*') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
        if not exist %COLLECTION_FOLDER%\Registry\%%j (
            mkdir %COLLECTION_FOLDER%\Registry\%%j
            mkdir %COLLECTION_FOLDER%\Registry\%%j\Shellbags            
        )
        %COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:%%i /OutputPath:%COLLECTION_FOLDER%\Registry\%%j\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    )
    
    for /f "tokens=*" %%i in ('dir /ah /b /s UsrClass.dat.*') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
        
        %COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:%%i /OutputPath:%COLLECTION_FOLDER%\Registry\%%j\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %ANALYSISTOOLS_FOLDER%\SBECmd.exe -d %COLLECTION_FOLDER%\Registry\%%j\ --csv %COLLECTION_FOLDER%\Registry\%%j\Shellbags -q >> %COLLECTION_FOLDER%\Collection.log 2>&1
    )
    call %SCRIPT_DRIVE%\Windows\Scripts\RegRipper_Script.bat %CASE_NAME%

    REM Collecting Each User's Recent Folder
    echo [+] Collecting Each User's Recent Folder on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting Each User's Recent Folder on %DATE% %TIME% %ESC%%END%
        
    for /f "tokens=*" %%i in ('dir /ah /b /s Recent') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
        if not exist %COLLECTION_FOLDER%\Recent\%%j (
            mkdir %COLLECTION_FOLDER%\Recent\%%j
            mkdir %COLLECTION_FOLDER%\Recent\%%j\JLECmd-output
            %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %%i %COLLECTION_FOLDER%\Recent\%%j /ZB /copy:DAT /r:0 /ts /FP /np /E /A-:SH >> %COLLECTION_FOLDER%\Collection.log 2>&1
            %ANALYSISTOOLS_FOLDER%\JLECmd.exe -d %COLLECTION_FOLDER%\Recent\%%j\AutomaticDestinations --csv %COLLECTION_FOLDER%\Recent\%%j\JLECmd-output --csvf JLECmd_AutomaticDestinations.csv -q >> %COLLECTION_FOLDER%\Collection.log 2>&1
            %ANALYSISTOOLS_FOLDER%\JLECmd.exe -d %COLLECTION_FOLDER%\Recent\%%j\CustomDestinations --csv %COLLECTION_FOLDER%\Recent\%%j\JLECmd-output --csvf JLECmd_CustomDestinations.csv -q >> %COLLECTION_FOLDER%\Collection.log 2>&1
        )
    )
    
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
        %ANALYSISTOOLS_FOLDER%\WxTCmd.exe -f ActivitiesCache.db --csv %COLLECTION_FOLDER%\ActivitiesCache\%%j\WxT-output >> %COLLECTION_FOLDER%\Collection.log 2>&1
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
    
    call %SCRIPT_DRIVE%\Windows\Scripts\EvtxECmd_Script.bat %CASE_NAME%
    
    REM Collecting MBR
    echo [+] Collecting MBR on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting MBR on %DATE% %TIME% %ESC%%END%
    
    %COLLECTFILESTOOLS_FOLDER%\dd.exe if=\\.\PhysicalDrive0 of=%COLLECTION_FOLDER%\MBR\%CASE_NAME%_MBR.dump bs=512 count=32 >> %COLLECTION_FOLDER%\Collection.log 2>&1

    REM Collecting $MFT and parsing to csv
    echo [+] Collecting $MFT, $LogFile and parsing to csv on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting MFT, LogFile, UsnJrnl and parsing to csv on %DATE% %TIME% %ESC%%END%
    
    %COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%0 /OutputPath:%COLLECTION_FOLDER%\NTFS\ /OutputName:%CASE_NAME%_$MFT >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %ANALYSISTOOLS_FOLDER%\MFTECmd.exe -f %COLLECTION_FOLDER%\NTFS\%CASE_NAME%_$MFT --csv %COLLECTION_FOLDER%\NTFS --csvf %CASE_NAME%_MFT.csv >> %COLLECTION_FOLDER%\Collection.log 2>&1

    REM Collecting $LogFile
    %COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%2 /OutputPath:%COLLECTION_FOLDER%\NTFS\ /OutputName:%CASE_NAME%_$LogFile >> %COLLECTION_FOLDER%\Collection.log 2>&1
    
    REM Collecting $UsnJrnl and parsing to csv
    %COLLECTFILESTOOLS_FOLDER%\ExtractUsnJrnl\ExtractUsnJrnl64.exe /DevicePath:%SYSTEM_DRIVE% /OutputPath:%COLLECTION_FOLDER%\NTFS\ /OutputName:%CASE_NAME%_$J >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %ANALYSISTOOLS_FOLDER%\MFTECmd.exe -f %COLLECTION_FOLDER%\NTFS\%CASE_NAME%_$J --csv %COLLECTION_FOLDER%\NTFS --csvf %CASE_NAME%_J.csv >> %COLLECTION_FOLDER%\Collection.log 2>&1
    
    REM Collecting AppCompatCache Information
    echo [+] Collecting AppCompatCache Information on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting AppCompatCache Information on %DATE% %TIME% %ESC%%END%
    
    %ANALYSISTOOLS_FOLDER%\AppCompatCacheParser.exe -t -f %COLLECTION_FOLDER%\Registry\SYSTEM --csv %COLLECTION_FOLDER%\RecentExecution\ --csvf AppCompatCacheParser_output.csv >> %COLLECTION_FOLDER%\Collection.log 2>&1
    
    REM Collecting Prefetch File
    echo [+] Collecting Prefetch File on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting Prefetch File on %DATE% %TIME% %ESC%%END%
    
    %ANALYSISTOOLS_FOLDER%\PECmd.exe -d %SYSTEM_DRIVE%\Windows\Prefetch --csv %COLLECTION_FOLDER%\Prefetch --csvf %CASE_NAME%_pf.csv -q >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %ANALYSISTOOLS_FOLDER%\winprefetchview\x64\WinPrefetchView.exe /sort "Last Run Time" /scomma %COLLECTION_FOLDER%\Prefetch\%CASE_NAME%_Prefetch.csv >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %SYSTEM_DRIVE%\Windows\Prefetch %COLLECTION_FOLDER%\Prefetch\ *.pf /ZB /copy:DAT /r:0 /ts /FP /np >> %COLLECTION_FOLDER%\Collection.log 2>&1
    
    REM Collecting Web Servers logs
    echo [+] Collecting Web Servers logs on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting Web Servers logs on %DATE% %TIME% %ESC%%END%
    
    %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %SYSTEM_DRIVE%\inetpub\logs\LogFiles\ %COLLECTION_FOLDER%\WebServer\ *.log /E /ZB /copy:DAT /r:0 /ts /FP /np >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %SYSTEM_DRIVE%\Windows\nginx\logs\ %COLLECTION_FOLDER%\WebServer\ *.log /E /ZB /copy:DAT /r:0 /ts /FP /np >> %COLLECTION_FOLDER%\Collection.log 2>&1
    
    REM Collecting Sign Information
    echo [+] Collecting Sign InformSation on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting Sign InformSation on %DATE% %TIME% %ESC%%END%
    
    "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -w %COLLECTION_FOLDER%\SignInfo\%CASE_NAME%_Windows_exe.csv %SYSTEM_DRIVE%\Windows\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -w %COLLECTION_FOLDER%\SignInfo\%CASE_NAME%_Windows_dll.csv %SYSTEM_DRIVE%\Windows\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -w %COLLECTION_FOLDER%\SignInfo\%CASE_NAME%_System32_exe.csv %SYSTEM_DRIVE%\Windows\System32\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -w %COLLECTION_FOLDER%\SignInfo\%CASE_NAME%_System32_dll.csv %SYSTEM_DRIVE%\Windows\System32\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -w %COLLECTION_FOLDER%\SignInfo\%CASE_NAME%_Syswow64_exe.csv %SYSTEM_DRIVE%\Windows\syswow64\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -w %COLLECTION_FOLDER%\SignInfo\%CASE_NAME%_Syswow64_dll.csv %SYSTEM_DRIVE%\Windows\syswow64\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    
    REM Collecting Recycle Bin files
    echo [+] Collecting Recycle Bin files on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting Recycle Bin files on %DATE% %TIME% %ESC%%END%
    
    %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %SYSTEM_DRIVE%\$Recycle.Bin %COLLECTION_FOLDER%\RecycleBin /ZB /copy:DAT /r:0 /ts /FP /np /E /A-:SH >> %COLLECTION_FOLDER%\Collection.log 2>&1

    REM Collecting Windows.edb
    echo [+] Collecting Windows.edb on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting Windows.edb on %DATE% %TIME% %ESC%%END%
    
    %COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb /OutputPath:%COLLECTION_FOLDER%\Windows.edb\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    
    REM Collecting SRUM
    echo [+] Collecting SRUM on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Collecting SRUM on %DATE% %TIME% %ESC%%END%
     
    %COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\sru\SRUDB.dat /OutputPath:%COLLECTION_FOLDER%\SRUM >> %COLLECTION_FOLDER%\Collection.log 2>&1
    
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
        %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\Microsoft\Windows Defender\Support\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E >> %COLLECTION_FOLDER%\Collection.log 2>&1
    )
    
    REM Scan common directories where malware hide in
    echo [+] Scan common directories where malware hide in on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%Y%[+] Scan common directories where malware hide in on %DATE% %TIME% %ESC%%END%
    
    "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_RecycleBin_exe.csv C:\$Recycle.bin\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_RecycleBin_dll.csv C:\$Recycle.bin\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_Recycler_exe.csv C:\RECYCLER\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_Recycler_dll.csv C:\RECYCLER\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_PerfLogs_exe.csv C:\PerfLogs\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_PerfLogs_dll.csv C:\PerfLogs\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_Temp_exe.csv C:\Windows\Temp\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_Temp_dll.csv C:\Windows\Temp\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_INF_exe.csv C:\Windows\INF\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_INF_dll.csv C:\Windows\INF\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_Help_exe.csv C:\Windows\Help\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_Help_dll.csv C:\Windows\Help\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_Font_exe.csv C:\Windows\Font\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_Font_dll.csv C:\Windows\Font\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_ProgramData_exe.csv C:\ProgramData\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_ProgramData_dll.csv C:\ProgramData\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_Intel_exe.csv C:\Intel\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    "%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_Intel_dll.csv C:\Intel\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
       
    echo [+] Finished collecting for %CASE_NAME% on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
    echo %ESC%%P%[+] Finished collecting for %CASE_NAME% on %DATE% %TIME% %ESC%%END%
    
) else echo %ESC%%P%[-] %CASE_NAME% has already collected. %ESC%%END%

pause