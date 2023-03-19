@echo off
:: --------------------------------------------------------------------------------------------------------------------------
:: Name:     RegRipper_Script.cmd
:: Purpose:  Parse registry hive.
:: Author:   FS FANG
:: Version:  1.0.3
:: Revision: Oct 2020 v1.0.0 - initial version
::           Dec 2020 v1.0.1 - add:    create collection folder automatically
::                             modify: parse each user's NTUSER.DAT, UsrClass
::           Nov 2021 v1.0.2 - modify: could be called by DF_Script.cmd
::           Mar 2023 v1.0.3 - add:    process hive transaction logs via registryFlush.exe
::                             modify: improved display of messages
:: --------------------------------------------------------------------------------------------------------------------------
:: --------------------------------------------------------------------------------------------------------------------------
:: Set Setting Script Variables
:: --------------------------------------------------------------------------------------------------------------------------
REM Define Script Header and Usage
:header
call :setESC

echo.
echo %ESC%%G%RegRipper_Script v1.0.3 %ESC%%END%
echo %ESC%%G%Developed by: FS FANG %ESC%%END%
echo %ESC%%G%Parses Registry Hive %ESC%%END%
echo.
set CASE_NAME=%1

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
REM Setting Batch Script Drive
set SCRIPT_PATH=%~d0

REM Setting rip.exe Path
set RIP_FOLDER=%SCRIPT_PATH%\Windows\Tools\EvidenceAnalysis\RegRipper3.0-master

REM Setting Directory to process that contains registry hive
set REG_FOLDER=%SCRIPT_PATH%\Collection_%CASE_NAME%\Registry

REM Setting Parse Result Path
set PARSE_FOLDER=%SCRIPT_PATH%\Collection_%CASE_NAME%\RegParse
:: --------------------------------------------------------------------------------------------------------------------------
REM change code page number to UTF8
chcp 65001 >nul

echo %ESC%%C%[+] Start running regrip.cmd for %CASE_NAME%

if not exist %PARSE_FOLDER% (
   
    echo %ESC%%C%[+] Creating RegParse Folders for %CASE_NAME% %ESC%%END%
    
    REM Create RegParse Folder
    mkdir %PARSE_FOLDER%
    mkdir %PARSE_FOLDER%\At
    mkdir %PARSE_FOLDER%\SAM
    mkdir %PARSE_FOLDER%\SRUM
    mkdir %PARSE_FOLDER%\UserActivity
    mkdir %PARSE_FOLDER%\AppCompatCache
    mkdir %PARSE_FOLDER%\WindowsPrefetch
    mkdir %PARSE_FOLDER%\SystemConfiguration
    mkdir %PARSE_FOLDER%\SoftwareExecutedHistory
    
    REM Recording the time and date of the registry parsing
    echo [+] Logging initiated for %CASE_NAME% on %DATE% %TIME% > %PARSE_FOLDER%\RegParse.log
    echo %ESC%%C%[+] Logging initiated for %CASE_NAME% on %DATE% %TIME% %ESC%%END%
    
    REM Processing hive transaction logs
    echo [+] Processing hive transaction logs on %DATE% %TIME% >> %PARSE_FOLDER%\RegParse.log
    echo %ESC%%C%[+] Processing hive transaction logs on %DATE% %TIME% %ESC%%END%
    
    %RIP_FOLDER%\registryFlush.exe -f %REG_FOLDER%\SAM --overwrite >> %PARSE_FOLDER%\RegParse.log 2>&1
    %RIP_FOLDER%\registryFlush.exe -f %REG_FOLDER%\SOFTWARE --overwrite >> %PARSE_FOLDER%\RegParse.log 2>&1
    %RIP_FOLDER%\registryFlush.exe -f %REG_FOLDER%\SYSTEM --overwrite >> %PARSE_FOLDER%\RegParse.log 2>&1
    %RIP_FOLDER%\registryFlush.exe -f %REG_FOLDER%\SECURITY --overwrite >> %PARSE_FOLDER%\RegParse.log 2>&1

    REM Parsing the SAM hive file for user/group membership info       
    echo [+] Parsing User/Group Membership Info on %DATE% %TIME% >> %PARSE_FOLDER%\RegParse.log
    echo %ESC%%C%[+] Parsing User/Group Membership Info on %DATE% %TIME% %ESC%%END%
        
    %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SAM -p samparse > %PARSE_FOLDER%\SAM\samparse.txt 2>&1
    
    REM Parsing System Configuration
    echo [+] Parsing System Configuration on %DATE% %TIME% >> %PARSE_FOLDER%\RegParse.log
    echo %ESC%%C%[+] Parsing System Configuration on %DATE% %TIME% %ESC%%END%
        
    REM TimeZoneInformation 
    %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SYSTEM -p timezone > %PARSE_FOLDER%\SystemConfiguration\timezone.txt 2>&1

    REM winver
    %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SOFTWARE -p winver > %PARSE_FOLDER%\SystemConfiguration\winver.txt 2>&1

    REM installer
    %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SOFTWARE -p installer > %PARSE_FOLDER%\SystemConfiguration\installer.txt 2>&1

    REM networkcards
    %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SOFTWARE -p networkcards > %PARSE_FOLDER%\SystemConfiguration\networkcards.txt 2>&1

    REM nic2
    %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SYSTEM -p nic2 > %PARSE_FOLDER%\SystemConfiguration\NIC.txt 2>&1

    REM networklist
    %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SOFTWARE -p networklist > %PARSE_FOLDER%\SystemConfiguration\networklist.txt 2>&1
       
    echo [+] Parsing System Autostart Programs on %DATE% %TIME% >> %PARSE_FOLDER%\RegParse.log
    echo %ESC%%C%[+] Parsing System Autostart Programs on %DATE% %TIME% %ESC%%END%
            
    REM runonceex
    %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SOFTWARE -p runonceex >> %PARSE_FOLDER%\SystemConfiguration\SystemAutostartPrograms.txt 2>&1

    REM services
    %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SYSTEM -p services > %PARSE_FOLDER%\SystemConfiguration\services.txt 2>&1

    REM Shares of the System
    %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SYSTEM -p shares > %PARSE_FOLDER%\SystemConfiguration\shares.txt 2>&1

    REM Last Shutdown Time
    %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SYSTEM -p shutdown > %PARSE_FOLDER%\SystemConfiguration\shutdown.txt 2>&1
       
    echo [+] Parsing Windows Prefetch on %DATE% %TIME% >> %PARSE_FOLDER%\RegParse.log
    echo %ESC%%C%[+] Parsing Windows Prefetch on %DATE% %TIME% %ESC%%END%
        
    REM prefetch
    %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SYSTEM -p prefetch > %PARSE_FOLDER%\WindowsPrefetch\prefetch.txt 2>&1
      
    echo [+] Parsing AppCompatCache on %DATE% %TIME% >> %PARSE_FOLDER%\RegParse.log
    echo %ESC%%C%[+] Parsing AppCompatCache on %DATE% %TIME% %ESC%%END%
        
    REM AppCompatCache
    %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SYSTEM -p appcompatcache > %PARSE_FOLDER%\AppCompatCache\appcompatcache.txt 2>&1

    REM Shimcache
    %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SYSTEM -p shimcache > %PARSE_FOLDER%\AppCompatCache\shimcache.txt 2>&1
       
    echo [+] Parsing SRUM on %DATE% %TIME% >> %PARSE_FOLDER%\RegParse.log
    echo %ESC%%C%[+] Parsing SRUM on %DATE% %TIME% %ESC%%END%
        
    REM System Resource Usage Monitor
    %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SOFTWARE -p srum > %PARSE_FOLDER%\SRUM\srum.txt 2>&1

    echo [+] Parsing Remote Info on %DATE% %TIME% >> %PARSE_FOLDER%\RegParse.log
    echo %ESC%%C%[+] Parsing Remote Info on %DATE% %TIME% %ESC%%END%
        
    REM remoteaccess
    %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SYSTEM -p remoteaccess > %PARSE_FOLDER%\SoftwareExecutedHistory\remoteaccess.txt 2>&1
    REM termserv
    %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SYSTEM -r %REG_FOLDER%\SOFTWARE -p termserv > %PARSE_FOLDER%\SoftwareExecutedHistory\termserv.txt 2>&1
       
    echo [+] Parsing At/Schtasks Info on %DATE% %TIME% >> %PARSE_FOLDER%\RegParse.log
    echo %ESC%%C%[+] Parsing At/Schtasks Info on %DATE% %TIME% %ESC%%END%
        
    REM at
    %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SOFTWARE -p at > %PARSE_FOLDER%\At\at.txt 2>&1
    REM tasks
    %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SOFTWARE -p tasks > %PARSE_FOLDER%\At\tasks.txt 2>&1
    REM taskcache
    %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SOFTWARE -p taskcache > %PARSE_FOLDER%\At\taskcache.txt 2>&1
    
    REM Parsing Each User's Registry Hive (NTUSER.DAT, USRCLASS.DAT)
        
    echo [+] Parsing Each User's Registry Hive on %DATE% %TIME% >> %PARSE_FOLDER%\RegParse.log
    echo %ESC%%C%[+] Parsing Each User's Registry Hive on %DATE% %TIME% %ESC%%END%
        
    for /f %%i in ('dir /ad /b %REG_FOLDER%\') do (
            
        mkdir %PARSE_FOLDER%\UserActivity\%%i
        
        REM Processing hive transaction logs
        %RIP_FOLDER%\registryFlush.exe -f %REG_FOLDER%\%%i\NTUSER.DAT --overwrite >> %PARSE_FOLDER%\RegParse.log 2>&1
        %RIP_FOLDER%\registryFlush.exe -f %REG_FOLDER%\%%i\UsrClass.DAT --overwrite >> %PARSE_FOLDER%\RegParse.log 2>&1
        
        REM Microsoft OS version
        %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p osversion > %PARSE_FOLDER%\UserActivity\%%i\OSversion.txt 2>&1
        
        REM environment
        %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SYSTEM -r %REG_FOLDER%\%%i\NTUSER.DAT -p environment > %PARSE_FOLDER%\UserActivity\%%i\environment.txt 2>&1
        
        REM run
        %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p run >> %PARSE_FOLDER%\UserActivity\%%i\SystemAutostartPrograms.txt 2>&1
                   
        echo [+] Parsing User Activity on %DATE% %TIME% >> %PARSE_FOLDER%\RegParse.log
        echo %ESC%%C%[+] Parsing User Activity on %DATE% %TIME% %ESC%%END%
            
        REM Search History
        %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p wordwheelquery > %PARSE_FOLDER%\UserActivity\%%i\wordwheelquery.txt 2>&1

        REM Typed Paths
        %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p typedpaths > %PARSE_FOLDER%\UserActivity\%%i\typedpaths.txt 2>&1

        REM typedurls
        %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p typedurls > %PARSE_FOLDER%\UserActivity\%%i\typedurls.txt 2>&1

        REM Recent Docs
        %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p recentdocs > %PARSE_FOLDER%\UserActivity\%%i\recentdocs.txt 2>&1

        REM recentapps
        %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p recentapps > %PARSE_FOLDER%\UserActivity\%%i\recentapps.txt 2>&1

        REM OpenSaveMRU
        %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p comdlg32 > %PARSE_FOLDER%\UserActivity\%%i\comdlg32.txt 2>&1

        REM Last Commands Executed
        %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p runmru > %PARSE_FOLDER%\UserActivity\%%i\runmru.txt 2>&1

        REM UserAssist
        %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p userassist > %PARSE_FOLDER%\UserActivity\%%i\userassist.txt 2>&1

        REM Shell Item Analysis
        REM JumpList
        %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p jumplistdata > %PARSE_FOLDER%\UserActivity\%%i\jumplistdata.txt 2>&1

        REM parse (Vista, Win7/Win2008R2) shell bags
        %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\UsrClass.DAT -p shellbags > %PARSE_FOLDER%\UserActivity\%%i\shellbags.txt 2>&1

        REM shellfolders
        %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p shellfolders > %PARSE_FOLDER%\UserActivity\%%i\shellfolders.txt 2>&1

        REM lastloggedon
        %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SOFTWARE -p lastloggedon > %PARSE_FOLDER%\UserActivity\%%i\lastloggedon.txt 2>&1

        REM mndmru
        %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p mndmru > %PARSE_FOLDER%\UserActivity\%%i\mndmru.txt 2>&1

        REM muicache
        %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -r %REG_FOLDER%\%%i\UsrClass.DAT -p muicache > %PARSE_FOLDER%\UserActivity\%%i\muicache.txt 2>&1

        REM profilelist
        %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SOFTWARE -p profilelist > %PARSE_FOLDER%\UserActivity\%%i\profilelist.txt 2>&1

        REM pslogging
        %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -r %REG_FOLDER%\SOFTWARE -p pslogging > %PARSE_FOLDER%\UserActivity\%%i\pslogging.txt 2>&1
                   
        echo [+] Parsing Software Executed History on %DATE% %TIME% >> %PARSE_FOLDER%\RegParse.log
        echo %ESC%%C%[+] Parsing Software Executed History on %DATE% %TIME% %ESC%%END%
            
        REM putty
        %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p putty > %PARSE_FOLDER%\UserActivity\%%i\putty.txt 2>&1
        
        REM sevenzip
        %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p sevenzip > %PARSE_FOLDER%\UserActivity\%%i\sevenzip.txt 2>&1
        
        REM winrar
        %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p winrar > %PARSE_FOLDER%\UserActivity\%%i\winrar.txt 2>&1
        
        REM winscp
        %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p winscp > %PARSE_FOLDER%\UserActivity\%%i\winscp.txt 2>&1
        
        REM WinZip
        %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p winzip > %PARSE_FOLDER%\UserActivity\%%i\winzip.txt 2>&1
        
        REM tsclient
        %RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p tsclient > %PARSE_FOLDER%\UserActivity\%%i\tsclient.txt 2>&1 
    )
   
    echo [+] Finished Parsing Registry for %CASE_NAME% on %DATE% %TIME% >> %PARSE_FOLDER%\RegParse.log
    echo %ESC%%P%[+] Finished Parsing Registry for %CASE_NAME% on %DATE% %TIME% %ESC%%END%
        
) else echo %ESC%%P%[-] %CASE_NAME% Registry has already parsed. %ESC%%END%
