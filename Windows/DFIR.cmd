::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Name:     DFIR.cmd                                                                           ::
:: Purpose:  An artifacts collection and analysis script based on Windows operating system.     ::
:: Author:   FS FANG                                                                            ::
:: Version:  2.0.0                                                                              ::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
@echo off
goto :init

:header
call :setESC
echo.

echo %ESC%%G%  ____  _____ _____ _____ _____ _____ ____  %ESC%%END% 
echo %ESC%%G% ^|    \^|   __^|     ^| __  ^|     ^|     ^|    \ %ESC%%END%
echo %ESC%%G% ^|  ^|  ^|   __^|-   -^|    -^|   --^| ^| ^| ^|  ^|  ^| Windows Ver. %ESC%%END%
echo %ESC%%G% ^|____/^|__^|  ^|_____^|__^|__^|_____^|_^|_^|_^|____/  v2.0.0  @FFS %ESC%%END%       

echo.
echo %ESC%%C% Developed by: FS FANG %ESC%%END%
echo %ESC%%C% An artifacts collection and analysis script based on Windows operating system. %ESC%%END%
echo.

goto :eof

:setESC
:Console color
set R=[91m
set G=[92m
set Y=[93m
set B=[94m
set P=[95m
set C=[96m
set END=[0m

for /F "tokens=1,2 delims=#" %%a in ('"prompt #$H#$E# & echo on & for %%b in (1) do rem"') do (
  set ESC=%%b
  exit /B 0
)
exit /B 0

:usage
echo  Usage:
echo   %SCRIPT_NAME% [options] [optional argument] 
echo.
echo.  /?, --help           Display help information
echo.  /v, --version        Display version information
echo   /m, --memory         Dump memory when live response
echo.  /l, --live           Run in live response mode. Collect artifacts for incident response investigation
echo   /f, --forensics      Run in forensics mode. Collection artifacts from disk image for investigation
echo   /p, --parse          Analyze artifacts from collection files
echo.
echo  Examples:
echo   %SCRIPT_NAME% /m /l                        Dump physical memory and collect artifacts on local machine
echo   %SCRIPT_NAME% /m /l /p ComputerName        Dump physical memory and collect artifacts with parsing on local machine (.net6 required)
echo   %SCRIPT_NAME% /f F: CaseName /p CaseName   Collecting and parsing artifacts from image mounting drive (F:)
goto :eof

:version
echo.
echo %ESC%%P% %SCRIPT_NAME% - %VERSION% %ESC%%END%
goto :eof

:missing_argument
echo %ESC%%R% [-] Missing Argument %ESC%%END%
call :usage
echo.
goto :eof

:unknown_argument
echo %ESC%%R% [-] Not supported option %ESC%%END%
call :usage
echo.
goto :eof

:init
REM Setting Environment 
set VERSION=2.0.0
set SYSTEM_DRIVE=
set CASE_NAME=

if "%PROCESSOR_ARCHITECTURE%" == "x86" set ARCH=32
if "%PROCESSOR_ARCHITECTURE%" == "AMD64" set ARCH=64

set SCRIPT_DRIVE=%~d0
set SCRIPT_NAME=%~nx0

set COLLECTION_TOOLS=%SCRIPT_DRIVE%\Windows\Tools\EvidenceCollection
set ANALYSIS_TOOLS=%SCRIPT_DRIVE%\Windows\Tools\EvidenceAnalysis

call :header

:validate
set ARG=0
for %%x in (%*) do Set /A ARG+=1
if "%~1" == "/?" set ARG=1 
if "%~1" == "-?" set ARG=1
if %ARG% == 0 goto :missing_argument

:parse
if "%~1"=="" exit /B
if /i "%~1"=="/?"           call :usage & exit /B
if /i "%~1"=="-?"           call :usage & exit /B
if /i "%~1"=="--help"       call :usage & exit /B
if /i "%~1"=="/v"           call :version & exit /B
if /i "%~1"=="-v"           call :version & exit /B
if /i "%~1"=="--version"    call :version & exit /B
if /i "%~1"=="/m"           call :memory & shift & goto :parse
if /i "%~1"=="-m"           call :memory & shift & goto :parse
if /i "%~1"=="--memory"     call :memory & shift & goto :parse
if /i "%~1"=="/l"           call :live & shift & goto :parse
if /i "%~1"=="-l"           call :live & shift & goto :parse
if /i "%~1"=="--live"       call :live & shift & goto :parse
if /i "%~1"=="/f" (
    set SYSTEM_DRIVE=%~2 & set CASE_NAME=%~3
    if not defined SYSTEM_DRIVE (
        goto :missing_argument
    ) else if not defined CASE_NAME (
        goto :missing_argument
    ) else if /i "%~4"=="/p" (
        call :forensics & call :parser & shift & shift & shift & shift & goto :parse
    ) else if /i "%~4"=="-p" (
        call :forensics & call :parser & shift & shift & shift & shift & goto :parse
    ) else if /i "%~4"=="--parse" (
        call :forensics & call :parser & shift & shift & shift & shift & goto :parse
    ) else call :forensics & shift & shift & shift & goto :parse
)
if /i "%~1"=="-f" (
    set SYSTEM_DRIVE=%~2 & set CASE_NAME=%~3
    if not defined SYSTEM_DRIVE (
        goto :missing_argument
    ) else if not defined CASE_NAME (
        goto :missing_argument
    ) else if /i "%~4"=="/p" (
        call :forensics & call :parse & shift & shift & shift & shift & goto :parse
    ) else if /i "%~4"=="-p" (
        call :forensics & call :parse & shift & shift & shift & shift & goto :parse
    ) else if /i "%~4"=="--parse" (
        call :forensics & call :parse & shift & shift & shift & shift & goto :parse
    ) else call :forensics & shift & shift & shift & goto :parse
)
if /i "%~1"=="--forensics" (
    set SYSTEM_DRIVE=%~2 & set CASE_NAME=%~3
    if not defined SYSTEM_DRIVE (
        goto :missing_argument
    ) else if not defined CASE_NAME (
        goto :missing_argument
    ) else if /i "%~4"=="/p" (
        call :forensics & call :parse & shift & shift & shift & shift & goto :parse
    ) else if /i "%~4"=="-p" (
        call :forensics & call :parse & shift & shift & shift & shift & goto :parse
    ) else if /i "%~4"=="--parse" (
        call :forensics & call :parse & shift & shift & shift & shift & goto :parse
    ) else call :forensics & shift & shift & shift & goto :parse
)
if /i "%~1"=="/p" (
    set CASE_NAME=%~2
    if not defined CASE_NAME (
        goto :missing_argument
    ) else call :parser & shift & shift & goto :parse
)
if /i "%~1"=="-p" (
    set CASE_NAME=%~2
    if not defined CASE_NAME (
        goto :missing_argument
    ) else call :parser & shift & shift & goto :parse
)
if /i "%~1"=="--parse" (
    set CASE_NAME=%~2
    if not defined CASE_NAME (
        goto :missing_argument
    ) else call :parser & shift & shift & goto :parse
)

goto :unknown_argument

:legacy
REM XP/2003/2000 (legacy operating system)
ver | find "5.0" > nul
if %ERRORLEVEL% == 0 set OS=legacy
ver | find  "5.1" > nul
if %ERRORLEVEL% == 0 set OS=legacy
ver | find  "5.2" > nul
if %ERRORLEVEL% == 0 set OS=legacy

if not %OS% == legacy (set USERPATH=%SYSTEM_DRIVE%\Users) else set (USERPATH="%SYSTEM_DRIVE%\Documents and Settings")

goto :eof

:dump_memory
REM Dumping Memory
echo [+] Dumping Memory for %CASE_NAME% on %DATE% %TIME% >> %SCRIPT_DRIVE%\Memdump.log
echo %ESC%%Y%[+] Dumping Memory for %CASE_NAME% on %DATE% %TIME% %ESC%%END%

if %ARCH% == 32 (
    %COLLECTION_TOOLS%\winpmem\winpmem_mini_x86.exe %SCRIPT_DRIVE%\%CASE_NAME%_physmem.raw >> %SCRIPT_DRIVE%\Memdump.log 2>&1
)
if %ARCH% == 64 (
    %COLLECTION_TOOLS%\winpmem\winpmem_mini_x64_rc2.exe %SCRIPT_DRIVE%\%CASE_NAME%_physmem.raw >> %SCRIPT_DRIVE%\Memdump.log 2>&1
)
goto :eof

:collect_systeminfo
REM Collecting SystemInfo
echo [+] Collecting SystemInfo on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%Y%[+] Collecting SystemInfo on %DATE% %TIME% %ESC%%END%

systeminfo > %COLLECTION_FOLDER%\%CASE_NAME%_Systeminfo.txt 2>&1
goto :eof

:collect_timeline
REM Making System Timeline
echo [+] Making System Timeline on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%Y%[+] Making System Timeline on %DATE% %TIME% %ESC%%END%

if /i "%SYSTEM_DRIVE%" == "C:" ( 
    for /f "skip=1 delims=" %%i in ('wmic logicaldisk where "DriveType='3'" get DeviceID') do @for /f "tokens=1 delims=:" %%j in ("%%i") do (
        dir %%j:\ /a/s/od/ta > %COLLECTION_FOLDER%\Timeline\%CASE_NAME%_%%j_AccessTime.txt 2>&1
        dir %%j:\ /a/s/od/tc/q > %COLLECTION_FOLDER%\Timeline\%CASE_NAME%_%%j_CreationTime.txt 2>&1
        dir %%j:\ /a/s/od/tw > %COLLECTION_FOLDER%\Timeline\%CASE_NAME%_%%j_WriteTime.txt 2>&1
    )
) else (
    dir %SYSTEM_DRIVE%\ /a/s/od/ta > %COLLECTION_FOLDER%\Timeline\%CASE_NAME%_AccessTime.txt 2>&1
    dir %SYSTEM_DRIVE%\ /a/s/od/tc/q > %COLLECTION_FOLDER%\Timeline\%CASE_NAME%_CreationTime.txt 2>&1
    dir %SYSTEM_DRIVE%\ /a/s/od/tw > %COLLECTION_FOLDER%\Timeline\%CASE_NAME%_WriteTime.txt 2>&1

)
goto :eof

:collect_networkinfo
REM Collecting Network Activity Information
echo [+] Collecting Network Activity Information on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%Y%[+] Collecting Network Activity Information on %DATE% %TIME% %ESC%%END%

ipconfig /all > %COLLECTION_FOLDER%\NetworkInfo\%CASE_NAME%_NIC.txt 2>&1
route print > %COLLECTION_FOLDER%\NetworkInfo\%CASE_NAME%_Route.txt 2>&1
nbtstat -c > %COLLECTION_FOLDER%\NetworkInfo\%CASE_NAME%_NetNameCache.txt 2>&1
nbtstat -rn > %COLLECTION_FOLDER%\NetworkInfo\%CASE_NAME%_NetRoute.txt 2>&1
netstat -ano > %COLLECTION_FOLDER%\NetworkInfo\%CASE_NAME%_NetStat.txt 2>&1
arp.exe -a > %COLLECTION_FOLDER%\NetworkInfo\%CASE_NAME%_Arp.txt 2>&1
net session > %COLLECTION_FOLDER%\NetworkInfo\%CASE_NAME%_Session.txt 2>&1
net share > %COLLECTION_FOLDER%\NetworkInfo\%CASE_NAME%_SharedDrives.txt 2>&1
netsh interface portproxy show all > %COLLECTION_FOLDER%\NetworkInfo\%CASE_NAME%_portproxy.txt 2>&1
if %ARCH% == 32 (
    %COLLECTION_TOOLS%\psfile\psfile.exe /accepteula /nobanner > %COLLECTION_FOLDER%\NetworkInfo\%CASE_NAME%_Openfileremote.txt 2>&1
)
if %ARCH% == 64 (
    %COLLECTION_TOOLS%\psfile\psfile64.exe /accepteula /nobanner > %COLLECTION_FOLDER%\NetworkInfo\%CASE_NAME%_Openfileremote.txt 2>&1
)
%COLLECTION_TOOLS%\promqry.exe > %COLLECTION_FOLDER%\NetworkInfo\%CASE_NAME%_NSniff.txt
goto :eof

:collect_userinfo
REM Collecting User Information, Logon users
echo [+] Collecting User Information, Logon users on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%Y%[+] Collecting User Information, Logon users on %DATE% %TIME% %ESC%%END%

net user > %COLLECTION_FOLDER%\AccountInfo\%CASE_NAME%_AccountInfo.txt
net user Administrator > %COLLECTION_FOLDER%\AccountInfo\%CASE_NAME%_LocalAdminInfo.txt
net localgroup > %COLLECTION_FOLDER%\AccountInfo\%CASE_NAME%_GroupInfo.txt
net localgroup Administrators > %COLLECTION_FOLDER%\AccountInfo\%CASE_NAME%_AdminGroupInfo.txt
if %ARCH% == 32 (
    %COLLECTION_TOOLS%\PsLoggedon\PsLoggedon.exe /accepteula /nobanner > %COLLECTION_FOLDER%\AccountInfo\%CASE_NAME%_LoggedUsers.txt 2>&1
    %COLLECTION_TOOLS%\logonsessions\logonsessions.exe /accepteula /nobanner -p > %COLLECTION_FOLDER%\AccountInfo\%CASE_NAME%_LoggedOnUsers.txt 2>&1
)
if %ARCH% == 64 (
    %COLLECTION_TOOLS%\PsLoggedon\PsLoggedon64.exe /accepteula /nobanner > %COLLECTION_FOLDER%\AccountInfo\%CASE_NAME%_LoggedUsers.txt 2>&1
    %COLLECTION_TOOLS%\logonsessions\logonsessions64.exe /accepteula /nobanner -p > %COLLECTION_FOLDER%\AccountInfo\%CASE_NAME%_LoggedOnUsers.txt 2>&1
)
goto :eof

:collect_processinfo
REM Collecting Running Processes Information
echo [+] Collecting Running Processes Information on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%Y%[+] Collecting Running Processes Information on %DATE% %TIME% %ESC%%END%

tasklist /svc > %COLLECTION_FOLDER%\ProcessInfo\%CASE_NAME%_Taskserv.txt 2>&1
tasklist /v > %COLLECTION_FOLDER%\ProcessInfo\%CASE_NAME%_Taskinfo.txt 2>&1
if %ARCH% == 32 (
    %COLLECTION_TOOLS%\pslist\pslist.exe /accepteula /nobanner /t > %COLLECTION_FOLDER%\ProcessInfo\%CASE_NAME%_Tasktree.txt 2>&1
    %COLLECTION_TOOLS%\Listdlls\Listdlls.exe /accepteula /nobanner -v > %COLLECTION_FOLDER%\ProcessInfo\%CASE_NAME%_Lstdlls.txt 2>&1
    %COLLECTION_TOOLS%\handle\handle.exe /accepteula /nobanner -a > %COLLECTION_FOLDER%\ProcessInfo\%CASE_NAME%_Lsthandles.txt 2>&1
    %COLLECTION_TOOLS%\PsService\PsService.exe /accepteula /nobanner config > %COLLECTION_FOLDER%\ProcessInfo\%CASE_NAME%_Tasklst.txt 2>&1
)
if %ARCH% == 64 (
    %COLLECTION_TOOLS%\pslist\pslist64.exe /accepteula /nobanner /t > %COLLECTION_FOLDER%\ProcessInfo\%CASE_NAME%_Tasktree.txt 2>&1
    %COLLECTION_TOOLS%\Listdlls\Listdlls64.exe /accepteula /nobanner -v > %COLLECTION_FOLDER%\ProcessInfo\%CASE_NAME%_Lstdlls.txt 2>&1
    %COLLECTION_TOOLS%\handle\handle64.exe /accepteula /nobanner -a > %COLLECTION_FOLDER%\ProcessInfo\%CASE_NAME%_Lsthandles.txt 2>&1
    %COLLECTION_TOOLS%\PsService\PsService64.exe /accepteula /nobanner config > %COLLECTION_FOLDER%\ProcessInfo\%CASE_NAME%_Tasklst.txt 2>&1
)
goto :eof

:collect_autorun
REM Collecting :Automatically Start Programs
echo [+] Collecting Automatically Start Programs on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log    
echo %ESC%%Y%[+] Collecting Automatically Start Programs on %DATE% %TIME% %ESC%%END%

if %ARCH% == 32 (
    %COLLECTION_TOOLS%\autoruns\autorunsc.exe /accepteula /nobanner -a * -c -h -s -t * > %COLLECTION_FOLDER%\TaskInfo\%CASE_NAME%_Autoruns.txt 2>&1
    %COLLECTION_TOOLS%\autoruns\Autoruns.exe -e -a %COLLECTION_FOLDER%\TaskInfo\%CASE_NAME%_Autoruns.arn 
)
if %ARCH% == 64 (
    %COLLECTION_TOOLS%\autoruns\autorunsc64.exe /accepteula /nobanner -a * -c -h -s -t * > %COLLECTION_FOLDER%\TaskInfo\%CASE_NAME%_Autoruns.txt 2>&1
    %COLLECTION_TOOLS%\autoruns\Autoruns64.exe -e -a %COLLECTION_FOLDER%\TaskInfo\%CASE_NAME%_Autoruns.arn >> %COLLECTION_FOLDER%\Collection.log 2>&1
)
at > %COLLECTION_FOLDER%\TaskInfo\%CASE_NAME%_At.txt 2>&1
schtasks /query > %COLLECTION_FOLDER%\TaskInfo\%CASE_NAME%_Schtask.txt 2>&1
xcopy %SYSTEM_DRIVE%\Windows\Tasks\* %COLLECTION_FOLDER%\TaskInfo\Tasks\ /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
goto :eof

:collect_registry
REM Collecting Registry (SYSTEM, SOFTWARE, SECURITY, SAM, Amcache and each user's NTUSER.DAT, USRCLASS.DAT)
echo [+] Collecting Registry on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%Y%[+] Collecting Registry on %DATE% %TIME% %ESC%%END%

if %ARCH% == 32 (
    %COLLECTION_TOOLS%\RawCopy\RawCopy.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SYSTEM /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1 
    %COLLECTION_TOOLS%\RawCopy\RawCopy.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SYSTEM.LOG1 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\RawCopy\RawCopy.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SYSTEM.LOG2 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\RawCopy\RawCopy.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SOFTWARE /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\RawCopy\RawCopy.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SOFTWARE.LOG1 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\RawCopy\RawCopy.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SOFTWARE.LOG2 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\RawCopy\RawCopy.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SECURITY /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\RawCopy\RawCopy.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SECURITY.LOG1 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\RawCopy\RawCopy.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SECURITY.LOG2 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\RawCopy\RawCopy.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SAM /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\RawCopy\RawCopy.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SAM.LOG1 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\RawCopy\RawCopy.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SAM.LOG2 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\RawCopy\RawCopy.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\appcompat\Programs\Amcache.hve /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\RawCopy\RawCopy.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\appcompat\Programs\Amcache.hve.LOG1 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\RawCopy\RawCopy.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\appcompat\Programs\Amcache.hve.LOG2 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
) 
if %ARCH% == 64 (
    %COLLECTION_TOOLS%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SYSTEM /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SYSTEM.LOG1 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SYSTEM.LOG2 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SOFTWARE /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SOFTWARE.LOG1 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SOFTWARE.LOG2 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SECURITY /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SECURITY.LOG1 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SECURITY.LOG2 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SAM /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SAM.LOG1 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SAM.LOG2 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\appcompat\Programs\Amcache.hve /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\appcompat\Programs\Amcache.hve.LOG1 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\appcompat\Programs\Amcache.hve.LOG2 /OutputPath:%COLLECTION_FOLDER%\Registry\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
)

REM Change Path To %USERPATH%
%SYSTEM_DRIVE%
cd %USERPATH%

for /f "tokens=*" %%i in ('dir /ah /b /s NTUSER.DAT.*') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
    if not exist %COLLECTION_FOLDER%\Registry\%%j (
        mkdir %COLLECTION_FOLDER%\Registry\%%j 2>>%COLLECTION_FOLDER%\Collection.log
    )
    if %ARCH% == 32 (
        %COLLECTION_TOOLS%\RawCopy\RawCopy.exe /FileNamePath:"%%i" /OutputPath:%COLLECTION_FOLDER%\Registry\%%j\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    )
    if %ARCH% == 64 (
        %COLLECTION_TOOLS%\RawCopy\RawCopy64.exe /FileNamePath:"%%i" /OutputPath:%COLLECTION_FOLDER%\Registry\%%j\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    )
)

for /f "tokens=*" %%i in ('dir /ah /b /s UsrClass.dat.*') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
        
    if %ARCH% == 32 (
        %COLLECTION_TOOLS%\RawCopy\RawCopy.exe /FileNamePath:"%%i" /OutputPath:%COLLECTION_FOLDER%\Registry\%%j\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    )
    if %ARCH% == 64 (
        %COLLECTION_TOOLS%\RawCopy\RawCopy64.exe /FileNamePath:"%%i" /OutputPath:%COLLECTION_FOLDER%\Registry\%%j\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
    )        
)

REM switch back to script path
%SCRIPT_DRIVE%

goto :eof

:collect_recent
REM Collecting Each User's Recent Folder
echo [+] Collecting Each User's Recent Folder on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%Y%[+] Collecting Each User's Recent Folder on %DATE% %TIME% %ESC%%END%

REM Change Path To %USERPATH%
%SYSTEM_DRIVE%
cd %USERPATH%

for /f "tokens=*" %%i in ('dir /ah /b /s Recent') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
    if not exist %COLLECTION_FOLDER%\Recent\%%j (
        mkdir %COLLECTION_FOLDER%\Recent\%%j 2>>%COLLECTION_FOLDER%\Collection.log
        REM xcopy "%%i" %COLLECTION_FOLDER%\Recent\%%j /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
        %COLLECTION_TOOLS%\Robocopy\Robocopy.exe "%%i" %COLLECTION_FOLDER%\Recent\%%j /ZB /copy:DAT /r:0 /ts /FP /np /E /A-:SH >> %COLLECTION_FOLDER%\Collection.log 2>&1
    )
)

%COLLECTION_TOOLS%\lastactivityview\LastActivityView.exe /scomma %COLLECTION_FOLDER%\Recent\%CASE_NAME%_LastActivity.csv >> %COLLECTION_FOLDER%\Collection.log 2>&1
%COLLECTION_TOOLS%\recentfilesview\RecentFilesView.exe /shtml %COLLECTION_FOLDER%\Recent\%CASE_NAME%_RecentFilesView.html /sort ~3 >> %COLLECTION_FOLDER%\Collection.log 2>&1

REM switch back to script path
%SCRIPT_DRIVE%

goto :eof

:collect_bitmapcache
REM Collecting Each User's Bitmap Cache
echo [+] Collecting Each User's Bitmap Cache on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%Y%[+] Collecting Each User's Bitmap Cache on %DATE% %TIME% %ESC%%END%

REM Change Path To %USERPATH%
%SYSTEM_DRIVE%
cd %USERPATH%

for /f "tokens=*" %%i in ('dir /ad /b /s "Terminal Server Client" 2^>^> %COLLECTION_FOLDER%\Collection.log') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
    if not exist %COLLECTION_FOLDER%\BMC\%%j (
        mkdir %COLLECTION_FOLDER%\BMC\%%j 2>>%COLLECTION_FOLDER%\Collection.log
        xcopy "%%i\Cache" %COLLECTION_FOLDER%\BMC\%%j /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1            
    )
)

REM switch back to script path
%SCRIPT_DRIVE%

goto :eof

:collect_powershelllog
REM Collecting Each User's PowerShell Console logs
echo [+] Collecting PowerShell Console logs on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%Y%[+] Collecting PowerShell Console logs on %DATE% %TIME% %ESC%%END%

REM Change Path To %USERPATH%
%SYSTEM_DRIVE%
cd %USERPATH%

for /f "tokens=*" %%i in ('dir /ad /b /s PSReadLine 2^>^> %COLLECTION_FOLDER%\Collection.log') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
    if not exist %COLLECTION_FOLDER%\PowerShell\%%j (
        mkdir %COLLECTION_FOLDER%\PowerShell\%%j 2>>%COLLECTION_FOLDER%\Collection.log
        xcopy %%i\ConsoleHost_history.txt %COLLECTION_FOLDER%\PowerShell\%%j /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
    )
)

REM switch back to script path
%SCRIPT_DRIVE%

goto :eof

:collect_activitiesCache
REM Collecting Each User's timeline ActivitiesCache.db (Win10+)
echo [+] Collecting Win10 timeline ActivitiesCache.db on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%Y%[+] Collecting Win10 timeline ActivitiesCache.db on %DATE% %TIME% %ESC%%END%

REM Change Path To %USERPATH%
%SYSTEM_DRIVE%
cd %USERPATH%

for /f "tokens=*" %%i in ('dir /ad /b /s ConnectedDevicesPlatform 2^>^> %COLLECTION_FOLDER%\Collection.log') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
    if not exist %COLLECTION_FOLDER%\ActivitiesCache\%%j (
        mkdir %COLLECTION_FOLDER%\ActivitiesCache\%%j 2>>%COLLECTION_FOLDER%\Collection.log
        xcopy %%i\L.%%j\* %COLLECTION_FOLDER%\ActivitiesCache\%%j /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
    )
)

REM switch back to script path
%SCRIPT_DRIVE%

goto :eof

:collect_ftplogs
REM Collecting FTP related logs
echo [+] Collecting FTP related logs on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%Y%[+] Collecting FTP related logs on %DATE% %TIME% %ESC%%END%

REM FileZilla Client
for /f "tokens=*" %%i in ('dir /ad /b /s FileZilla* 2^>^> %COLLECTION_FOLDER%\Collection.log') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
    if not exist %COLLECTION_FOLDER%\FTP\%%j (
        mkdir %COLLECTION_FOLDER%\FTP\%%j 2>>%COLLECTION_FOLDER%\Collection.log
        xcopy %%i\*.xml %COLLECTION_FOLDER%\FTP\%%j /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
    )
)

REM FileZilla Server logs
xcopy "%SYSTEM_DRIVE%\Windows\Program Files (x86)\FileZilla Server\Logs\*.log" %COLLECTION_FOLDER%\FTP /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1

REM WinSCP ini file
xcopy %SYSTEM_DRIVE%\Windows\WinSCP.ini %COLLECTION_FOLDER%\FTP /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
goto :eof

:collect_eventlogs
REM Collecting Windows Event Logs
echo [+] Collecting Windows Event Logs on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%Y%[+] Collecting Windows Event Logs on %DATE% %TIME% %ESC%%END%

%COLLECTION_TOOLS%\RawCopy\RawCopy.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\System32\config\AppEvent.Evt /OutputPath:%COLLECTION_FOLDER%\EventLog >> %COLLECTION_FOLDER%\Collection.log 2>&1
%COLLECTION_TOOLS%\RawCopy\RawCopy.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\System32\config\SecEvent.Evt /OutputPath:%COLLECTION_FOLDER%\EventLog >> %COLLECTION_FOLDER%\Collection.log 2>&1
%COLLECTION_TOOLS%\RawCopy\RawCopy.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\System32\config\SysEvent.Evt /OutputPath:%COLLECTION_FOLDER%\EventLog >> %COLLECTION_FOLDER%\Collection.log 2>&1
REM %COLLECTION_TOOLS%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\Windows\System32\winevt\Logs" "%COLLECTION_FOLDER%\EventLog" /ZB /copy:DAT /r:0 /ts /FP /np /E >> %COLLECTION_FOLDER%\Collection.log 2>&1
xcopy %SYSTEM_DRIVE%\Windows\System32\winevt\Logs %COLLECTION_FOLDER%\EventLog /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
goto :eof

:collect_mbr
echo [+] Collecting MBR on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%Y%[+] Collecting MBR on %DATE% %TIME% %ESC%%END%

%COLLECTION_TOOLS%\dd.exe if=\\.\PhysicalDrive0 of=%COLLECTION_FOLDER%\MBR\%CASE_NAME%_MBR.dump bs=512 count=32 >> %COLLECTION_FOLDER%\Collection.log 2>&1
goto :eof

:collect_ntfs
REM Collecting Each Fixed Disk's MFT, $LogFile, $UsnJrnl
echo [+] Collecting Each Fixed Disk's $MFT, $LogFile and parsing to csv on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%Y%[+] Collecting Each Fixed Disk's MFT, LogFile, UsnJrnl and parsing to csv on %DATE% %TIME% %ESC%%END%

if /i "%SYSTEM_DRIVE%"=="%SYSTEMDRIVE%" (
    for /f "skip=1 delims=" %%i in ('wmic logicaldisk where "DriveType='3'" get DeviceID') do @for /f "tokens=1 delims=:" %%j in ("%%i") do (

        if %ARCH% == 32 (
            %COLLECTION_TOOLS%\RawCopy\RawCopy.exe /FileNamePath:%%j:0 /OutputPath:%COLLECTION_FOLDER%\NTFS\ /OutputName:%CASE_NAME%_$MFT_%%j >> %COLLECTION_FOLDER%\Collection.log 2>&1
            %COLLECTION_TOOLS%\RawCopy\RawCopy.exe /FileNamePath:%%j:2 /OutputPath:%COLLECTION_FOLDER%\NTFS\ /OutputName:%CASE_NAME%_$LogFile_%%j >> %COLLECTION_FOLDER%\Collection.log 2>&1
            %COLLECTION_TOOLS%\ExtractUsnJrnl\ExtractUsnJrnl.exe /DevicePath:%%j: /OutputPath:%COLLECTION_FOLDER%\NTFS\ /OutputName:%CASE_NAME%_$J_%%j >> %COLLECTION_FOLDER%\Collection.log 2>&1
        )
        if %ARCH% == 64 (
            %COLLECTION_TOOLS%\RawCopy\RawCopy64.exe /FileNamePath:%%j:0 /OutputPath:%COLLECTION_FOLDER%\NTFS\ /OutputName:%CASE_NAME%_$MFT_%%j >> %COLLECTION_FOLDER%\Collection.log 2>&1
            %COLLECTION_TOOLS%\RawCopy\RawCopy64.exe /FileNamePath:%%j:2 /OutputPath:%COLLECTION_FOLDER%\NTFS\ /OutputName:%CASE_NAME%_$LogFile_%%j >> %COLLECTION_FOLDER%\Collection.log 2>&1
            %COLLECTION_TOOLS%\ExtractUsnJrnl\ExtractUsnJrnl64.exe /DevicePath:%%j: /OutputPath:%COLLECTION_FOLDER%\NTFS\ /OutputName:%CASE_NAME%_$J_%%j >> %COLLECTION_FOLDER%\Collection.log 2>&1
        )
    )
) else (
    %COLLECTION_TOOLS%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%0 /OutputPath:%COLLECTION_FOLDER%\NTFS\ /OutputName:%CASE_NAME%_$MFT_%SYSTEM_DRIVE% >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%2 /OutputPath:%COLLECTION_FOLDER%\NTFS\ /OutputName:%CASE_NAME%_$LogFile_%SYSTEM_DRIVE% >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\ExtractUsnJrnl\ExtractUsnJrnl64.exe /DevicePath:%SYSTEM_DRIVE% /OutputPath:%COLLECTION_FOLDER%\NTFS\ /OutputName:%CASE_NAME%_$J_%SYSTEM_DRIVE% >> %COLLECTION_FOLDER%\Collection.log 2>&1
)

goto :eof

:collect_prefetch
REM Collecting Prefetch File
echo [+] Collecting Prefetch File on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%Y%[+] Collecting Prefetch File on %DATE% %TIME% %ESC%%END%

REM xcopy %SYSTEM_DRIVE%\Windows\Prefetch\*.pf %COLLECTION_FOLDER%\Prefetch\ /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
%COLLECTION_TOOLS%\Robocopy\Robocopy.exe %SYSTEM_DRIVE%\Windows\Prefetch %COLLECTION_FOLDER%\Prefetch\ *.pf /ZB /copy:DAT /r:0 /ts /FP /np >> %COLLECTION_FOLDER%\Collection.log 2>&1

goto :eof

:collect_browserhistory
REM Collecting Browsing history
echo [+] Collecting Browsing History on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%Y%[+] Collecting Browsing History on %DATE% %TIME% %ESC%%END%

if %ARCH% == 32 (
    %COLLECTION_TOOLS%\browsinghistoryview\BrowsingHistoryView.exe /HistorySource 1 /LoadIE 1 /LoadFirefox 1 /LoadChrome 1 /LoadSafari 1 /sort "Visit Time" /scomma %COLLECTION_FOLDER%\BrowsingHistory\%CASE_NAME%_BrowsingHistory.csv
)
if %ARCH% == 64 (
    %COLLECTION_TOOLS%\browsinghistoryview\BrowsingHistoryView64.exe /HistorySource 1 /LoadIE 1 /LoadFirefox 1 /LoadChrome 1 /LoadSafari 1 /sort "Visit Time" /scomma %COLLECTION_FOLDER%\BrowsingHistory\%CASE_NAME%_BrowsingHistory.csv
)
goto :eof

:collect_iisinfo
REM Collecting IIS information (sites, apps, apppools, wps, logfile)
echo [+] IIS is enabled. Sites physical path: >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%G%[+] IIS is enabled. Sites physical path: %ESC%%END%
%SYSTEM_DRIVE%\Windows\system32\inetsrv\appcmd.exe list vdirs /text:physicalPath >> %COLLECTION_FOLDER%\Collection.log 2>&1
for /f "delims=" %%i in ('%SYSTEM_DRIVE%\Windows\system32\inetsrv\appcmd.exe list vdirs /text:physicalPath') do echo %ESC%%G%     %%i %ESC%%END%

echo [+] Collecting IIS info on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%Y%[+] Collecting IIS info on %DATE% %TIME% %ESC%%END%

%SYSTEM_DRIVE%\Windows\system32\inetsrv\appcmd.exe list sites /text:* > %COLLECTION_FOLDER%\IISInfo\%CASE_NAME%_siteInfo.txt 2>&1
%SYSTEM_DRIVE%\Windows\system32\inetsrv\appcmd.exe list apppools /text:* > %COLLECTION_FOLDER%\IISInfo\%CASE_NAME%_apppoolInfo.txt 2>&1
%SYSTEM_DRIVE%\Windows\system32\inetsrv\appcmd.exe list apps /text:* > %COLLECTION_FOLDER%\IISInfo\%CASE_NAME%_appInfo.txt 2>&1
%SYSTEM_DRIVE%\Windows\system32\inetsrv\appcmd.exe list wps > %COLLECTION_FOLDER%\IISInfo\%CASE_NAME%_wpInfo.txt 2>&1
%SYSTEM_DRIVE%\Windows\system32\inetsrv\appcmd.exe list modules > %COLLECTION_FOLDER%\IISInfo\%CASE_NAME%_moduleInfo.txt 2>&1
%SYSTEM_DRIVE%\Windows\system32\inetsrv\appcmd.exe list config /text:* > %COLLECTION_FOLDER%\IISInfo\%CASE_NAME%_configInfo.txt 2>&1

if %ARCH% == 32 (
    %COLLECTION_TOOLS%\RawCopy\RawCopy.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\System32\inetsrv\Config\applicationHost.config /OutputPath:%COLLECTION_FOLDER%\IISInfo\ /OutputName:applicationHost.config >> %COLLECTION_FOLDER%\Collection.log 2>&1
)
if %ARCH% == 64 (
    %COLLECTION_TOOLS%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\System32\inetsrv\Config\applicationHost.config /OutputPath:%COLLECTION_FOLDER%\IISInfo\ /OutputName:applicationHost.config >> %COLLECTION_FOLDER%\Collection.log 2>&1
)

REM sigcheck iis installed modules
for /f "tokens=2 delims=:" %%i in ('%SYSTEM_DRIVE%\Windows\system32\inetsrv\appcmd.exe list config -section:system.webServer/globalModules /text:* ^ ^| findstr "image"') do call :sigcheck %%i

REM copy iis logs
for /f %%i in ('%SYSTEM_DRIVE%\Windows\system32\inetsrv\appcmd.exe list sites /text:logFile.directory') do (
    xcopy %%i %COLLECTION_FOLDER%\IISInfo\ /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
)

:sigcheck
REM For Processing sigcheck iis installed modules
if not [%1] == [] set module=%1
if %ARCH% == 32 (
    %COLLECTION_TOOLS%\sigcheck\sigcheck.exe /accepteula /nobanner -h %module% >> %COLLECTION_FOLDER%\IISInfo\%CASE_NAME%_modulesign.txt 2>&1
)
if %ARCH% == 64 (
    %COLLECTION_TOOLS%\sigcheck\sigcheck64.exe /accepteula /nobanner -h %module% >> %COLLECTION_FOLDER%\IISInfo\%CASE_NAME%_modulesign.txt 2>&1
)
goto :eof

goto :eof

:collect_signinfo
REM Collecting Sign Information
echo [+] Collecting Sign Information on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%Y%[+] Collecting Sign Information on %DATE% %TIME% %ESC%%END%

if %ARCH% == 32 (
    %COLLECTION_TOOLS%\sigcheck\sigcheck.exe /accepteula /nobanner -h -c -w %COLLECTION_FOLDER%\SignInfo\%CASE_NAME%_Windows_exe.csv %SYSTEM_DRIVE%\Windows\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck.exe /accepteula /nobanner -h -c -w %COLLECTION_FOLDER%\SignInfo\%CASE_NAME%_Windows_dll.csv %SYSTEM_DRIVE%\Windows\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck.exe /accepteula /nobanner -h -c -w %COLLECTION_FOLDER%\SignInfo\%CASE_NAME%_System32_exe.csv %SYSTEM_DRIVE%\Windows\System32\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck.exe /accepteula /nobanner -h -c -w %COLLECTION_FOLDER%\SignInfo\%CASE_NAME%_System32_dll.csv %SYSTEM_DRIVE%\Windows\System32\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck.exe /accepteula /nobanner -h -c -w %COLLECTION_FOLDER%\SignInfo\%CASE_NAME%_Syswow64_exe.csv %SYSTEM_DRIVE%\Windows\syswow64\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck.exe /accepteula /nobanner -h -c -w %COLLECTION_FOLDER%\SignInfo\%CASE_NAME%_Syswow64_dll.csv %SYSTEM_DRIVE%\Windows\syswow64\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
)
if %ARCH% == 64 (
    %COLLECTION_TOOLS%\sigcheck\sigcheck64.exe /accepteula /nobanner -h -c -w %COLLECTION_FOLDER%\SignInfo\%CASE_NAME%_Windows_exe.csv %SYSTEM_DRIVE%\Windows\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck64.exe /accepteula /nobanner -h -c -w %COLLECTION_FOLDER%\SignInfo\%CASE_NAME%_Windows_dll.csv %SYSTEM_DRIVE%\Windows\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck64.exe /accepteula /nobanner -h -c -w %COLLECTION_FOLDER%\SignInfo\%CASE_NAME%_System32_exe.csv %SYSTEM_DRIVE%\Windows\System32\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck64.exe /accepteula /nobanner -h -c -w %COLLECTION_FOLDER%\SignInfo\%CASE_NAME%_System32_dll.csv %SYSTEM_DRIVE%\Windows\System32\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck64.exe /accepteula /nobanner -h -c -w %COLLECTION_FOLDER%\SignInfo\%CASE_NAME%_Syswow64_exe.csv %SYSTEM_DRIVE%\Windows\syswow64\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck64.exe /accepteula /nobanner -h -c -w %COLLECTION_FOLDER%\SignInfo\%CASE_NAME%_Syswow64_dll.csv %SYSTEM_DRIVE%\Windows\syswow64\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
)
goto :eof

:collect_recyclebin
REM Collecting Recycle Bin files
echo [+] Collecting Recycle Bin files on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%Y%[+] Collecting Recycle Bin files on %DATE% %TIME% %ESC%%END%

%COLLECTION_TOOLS%\Robocopy\Robocopy.exe %SYSTEM_DRIVE%\$Recycle.Bin %COLLECTION_FOLDER%\RecycleBin /ZB /copy:DAT /r:0 /ts /FP /np /E /A-:SH >> %COLLECTION_FOLDER%\Collection.log 2>&1
%COLLECTION_TOOLS%\Robocopy\Robocopy.exe %SYSTEM_DRIVE%\RECYCLER %COLLECTION_FOLDER%\RecycleBin /ZB /copy:DAT /r:0 /ts /FP /np /E /A-:SH >> %COLLECTION_FOLDER%\Collection.log 2>&1

goto :eof

:collect_winedb
REM Collecting Windows.edb
echo [+] Collecting Windows.edb on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%Y%[+] Collecting Windows.edb on %DATE% %TIME% %ESC%%END%

if %ARCH% == 32 (
    %COLLECTION_TOOLS%\RawCopy\RawCopy.exe /FileNamePath:%SYSTEM_DRIVE%\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb /OutputPath:%COLLECTION_FOLDER%\Windows.edb\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
)
if %ARCH% == 64 (
    %COLLECTION_TOOLS%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb /OutputPath:%COLLECTION_FOLDER%\Windows.edb\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
)
goto :eof

:collect_srum
REM Collecting SRUM
echo [+] Collecting SRUM on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%Y%[+] Collecting SRUM on %DATE% %TIME% %ESC%%END%

if %ARCH% == 32 (
    %COLLECTION_TOOLS%\RawCopy\RawCopy.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\sru\SRUDB.dat /OutputPath:%COLLECTION_FOLDER%\SRUM >> %COLLECTION_FOLDER%\Collection.log 2>&1
)
if %ARCH% == 64 (
    %COLLECTION_TOOLS%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\sru\SRUDB.dat /OutputPath:%COLLECTION_FOLDER%\SRUM >> %COLLECTION_FOLDER%\Collection.log 2>&1
)
goto :eof

:collect_wmi
REM Collecting WMI repository
echo [+] Collecting WMI repository on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%Y%[+] Collecting WMI repository on %DATE% %TIME% %ESC%%END%

xcopy %SYSTEM_DRIVE%\Windows\System32\wbem\Repository %COLLECTION_FOLDER%\WMI /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
xcopy %SYSTEM_DRIVE%\Windows\System32\wbem\AutoRecover %COLLECTION_FOLDER%\WMI /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
xcopy %SYSTEM_DRIVE%\Windows\System32\wbem\*mof %COLLECTION_FOLDER%\WMI /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1

goto :eof

:collect_setupapi
REM Collecting setupapi.log
echo [+] Collecting setupapi.log on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%Y%[+] Collecting setupapi.log on %DATE% %TIME% %ESC%%END%

xcopy %SYSTEM_DRIVE%\Windows\inf\setupapi.dev.*.log %COLLECTION_FOLDER%\USBInfo /C /F /H /Y >> %COLLECTION_FOLDER%\Collection.log 2>&1
goto :eof

:collect_cryptneturlcache
REM Collect CryptnetUrlCache
echo [+] Collecting CryptnetUrlCache on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%Y%[+] Collecting CryptnetUrlCache on %DATE% %TIME% %ESC%%END%

REM Change Path To %USERPATH%
%SYSTEM_DRIVE%
cd %USERPATH%

for /f "tokens=*" %%i in ('dir /ad /b /s CryptnetUrlCache 2^>^> %COLLECTION_FOLDER%\Collection.log') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
    if not exist %COLLECTION_FOLDER%\CryptnetUrlCache\%%j (
        mkdir %COLLECTION_FOLDER%\CryptnetUrlCache\%%j 2>>%COLLECTION_FOLDER%\Collection.log
        xcopy %%i %COLLECTION_FOLDER%\CryptnetUrlCache\%%j /C /F /H /Y /I /R /S >> %COLLECTION_FOLDER%\Collection.log
    )
)

%COLLECTION_TOOLS%\CryptnetUrlCacheParser.exe --useContent -o %COLLECTION_FOLDER%\CryptnetUrlCache\CryptnetUrlCache.csv >> %COLLECTION_FOLDER%\Collection.log

REM switch back to script path
%SCRIPT_DRIVE%

goto :eof

:collect_antiviruslogs
REM Collecting AntiVirus logs
echo [+] Collecting AntiVirus logs on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%Y%[+] Collecting AntiVirus logs on %DATE% %TIME% %ESC%%END%

if %OS% == legacy (
    xcopy "%SYSTEM_DRIVE%\Documents And Settings\All Users\Application Data\Avast Software\Avast\Log\\" %COLLECTION_FOLDER%\Antivirus\ /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
    xcopy "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\AVG\Antivirus\log\" %COLLECTION_FOLDER%\Antivirus\ /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
    xcopy "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\AVG\Antivirus\report\" %COLLECTION_FOLDER%\Antivirus\ /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
    xcopy "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\ESET\ESET NOD32 Antivirus\Logs\\" %COLLECTION_FOLDER%\Antivirus\ /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
    xcopy "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\McAfee\DesktopProtection\\" %COLLECTION_FOLDER%\Antivirus\ /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
    xcopy "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\Sophos\\" %COLLECTION_FOLDER%\Antivirus\ /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
    xcopy "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\Symantec\Symantec Endpoint Protection\Logs\AV\\" %COLLECTION_FOLDER%\Antivirus\ /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
    xcopy "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\Symantec\Symantec Endpoint Protection\Quarantine\\" %COLLECTION_FOLDER%\Antivirus\ /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
) else (   
    xcopy "%SYSTEM_DRIVE%\ProgramData\Avast Software\Avast\Log\\" %COLLECTION_FOLDER%\Antivirus\ /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
    xcopy "%SYSTEM_DRIVE%\ProgramData\Avast Software\Avast\Chest\\" %COLLECTION_FOLDER%\Antivirus\ /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
    xcopy "%SYSTEM_DRIVE%\ProgramData\AVG\Antivirus\log\" %COLLECTION_FOLDER%\Antivirus\ /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
    xcopy "%SYSTEM_DRIVE%\ProgramData\AVG\Antivirus\report\\" %COLLECTION_FOLDER%\Antivirus\ /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
    xcopy "%SYSTEM_DRIVE%\ProgramData\Avira\Antivirus\LOGFILES\\" %COLLECTION_FOLDER%\Antivirus\ /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
    xcopy "%SYSTEM_DRIVE%\ProgramData\ESET\ESET NOD32 Antivirus\Logs\\" %COLLECTION_FOLDER%\Antivirus\ /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
    xcopy "%SYSTEM_DRIVE%\ProgramData\F-Secure\Log\\" %COLLECTION_FOLDER%\Antivirus\ /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
    xcopy "%SYSTEM_DRIVE%\ProgramData\F-Secure\Antivirus\ScheduledScanReports\\" %COLLECTION_FOLDER%\Antivirus\ /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
    xcopy "%SYSTEM_DRIVE%\ProgramData\McAfee\DesktopProtection\\" %COLLECTION_FOLDER%\Antivirus\ /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
    xcopy "%SYSTEM_DRIVE%\ProgramData\McAfee\Endpoint Security\Logs\\" %COLLECTION_FOLDER%\Antivirus\ /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
    xcopy "%SYSTEM_DRIVE%\ProgramData\McAfee\Endpoint Security\Logs_Old\\" %COLLECTION_FOLDER%\Antivirus\ /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
    xcopy "%SYSTEM_DRIVE%\ProgramData\Mcafee\VirusScan\\" %COLLECTION_FOLDER%\Antivirus\ /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
    xcopy "%SYSTEM_DRIVE%\ProgramData\Sophos\\" %COLLECTION_FOLDER%\Antivirus\ /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
    xcopy "%SYSTEM_DRIVE%\ProgramData\Symantec\Symantec Endpoint Protection\\" %COLLECTION_FOLDER%\Antivirus\ /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
    xcopy "%SYSTEM_DRIVE%\ProgramData\Trend Micro\\" %COLLECTION_FOLDER%\Antivirus\ /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
    xcopy "%SYSTEM_DRIVE%\ProgramData\Microsoft\Microsoft AntiMalware\Support\\" %COLLECTION_FOLDER%\Antivirus\ /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
    xcopy "%SYSTEM_DRIVE%\ProgramData\Microsoft\Windows Defender\Support\\" %COLLECTION_FOLDER%\Antivirus\ /E /C /F /H /Y /I /R >> %COLLECTION_FOLDER%\Collection.log 2>&1
)
goto :eof

:collect_susdir
REM Scan common directories where malware hide in
echo [+] Scan common directories where malware hide in on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%Y%[+] Scan common directories where malware hide in on %DATE% %TIME% %ESC%%END%

if %ARCH% == 32 (
    %COLLECTION_TOOLS%\sigcheck\sigcheck.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_RecycleBin_exe.csv %SYSTEM_DRIVE%\$Recycle.bin\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_RecycleBin_dll.csv %SYSTEM_DRIVE%\$Recycle.bin\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_Recycler_exe.csv %SYSTEM_DRIVE%\RECYCLER\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_Recycler_dll.csv %SYSTEM_DRIVE%\RECYCLER\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_PerfLogs_exe.csv %SYSTEM_DRIVE%\PerfLogs\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_PerfLogs_dll.csv %SYSTEM_DRIVE%\PerfLogs\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_Temp_exe.csv %SYSTEM_DRIVE%\Windows\Temp\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_Temp_dll.csv %SYSTEM_DRIVE%\Windows\Temp\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_INF_exe.csv %SYSTEM_DRIVE%\Windows\INF\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_INF_dll.csv %SYSTEM_DRIVE%\Windows\INF\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_Help_exe.csv %SYSTEM_DRIVE%\Windows\Help\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_Help_dll.csv %SYSTEM_DRIVE%\Windows\Help\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_Font_exe.csv %SYSTEM_DRIVE%\Windows\Font\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_Font_dll.csv %SYSTEM_DRIVE%\Windows\Font\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_ProgramData_exe.csv %SYSTEM_DRIVE%\ProgramData\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_ProgramData_dll.csv %SYSTEM_DRIVE%\ProgramData\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_Intel_exe.csv %SYSTEM_DRIVE%\Intel\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_Intel_dll.csv %SYSTEM_DRIVE%\Intel\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
)
if %ARCH% == 64 (
    %COLLECTION_TOOLS%\sigcheck\sigcheck64.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_RecycleBin_exe.csv %SYSTEM_DRIVE%\$Recycle.bin\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck64.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_RecycleBin_dll.csv %SYSTEM_DRIVE%\$Recycle.bin\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck64.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_Recycler_exe.csv %SYSTEM_DRIVE%\RECYCLER\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck64.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_Recycler_dll.csv %SYSTEM_DRIVE%\RECYCLER\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck64.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_PerfLogs_exe.csv %SYSTEM_DRIVE%\PerfLogs\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck64.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_PerfLogs_dll.csv %SYSTEM_DRIVE%\PerfLogs\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck64.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_Temp_exe.csv %SYSTEM_DRIVE%\Windows\Temp\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck64.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_Temp_dll.csv %SYSTEM_DRIVE%\Windows\Temp\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck64.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_INF_exe.csv %SYSTEM_DRIVE%\Windows\INF\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck64.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_INF_dll.csv %SYSTEM_DRIVE%\Windows\INF\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck64.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_Help_exe.csv %SYSTEM_DRIVE%\Windows\Help\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck64.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_Help_dll.csv %SYSTEM_DRIVE%\Windows\Help\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck64.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_Font_exe.csv %SYSTEM_DRIVE%\Windows\Font\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck64.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_Font_dll.csv %SYSTEM_DRIVE%\Windows\Font\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck64.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_ProgramData_exe.csv %SYSTEM_DRIVE%\ProgramData\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck64.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_ProgramData_dll.csv %SYSTEM_DRIVE%\ProgramData\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck64.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_Intel_exe.csv %SYSTEM_DRIVE%\Intel\*.exe >> %COLLECTION_FOLDER%\Collection.log 2>&1
    %COLLECTION_TOOLS%\sigcheck\sigcheck64.exe /accepteula /nobanner -h -c -s -w %COLLECTION_FOLDER%\Suspect\%CASE_NAME%_Intel_dll.csv %SYSTEM_DRIVE%\Intel\*.dll >> %COLLECTION_FOLDER%\Collection.log 2>&1
)
goto :eof

:parse_registry
REM Parsing Registry Hive
echo [+] Parsing Registry for %CASE_NAME% on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing Registry for %CASE_NAME% on %DATE% %TIME% %ESC%%END%

REM Processing hive transaction logs
echo [+] Processing hive transaction logs on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Processing hive transaction logs on %DATE% %TIME% %ESC%%END%

%ANALYSIS_TOOLS%\RegRipper3.0-master\registryFlush.exe -f %COLLECTION_FOLDER%\Registry\SAM --overwrite >> %PARSE_FOLDER%\Parser.log 2>&1
%ANALYSIS_TOOLS%\RegRipper3.0-master\registryFlush.exe -f %COLLECTION_FOLDER%\Registry\SOFTWARE --overwrite >> %PARSE_FOLDER%\Parser.log 2>&1
%ANALYSIS_TOOLS%\RegRipper3.0-master\registryFlush.exe -f %COLLECTION_FOLDER%\Registry\SYSTEM --overwrite >> %PARSE_FOLDER%\Parser.log 2>&1
%ANALYSIS_TOOLS%\RegRipper3.0-master\registryFlush.exe -f %COLLECTION_FOLDER%\Registry\SECURITY --overwrite >> %PARSE_FOLDER%\Parser.log 2>&1

chcp 65001 >nul

mkdir %PARSE_FOLDER%\Registry\SAM
mkdir %PARSE_FOLDER%\Registry\Amcache
mkdir %PARSE_FOLDER%\Registry\Schtasks
mkdir %PARSE_FOLDER%\Registry\USBDevice
mkdir %PARSE_FOLDER%\Registry\UserActivity
mkdir %PARSE_FOLDER%\Registry\SystemConfiguration
mkdir %PARSE_FOLDER%\Registry\SoftwareExecutedHistory

REM Parsing the SAM hive file for user/group info       
echo [+] Parsing User/Group Info on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing User/Group Membership Info on %DATE% %TIME% %ESC%%END%
    
%ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\SAM -p samparse > %PARSE_FOLDER%\Registry\SAM\samparse.txt 2>&1

REM Parsing System Configuration
echo [+] Parsing System Configuration on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing System Configuration on %DATE% %TIME% %ESC%%END%

%ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\SYSTEM -p timezone > %PARSE_FOLDER%\Registry\SystemConfiguration\timezone.txt 2>&1
%ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\SOFTWARE -p winver > %PARSE_FOLDER%\Registry\SystemConfiguration\winver.txt 2>&1
%ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\SYSTEM -p compname > %PARSE_FOLDER%\Registry\SystemConfiguration\compname.txt 2>&1
%ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\SOFTWARE -p installer > %PARSE_FOLDER%\Registry\SystemConfiguration\installer.txt 2>&1
%ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\SYSTEM -p prefetch > %PARSE_FOLDER%\Registry\SystemConfiguration\prefetch.txt 2>&1
%ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\SOFTWARE -p networkcards > %PARSE_FOLDER%\Registry\SystemConfiguration\networkcards.txt 2>&1
%ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\SYSTEM -p nic2 > %PARSE_FOLDER%\Registry\SystemConfiguration\NIC.txt 2>&1
%ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\SOFTWARE -p networklist > %PARSE_FOLDER%\Registry\SystemConfiguration\networklist.txt 2>&1
%ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\SYSTEM -p portproxy > %PARSE_FOLDER%\Registry\SystemConfiguration\portproxy.txt 2>&1
%ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\SOFTWARE -p runonceex >> %PARSE_FOLDER%\Registry\SystemConfiguration\SystemAutostartPrograms.txt 2>&1
%ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\SYSTEM -p services > %PARSE_FOLDER%\Registry\SystemConfiguration\services.txt 2>&1
%ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\SYSTEM -p shares > %PARSE_FOLDER%\Registry\SystemConfiguration\shares.txt 2>&1
%ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\SYSTEM -p shutdown > %PARSE_FOLDER%\Registry\SystemConfiguration\shutdown.txt 2>&1
%ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\SOFTWARE -p srum > %PARSE_FOLDER%\Registry\SRUM\srum.txt 2>&1
%ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\SOFTWARE -p wbem > %PARSE_FOLDER%\Registry\WMI\wbem.txt 2>&1

REM Parsing Software Executed History
echo [+] Parsing Software Executed History on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing Software Executed History on %DATE% %TIME% %ESC%%END%

%ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\SYSTEM -p appcompatcache > %PARSE_FOLDER%\Registry\SoftwareExecutedHistory\appcompatcache.txt 2>&1
%ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\SYSTEM -p shimcache > %PARSE_FOLDER%\Registry\SoftwareExecutedHistory\shimcache.txt 2>&1
%ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\SYSTEM -p remoteaccess > %PARSE_FOLDER%\Registry\SoftwareExecutedHistory\remoteaccess.txt 2>&1
%ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\SYSTEM -r %COLLECTION_FOLDER%\Registry\SOFTWARE -p termserv > %PARSE_FOLDER%\Registry\SoftwareExecutedHistory\termserv.txt 2>&1
%ANALYSIS_TOOLS%\AppCompatCacheParser.exe -f %COLLECTION_FOLDER%\Registry\SYSTEM --nl false -t --csv %PARSE_FOLDER%\Registry\SoftwareExecutedHistory\ --csvf AppCompatCacheParser_output.csv >> %PARSE_FOLDER%\Parser.log 2>&1

REM Parsing Schtasks Information
echo [+] Parsing Schtasks Information on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing Schtasks Information on %DATE% %TIME% %ESC%%END%

%ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\SOFTWARE -p at > %PARSE_FOLDER%\Registry\Schtasks\at.txt 2>&1
%ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\SOFTWARE -p tasks > %PARSE_FOLDER%\Registry\Schtasks\tasks.txt 2>&1
%ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\SOFTWARE -p taskcache > %PARSE_FOLDER%\Registry\Schtasks\taskcache.txt 2>&1

REM Parsing USB Devices Information
echo [+] Parsing USB Devices Information on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing USB Devices Information on %DATE% %TIME% %ESC%%END%

%ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\SYSTEM -p usb > %PARSE_FOLDER%\Registry\USBDevice\usb.txt 2>&1 
%ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\SYSTEM -p usbdevices > %PARSE_FOLDER%\Registry\USBDevice\usbdevices.txt 2>&1 
%ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\SYSTEM -p usbstor > %PARSE_FOLDER%\Registry\USBDevice\usbstor.txt 2>&1 

REM Parsing Each User's Registry Hive (NTUSER.DAT, USRCLASS.DAT) 
echo [+] Parsing Each User's Registry Hive on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing Each User's Registry Hive on %DATE% %TIME% %ESC%%END%
    
for /f %%i in ('dir /ad /b %COLLECTION_FOLDER%\Registry\') do (
        
    mkdir %PARSE_FOLDER%\Registry\UserActivity\%%i
    
    REM Processing hive transaction logs
    %ANALYSIS_TOOLS%\RegRipper3.0-master\registryFlush.exe -f %COLLECTION_FOLDER%\Registry\%%i\NTUSER.DAT --overwrite >> %PARSE_FOLDER%\Parser.log 2>&1
    %ANALYSIS_TOOLS%\RegRipper3.0-master\registryFlush.exe -f %COLLECTION_FOLDER%\Registry\%%i\UsrClass.DAT --overwrite >> %PARSE_FOLDER%\Parser.log 2>&1
    
    %ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\%%i\NTUSER.DAT -p osversion > %PARSE_FOLDER%\Registry\UserActivity\%%i\OSversion.txt 2>&1
    %ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\SYSTEM -r %COLLECTION_FOLDER%\Registry\%%i\NTUSER.DAT -p environment > %PARSE_FOLDER%\Registry\UserActivity\%%i\environment.txt 2>&1
    %ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\%%i\NTUSER.DAT -p run >> %PARSE_FOLDER%\Registry\UserActivity\%%i\SystemAutostartPrograms.txt 2>&1
    %ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\%%i\NTUSER.DAT -p wordwheelquery > %PARSE_FOLDER%\Registry\UserActivity\%%i\wordwheelquery.txt 2>&1
    %ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\%%i\NTUSER.DAT -p typedpaths > %PARSE_FOLDER%\Registry\UserActivity\%%i\typedpaths.txt 2>&1
    %ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\%%i\NTUSER.DAT -p typedurls > %PARSE_FOLDER%\Registry\UserActivity\%%i\typedurls.txt 2>&1
    %ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\%%i\NTUSER.DAT -p recentdocs > %PARSE_FOLDER%\Registry\UserActivity\%%i\recentdocs.txt 2>&1
    %ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\%%i\NTUSER.DAT -p recentapps > %PARSE_FOLDER%\Registry\UserActivity\%%i\recentapps.txt 2>&1
    %ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\%%i\NTUSER.DAT -p comdlg32 > %PARSE_FOLDER%\Registry\UserActivity\%%i\comdlg32.txt 2>&1
    %ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\%%i\NTUSER.DAT -p runmru > %PARSE_FOLDER%\Registry\UserActivity\%%i\runmru.txt 2>&1
    %ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\%%i\NTUSER.DAT -p userassist > %PARSE_FOLDER%\Registry\UserActivity\%%i\userassist.txt 2>&1
    %ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\%%i\NTUSER.DAT -p jumplistdata > %PARSE_FOLDER%\Registry\UserActivity\%%i\jumplistdata.txt 2>&1
    %ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\%%i\UsrClass.DAT -p shellbags > %PARSE_FOLDER%\Registry\UserActivity\%%i\shellbags.txt 2>&1
    %ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\%%i\NTUSER.DAT -p shellfolders > %PARSE_FOLDER%\Registry\UserActivity\%%i\shellfolders.txt 2>&1
    %ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\SOFTWARE -p lastloggedon > %PARSE_FOLDER%\Registry\UserActivity\%%i\lastloggedon.txt 2>&1
    %ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\%%i\NTUSER.DAT -p mndmru > %PARSE_FOLDER%\Registry\UserActivity\%%i\mndmru.txt 2>&1
    %ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\%%i\NTUSER.DAT -r %COLLECTION_FOLDER%\Registry\%%i\UsrClass.DAT -p muicache > %PARSE_FOLDER%\Registry\UserActivity\%%i\muicache.txt 2>&1
    %ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\SOFTWARE -p profilelist > %PARSE_FOLDER%\Registry\UserActivity\%%i\profilelist.txt 2>&1
    %ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\%%i\NTUSER.DAT -r %COLLECTION_FOLDER%\Registry\SOFTWARE -p pslogging > %PARSE_FOLDER%\Registry\UserActivity\%%i\pslogging.txt 2>&1
    %ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\%%i\NTUSER.DAT -p putty > %PARSE_FOLDER%\Registry\UserActivity\%%i\putty.txt 2>&1
    %ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\%%i\NTUSER.DAT -p sevenzip > %PARSE_FOLDER%\Registry\UserActivity\%%i\sevenzip.txt 2>&1
    %ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\%%i\NTUSER.DAT -p winrar > %PARSE_FOLDER%\Registry\UserActivity\%%i\winrar.txt 2>&1
    %ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\%%i\NTUSER.DAT -p winscp > %PARSE_FOLDER%\Registry\UserActivity\%%i\winscp.txt 2>&1
    %ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\%%i\NTUSER.DAT -p winzip > %PARSE_FOLDER%\Registry\UserActivity\%%i\winzip.txt 2>&1
    %ANALYSIS_TOOLS%\RegRipper3.0-master\rip.exe -r %COLLECTION_FOLDER%\Registry\%%i\NTUSER.DAT -p tsclient > %PARSE_FOLDER%\Registry\UserActivity\%%i\tsclient.txt 2>&1 
)
REM Parsing Amcache.hve
echo [+] Parsing Amcache.hve on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing Amcache.hve on %DATE% %TIME% %ESC%%END%	

%ANALYSIS_TOOLS%\AmcacheParser\AmcacheParser.exe -f %COLLECTION_FOLDER%\Registry\Amcache.hve --csv %PARSE_FOLDER%\Registry\Amcache\ --csvf Amcache.csv -i >> %PARSE_FOLDER%\Parser.log 2>&1

goto :eof

:parse_bmc
REM Parsing Each User's Bitmap Cache
echo [+] Parsing Each User's Bitmap Cache on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing Each User's Bitmap Cache on %DATE% %TIME% %ESC%%END%

for /f %%i in ('dir /ad /b %COLLECTION_FOLDER%\BMC\') do (
  mkdir %PARSE_FOLDER%\BMC\%%i\bmc-tools-output
  %ANALYSIS_TOOLS%\bmc-tools.exe -s %COLLECTION_FOLDER%\BMC\%%i -d %PARSE_FOLDER%\BMC\%%i\bmc-tools-output -b >> %PARSE_FOLDER%\Parser.log 2>&1
)
goto :eof

:parse_activitiescache
REM Parsing Each User's timeline ActivitiesCache.db (Win10+)
echo [+] Parsing Win10 timeline ActivitiesCache.db on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing Win10 timeline ActivitiesCache.db on %DATE% %TIME% %ESC%%END%

for /f %%i in ('dir /ad /b %COLLECTION_FOLDER%\ActivitiesCache\') do (
  mkdir %PARSE_FOLDER%\ActivitiesCache\%%i\WxT-output
  %ANALYSIS_TOOLS%\WxTCmd\WxTCmd.exe -f %COLLECTION_FOLDER%\ActivitiesCache\%%i\ActivitiesCache.db --csv %PARSE_FOLDER%\ActivitiesCache\%%i\WxT-output >> %PARSE_FOLDER%\Parser.log 2>&1
)
goto :eof

:parse_winevt
REM Parsing Windows Event Logs
echo [+] Parsing Windows Event Logs on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing Windows Event Logs on %DATE% %TIME% %ESC%%END%

REM Parse Account Management Events
echo [+] Parsing Account Management Events on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing Account Management Events on %DATE% %TIME% %ESC%%END%

%ANALYSIS_TOOLS%\EvtxECmd\EvtxECmd.exe -f %COLLECTION_FOLDER%\EventLog\Security.evtx --inc 4720,4722,4723,4724,4725,4726,4727,4728,4729,4730,4731,4732,4733,4734,4735,4737,4738,4741,4742,4743,4754,4755,4756,4757,4758,4798,4799 --csv %PARSE_FOLDER%\EventLog --csvf AccountManagement.csv >> %PARSE_FOLDER%\Parser.log 2>&1

REM Parse Account Logon and Logon Events
echo [+] Parsing Account Logon and Logon Events on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing Account Logon and Logon Events on %DATE% %TIME% %ESC%%END%

%ANALYSIS_TOOLS%\EvtxECmd\EvtxECmd.exe -f %COLLECTION_FOLDER%\EventLog\Security.evtx --inc 4624,4625,4634,4647,4648,4672,4778,4779 --csv %PARSE_FOLDER%\EventLog --csvf AccountLogon.csv >> %PARSE_FOLDER%\Parser.log 2>&1

REM Parse Access to Shared Objects Events
echo [+] Parsing Access to Shared Objects Events on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing Access to Shared Objects Events on %DATE% %TIME% %ESC%%END%

%ANALYSIS_TOOLS%\EvtxECmd\EvtxECmd.exe -f %COLLECTION_FOLDER%\EventLog\Security.evtx --inc 5140,5142,5143,5144,5145 --csv %PARSE_FOLDER%\EventLog --csvf NetworkShare.csv >> %PARSE_FOLDER%\Parser.log 2>&1

REM Parse Scheduled task activity Events
echo [+] Parsing Scheduled task activity Events on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing Scheduled task activity Events on %DATE% %TIME% %ESC%%END%

%ANALYSIS_TOOLS%\EvtxECmd\EvtxECmd.exe -f %COLLECTION_FOLDER%\EventLog\Microsoft-Windows-TaskScheduler%%4Operational.evtx --inc 106,140,141,200,201 --csv %PARSE_FOLDER%\EventLog --csvf TaskScheduler.csv >> %PARSE_FOLDER%\Parser.log 2>&1
%ANALYSIS_TOOLS%\EvtxECmd\EvtxECmd.exe -f %COLLECTION_FOLDER%\EventLog\Security.evtx --inc 4698,4699,4700,4701,4702 --csv %PARSE_FOLDER%\EventLog --csvf ObjectAccess.csv >> %PARSE_FOLDER%\Parser.log 2>&1

REM Parse Object Handle Auditing Events
echo [+] Parsing Object Handle Events on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing Object Handle Events on %DATE% %TIME% %ESC%%END%

%ANALYSIS_TOOLS%\EvtxECmd\EvtxECmd.exe -f %COLLECTION_FOLDER%\EventLog\Security.evtx --inc 4656,4657,4658,4660,4663 --csv %PARSE_FOLDER%\EventLog --csvf ObjectHandle.csv >> %PARSE_FOLDER%\Parser.log 2>&1

REM Parse Policy Changes Auditing Event
echo [+] Parsing Audit Policy Changes Events on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing Audit Policy Changes Events on %DATE% %TIME% %ESC%%END%

%ANALYSIS_TOOLS%\EvtxECmd\EvtxECmd.exe -f %COLLECTION_FOLDER%\EventLog\Security.evtx --inc 4719,1102 --csv %PARSE_FOLDER%\EventLog --csvf AuditPolicyChange.csv >> %PARSE_FOLDER%\Parser.log 2>&1
%ANALYSIS_TOOLS%\EvtxECmd\EvtxECmd.exe -f %COLLECTION_FOLDER%\EventLog\System.evtx --inc 104 --csv %PARSE_FOLDER%\EventLog --csvf AuditPolicyChange_System.csv >> %PARSE_FOLDER%\Parser.log 2>&1

REM Parse Windows Services Auditing Event
echo [+] Parsing Audit Windows Services Events on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing Audit Windows Services Events on %DATE% %TIME% %ESC%%END%

%ANALYSIS_TOOLS%\EvtxECmd\EvtxECmd.exe -f %COLLECTION_FOLDER%\EventLog\Security.evtx --inc 6005,6006,7034,7036,7040,7045,4697 --csv %PARSE_FOLDER%\EventLog --csvf AuditWindowsService.csv >> %PARSE_FOLDER%\Parser.log 2>&1

REM Parse WiFi Connection Event
echo [+] Parsing WiFi Connection Events on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing WiFi Connection Events on %DATE% %TIME% %ESC%%END%

%ANALYSIS_TOOLS%\EvtxECmd\EvtxECmd.exe -f %COLLECTION_FOLDER%\EventLog\Security.evtx --inc 8001,8002 --csv %PARSE_FOLDER%\EventLog --csvf WirelessLAN.csv >> %PARSE_FOLDER%\Parser.log 2>&1

REM Parse Process Tracking Event
::  Enable Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Audit Policy -> Audit process tracking and
::		   Computer Configuration -> Administrative Templates -> System -> Audit Process Creation -> Include command line in process creation events

echo [+] Parsing Process Tracking Events on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing Process Tracking Events on %DATE% %TIME% %ESC%%END%

%ANALYSIS_TOOLS%\EvtxECmd\EvtxECmd.exe -f %COLLECTION_FOLDER%\EventLog\Security.evtx --inc 4688,5031,5152,5154,5156,5157,5158,5159 --csv %PARSE_FOLDER%\EventLog --csvf TrackProcess.csv >> %PARSE_FOLDER%\Parser.log 2>&1

REM Parse Program Execution Event	
echo [+] Parsing Program Execution Events on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing Program Execution Events on %DATE% %TIME% %ESC%%END%

%ANALYSIS_TOOLS%\EvtxECmd\EvtxECmd.exe -f "%COLLECTION_FOLDER%\EventLog\Microsoft-Windows-AppLocker%%4EXE and DLL.evtx" --csv %PARSE_FOLDER%\EventLog --csvf AppLocker.csv >> %PARSE_FOLDER%\Parser.log 2>&1

REM Parse Sysmon Event
echo [+] Parsing Sysmon Events on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing Sysmon Events on %DATE% %TIME% %ESC%%END%

%ANALYSIS_TOOLS%\EvtxECmd\EvtxECmd.exe -f %COLLECTION_FOLDER%\EventLog\Microsoft-Windows-Sysmon%%4Operational.evtx --inc 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,255 --csv %PARSE_FOLDER%\EventLog --csvf Sysmon.csv >> %PARSE_FOLDER%\Parser.log 2>&1

REM Parse PowerShell Event	
echo [+] Parsing PowerShell Events on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing PowerShell Events on %DATE% %TIME% %ESC%%END%

%ANALYSIS_TOOLS%\EvtxECmd\EvtxECmd.exe -f %COLLECTION_FOLDER%\EventLog\Microsoft-Windows-PowerShell%%4Operational.evtx --inc 4103,4104 --csv %PARSE_FOLDER%\EventLog --csvf PowerShell.csv >> %PARSE_FOLDER%\Parser.log 2>&1
%ANALYSIS_TOOLS%\EvtxECmd\EvtxECmd.exe -f "%COLLECTION_FOLDER%\EventLog\Windows PowerShell.evtx" --inc 400,800 --csv %PARSE_FOLDER%\EventLog --csvf PowerShell.csv >> %PARSE_FOLDER%\Parser.log 2>&1
    
REM Parse Windows Defender suspicious Event
echo [+] Parsing Windows Defender suspicious Events on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing Windows Defender suspicious Events on %DATE% %TIME% %ESC%%END%

%ANALYSIS_TOOLS%\EvtxECmd\EvtxECmd.exe -f "%COLLECTION_FOLDER%\EventLog\Microsoft-Windows-Windows Defender%%4Operational.evtx" --inc 1006,1007,1008,1013,1015,1116,1117,1118,1119,5001,5004,5007,5010,5012 --csv %PARSE_FOLDER%\EventLog --csvf WindowsDefender.csv >> %PARSE_FOLDER%\Parser.log 2>&1
%ANALYSIS_TOOLS%\EvtxECmd\EvtxECmd.exe -f "%COLLECTION_FOLDER%\EventLog\Microsoft-Windows-Windows Defender%%4WHC.evtx" --csv %PARSE_FOLDER%\EventLog --csvf WindowsDefenderWHC.csv >> %PARSE_FOLDER%\Parser.log 2>&1
    
REM Parse the Remote Desktop Protocol relative events	
echo [+] Parsing the Remote Desktop Protocol Relation Events on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing the Remote Desktop Protocol Relation Events on %DATE% %TIME% %ESC%%END%

%ANALYSIS_TOOLS%\EvtxECmd\EvtxECmd.exe -f %COLLECTION_FOLDER%\EventLog\Microsoft-Windows-TerminalServices-LocalSessionManager%%4Operational.evtx --inc 21,22,23,24,25,39,40 --csv %PARSE_FOLDER%\EventLog --csvf RDP_LocalSessionManager.csv >> %PARSE_FOLDER%\Parser.log 2>&1
%ANALYSIS_TOOLS%\EvtxECmd\EvtxECmd.exe -f %COLLECTION_FOLDER%\EventLog\Microsoft-Windows-TerminalServices-RemoteConnectionManager%%4Operational.evtx --inc 1149,1158 --csv %PARSE_FOLDER%\EventLog --csvf RDP_RemoteConnectionManager.csv >> %PARSE_FOLDER%\Parser.log 2>&1
%ANALYSIS_TOOLS%\EvtxECmd\EvtxECmd.exe -f %COLLECTION_FOLDER%\EventLog\Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%%4Operational.evtx --inc 131 --csv %PARSE_FOLDER%\EventLog --csvf RdpCoreTS.csv >> %PARSE_FOLDER%\Parser.log 2>&1
%ANALYSIS_TOOLS%\EvtxECmd\EvtxECmd.exe -f %COLLECTION_FOLDER%\EventLog\Security.evtx --inc 4624,4625,4634,4647,4778,4779 --csv %PARSE_FOLDER%\EventLog --csvf RDP_Security.csv >> %PARSE_FOLDER%\Parser.log 2>&1
%ANALYSIS_TOOLS%\EvtxECmd\EvtxECmd.exe -f %COLLECTION_FOLDER%\EventLog\System.evtx --inc 9009 --csv %PARSE_FOLDER%\EventLog --csvf RDP_System.csv >> %PARSE_FOLDER%\Parser.log 2>&1
goto :eof

:parse_ntfs
REM Parsing Fixed Disk's MFT, $LogFile, $UsnJrnl
echo [+] Parsing Each Fixed Disk's $MFT, $LogFile and parsing to csv on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing Each Fixed Disk's MFT, LogFile, UsnJrnl and parsing to csv on %DATE% %TIME% %ESC%%END%

for /f %%i in ('dir /b %COLLECTION_FOLDER%\NTFS\%CASE_NAME%_$MFT_*') do (
    %ANALYSIS_TOOLS%\MFTECmd\MFTECmd.exe -f %COLLECTION_FOLDER%\NTFS\%%i --csv %PARSE_FOLDER%\NTFS --csvf %%i.csv >> %PARSE_FOLDER%\Parser.log 2>&1
)

for /f %%i in ('dir /b %COLLECTION_FOLDER%\NTFS\%CASE_NAME%_$LogFile_*') do (
    %ANALYSIS_TOOLS%\LogFileParser\LogFileParser64.exe /LogFileFile:"%COLLECTION_FOLDER%\NTFS\%%i" /OutputPath:"%PARSE_FOLDER%\NTFS\" /Separator:',' /Unicode:1 >> %PARSE_FOLDER%\Parser.log 2>&1
)

for /f %%i in ('dir /b %COLLECTION_FOLDER%\NTFS\%CASE_NAME%_$J_*') do (
    %ANALYSIS_TOOLS%\MFTECmd\MFTECmd.exe -f %COLLECTION_FOLDER%\NTFS\%%i --csv %PARSE_FOLDER%\NTFS --csvf %%i.csv >> %PARSE_FOLDER%\Parser.log 2>&1
)

goto :eof

:parse_shellbag
REM Parsing Shellbags Information
echo [+] Parsing Shellbags Information on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing Shellbags Information on %DATE% %TIME% %ESC%%END%

%ANALYSIS_TOOLS%\SBECmd\SBECmd.exe -d %COLLECTION_FOLDER%\Registry\ --nl false --csv %PARSE_FOLDER%\Shellbags >> %PARSE_FOLDER%\Parser.log 2>&1

goto :eof

:parse_recent
REM Parsing Each User's Recent Folder
echo [+] Parsing Each User's Recent Folder on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing Each User's Recent Folder on %DATE% %TIME% %ESC%%END%

for /f %%i in ('dir /ad /b %COLLECTION_FOLDER%\Recent\') do (
	mkdir %PARSE_FOLDER%\Recent\%%i\JLECmd-output 2>>%PARSE_FOLDER%\Parser.log
	%ANALYSIS_TOOLS%\JLECmd\JLECmd.exe -d %COLLECTION_FOLDER%\Recent\%%i\AutomaticDestinations --csv %PARSE_FOLDER%\Recent\%%i\JLECmd-output --csvf JLECmd_AutomaticDestinations.csv -q --fd >> %PARSE_FOLDER%\Parser.log 2>&1
    %ANALYSIS_TOOLS%\JLECmd\JLECmd.exe -d %COLLECTION_FOLDER%\Recent\%%i\CustomDestinations --csv %PARSE_FOLDER%\Recent\%%i\JLECmd-output --csvf JLECmd_CustomDestinations.csv -q --fd >> %PARSE_FOLDER%\Parser.log 2>&1
    %ANALYSIS_TOOLS%\LECmd\LECmd.exe -d %COLLECTION_FOLDER%\Recent\%%i\ --csv %PARSE_FOLDER%\Recent\%%i --csvf LECmd-output.csv -q >> %PARSE_FOLDER%\Parser.log 2>&1
)
goto :eof

:parse_prefetch
REM Parsing Prefetch File
echo [+] Parsing Prefetch File on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing Prefetch File on %DATE% %TIME% %ESC%%END%

%ANALYSIS_TOOLS%\PECmd\PECmd.exe -d %COLLECTION_FOLDER%\Prefetch --csv %PARSE_FOLDER%\Prefetch --csvf %CASE_NAME%_pf.csv >> %PARSE_FOLDER%\Parser.log 2>&1

goto :eof

:parse_srum
REM Parsing SRUM
echo [+] Parsing SRUM on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing SRUM on %DATE% %TIME% %ESC%%END%

%ANALYSIS_TOOLS%\SrumECmd\SrumECmd.exe -f %COLLECTION_FOLDER%\SRUM\SRUDB.dat -r %COLLECTION_FOLDER%\Registry\SOFTWARE --csv  %PARSE_FOLDER%\SRUM\ >> %PARSE_FOLDER%\Parser.log 2>&1

goto :eof

:parse_wmi
REM Parsing WMI repository
echo [+] Parsing WMI repository on %DATE% %TIME% >> %COLLECTION_FOLDER%\Parser.log
echo %ESC%%Y%[+] Parsing WMI repository on %DATE% %TIME% %ESC%%END%

REM TODO: parsing wmi

goto :eof


:archive
REM Archiving collection
echo [+] Start archiving for %CASE_NAME% on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%Y%[+] Start archiving for %CASE_NAME% on %DATE% %TIME% %ESC%%END%

if %ARCH% == 32 (
    %COLLECTION_TOOLS%\7z\x86\7za.exe a %SCRIPT_DRIVE%\Collection_%CASE_NAME%.zip %SCRIPT_DRIVE%\Collection_%CASE_NAME%\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
)
if %ARCH% == 64 (
    %COLLECTION_TOOLS%\7z\x64\7za.exe a %SCRIPT_DRIVE%\Collection_%CASE_NAME%.zip %SCRIPT_DRIVE%\Collection_%CASE_NAME%\ >> %COLLECTION_FOLDER%\Collection.log 2>&1
)
goto :eof

:live
REM Set running environment 
set SYSTEM_DRIVE=%SYSTEMDRIVE%
set CASE_NAME=%COMPUTERNAME%
set COLLECTION_FOLDER=%SCRIPT_DRIVE%\Collection_%CASE_NAME%
call :legacy

REM Check if the host have already collected before running
if not exist %COLLECTION_FOLDER% (
    echo %ESC%%P%[+] Start running in live mode for %CASE_NAME% %ESC%%END%
    echo %ESC%%P%[+] Creating Collection Folders for %CASE_NAME% %ESC%%END%

    mkdir %COLLECTION_FOLDER%
    mkdir %COLLECTION_FOLDER%\MBR
    mkdir %COLLECTION_FOLDER%\NTFS
    mkdir %COLLECTION_FOLDER%\AccountInfo
    mkdir %COLLECTION_FOLDER%\EventLog
    mkdir %COLLECTION_FOLDER%\NetworkInfo
    mkdir %COLLECTION_FOLDER%\Prefetch
    mkdir %COLLECTION_FOLDER%\BrowsingHistory
    mkdir %COLLECTION_FOLDER%\PowerShell
    mkdir %COLLECTION_FOLDER%\IISInfo
    mkdir %COLLECTION_FOLDER%\ProcessInfo
    mkdir %COLLECTION_FOLDER%\Registry
    mkdir %COLLECTION_FOLDER%\Recent
    mkdir %COLLECTION_FOLDER%\SignInfo
    mkdir %COLLECTION_FOLDER%\TaskInfo
    mkdir %COLLECTION_FOLDER%\Timeline
    mkdir %COLLECTION_FOLDER%\BMC
    mkdir %COLLECTION_FOLDER%\Windows.edb
    mkdir %COLLECTION_FOLDER%\RecycleBin
    mkdir %COLLECTION_FOLDER%\SRUM
    mkdir %COLLECTION_FOLDER%\WMI
    mkdir %COLLECTION_FOLDER%\FTP
    mkdir %COLLECTION_FOLDER%\USBInfo
    mkdir %COLLECTION_FOLDER%\CryptnetUrlCache
    mkdir %COLLECTION_FOLDER%\Antivirus
    mkdir %COLLECTION_FOLDER%\Suspect
) else echo %ESC%%R%[-] %CASE_NAME% has already collected. %ESC%%END% & exit /B

echo [+] Logging initiated for %CASE_NAME% in live response mode on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%P%[+] Logging initiated for %CASE_NAME% in live response mode on %DATE% %TIME%
call :collect_systeminfo
call :collect_timeline
call :collect_networkinfo
call :collect_userinfo
call :collect_processinfo
call :collect_autorun
call :collect_registry
call :collect_recent
call :collect_bitmapcache
call :collect_powershelllog
call :collect_activitiesCache
call :collect_ftplogs
call :collect_eventlogs
call :collect_mbr
call :collect_ntfs
call :collect_prefetch
call :collect_browserhistory
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\InetStp /v VersionString > %COLLECTION_FOLDER%\IISInfo\%CASE_NAME%_iisVer.txt 2>&1
if %ERRORLEVEL% == 0 (
    call :collect_iisinfo
) else echo %ESC%%G%[-] IIS is disabled %ESC%%END%
call :collect_signinfo
call :collect_recyclebin
call :collect_winedb
call :collect_srum
call :collect_wmi
call :collect_setupapi
call :collect_cryptneturlcache
call :collect_antiviruslogs
call :collect_susdir
echo [+] Finish collecting on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%Y%[+] Finish collecting on %DATE% %TIME% %ESC%%END%
call :archive
echo [+] Finish archiving for %CASE_NAME% on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%P%[+] Finish archiving for %CASE_NAME% on %DATE% %TIME% %ESC%%END%

exit /B

:forensics
REM Set running environment
set COLLECTION_FOLDER=%SCRIPT_DRIVE%\Collection_%CASE_NAME%
set SYSTEM_DRIVE=%SYSTEM_DRIVE
call :legacy

REM Check if the host have already collected before running

if not exist %COLLECTION_FOLDER% (
    echo %ESC%%P%[+] Start running in forensics mode for %CASE_NAME% %ESC%%END%
    echo %ESC%%P%[+] Creating Collection Folders for %CASE_NAME% %ESC%%END%

    mkdir %COLLECTION_FOLDER%
    mkdir %COLLECTION_FOLDER%\MBR
    mkdir %COLLECTION_FOLDER%\NTFS
    mkdir %COLLECTION_FOLDER%\EventLog
    mkdir %COLLECTION_FOLDER%\Prefetch
    mkdir %COLLECTION_FOLDER%\BrowsingHistory
    mkdir %COLLECTION_FOLDER%\PowerShell
    mkdir %COLLECTION_FOLDER%\Registry
    mkdir %COLLECTION_FOLDER%\Recent
    mkdir %COLLECTION_FOLDER%\SignInfo
    mkdir %COLLECTION_FOLDER%\Timeline
    mkdir %COLLECTION_FOLDER%\BMC
    mkdir %COLLECTION_FOLDER%\Windows.edb
    mkdir %COLLECTION_FOLDER%\RecycleBin
    mkdir %COLLECTION_FOLDER%\SRUM
    mkdir %COLLECTION_FOLDER%\WMI
    mkdir %COLLECTION_FOLDER%\FTP
    mkdir %COLLECTION_FOLDER%\USBInfo
    mkdir %COLLECTION_FOLDER%\CryptnetUrlCache
    mkdir %COLLECTION_FOLDER%\Antivirus
    mkdir %COLLECTION_FOLDER%\Suspect
) else echo %ESC%%R%[-] %CASE_NAME% has already collected. %ESC%%END% & exit /B

echo [+] Logging initiated for %CASE_NAME% in forensics mode on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%P%[+] Logging initiated for %CASE_NAME% in forensics mode on %DATE% %TIME%
call :collect_timeline
call :collect_registry
call :collect_recent
call :collect_bitmapcache
call :collect_powershelllog
call :collect_activitiesCache
call :collect_ftplogs
call :collect_eventlogs
call :collect_mbr
call :collect_ntfs
call :collect_prefetch
call :collect_browserhistory
call :collect_signinfo
call :collect_recyclebin
call :collect_winedb
call :collect_srum
call :collect_wmi
call :collect_setupapi
call :collect_cryptneturlcache
call :collect_antiviruslogs
call :collect_susdir
echo [+] Finish collecting for %CASE_NAME% on %DATE% %TIME% >> %COLLECTION_FOLDER%\Collection.log
echo %ESC%%P%[+] Finish collecting for %CASE_NAME% on %DATE% %TIME% %ESC%%END%

exit /B

:memory
REM Set running environment
set SYSTEM_DRIVE=%SYSTEMDRIVE%
set CASE_NAME=%COMPUTERNAME%

echo %ESC%%P%[+] Start dumping memory for %CASE_NAME% %ESC%%END%
echo [+] Logging initiated for %CASE_NAME% in dumping memory mode on %DATE% %TIME% > %SCRIPT_DRIVE%\Memdump.log
echo %ESC%%P%[+] Logging initiated for %CASE_NAME% in dumping memory mode on %DATE% %TIME%

call :dump_memory
exit /B

:parser
REM Set running environment 

set COLLECTION_FOLDER=%SCRIPT_DRIVE%\Collection_%CASE_NAME%
set PARSE_FOLDER=%SCRIPT_DRIVE%\Collection_%CASE_NAME%\@Parsing

if exist %COLLECTION_FOLDER% (
    if not exist %PARSE_FOLDER% (
        echo %ESC%%P%[+] Start running in parser mode for %CASE_NAME% %ESC%%END%
        echo %ESC%%P%[+] Creating Parsing Folders for %CASE_NAME% %ESC%%END%
        
        mkdir %PARSE_FOLDER%
        mkdir %PARSE_FOLDER%\NTFS
        mkdir %PARSE_FOLDER%\EventLog
        mkdir %PARSE_FOLDER%\Prefetch
        mkdir %PARSE_FOLDER%\Registry
        mkdir %PARSE_FOLDER%\Recent
        mkdir %PARSE_FOLDER%\BMC
        mkdir %PARSE_FOLDER%\SRUM
        mkdir %PARSE_FOLDER%\WMI
    ) else echo %ESC%%R%[-] %CASE_NAME% has already parsed. %ESC%%END% & exit /B
) else echo %ESC%%R%[-] %CASE_NAME% has not collected yet. %ESC%%END% & exit /B

echo [+] Logging initiated for %CASE_NAME% in parser mode on %DATE% %TIME% > %PARSE_FOLDER%\Parser.log
echo %ESC%%P%[+] Logging initiated for %CASE_NAME% in parser mode on %DATE% %TIME%
call :parse_registry
call :parse_bmc
call :parse_activitiescache
call :parse_winevt
call :parse_ntfs
call :parse_shellbag
call :parse_recent
call :parse_prefetch
call :parse_srum

echo [+] Finish parsing for %CASE_NAME% on %DATE% %TIME% >> %PARSE_FOLDER%\Parser.log
echo %ESC%%P%[+] Finish parsing for %CASE_NAME% on %DATE% %TIME% %ESC%%END%

exit /B
