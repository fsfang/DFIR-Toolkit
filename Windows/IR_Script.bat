@echo off
:: --------------------------------------------------------------------------------------------------------------------------
:: Name:     IR_Script.cmd
:: Purpose:  Collect artifacts in a incident response case based on Windows operating system.
:: Author:   FS FANG
:: Version:  1.4.5
:: Revision: Sep 2020 v1.0.0 - initial version
::	     	 Oct 2020 v1.0.1 - add:		UsrClass.dat
::	     	 Nov 2020 v1.1.0 - compatible with 32/64-bit operation system
::	  		       		   	   add: 	acquire memory, schtasks Tasks folder, prefetch files
:: 			       		   	   modify:  collect all winevt logs by robocopy
::			       		   	   modify:  collect each user's ntuser.dat, usrclass.dat, and recent folder
::       	 Dec 2020 v1.1.1 - add: 	create collection folder automatically
::			       		   	   modify:	collect each fixed disk's MFT
::	     	 JAN 2021 v1.2.0 - add: 	collect bitmap cache, shellbags, Windows.edb, Recycle Bin files, Amcache.hve and SRUM folder
::	     	 Aug 2021 v1.3.0 - add:		define legacy platform collection procedure
::	     	 Sep 2021 v1.4.0 - add:		collect Antivirus logs, browsing history, web server logs, powershell console logs and FTP related logs
:: 	     	 Nov 2021 v1.4.1 - add:		collect Win10 Timeline ActivitiesCache.db
::	     	 Sep 2022 v1.4.2 - add: 	add Collection.log
::			       		   	   modify:	bug fixes
::	     	 Nov 2022 v1.4.3 - modify:	bug fixes
::	     	 Dec 2022 v1.4.4 - add:		collect and parse UsnJrnl
::			       		   	   modify:	collect each fixed disk's NTFS timeline
::	     	 Jan 2023 v1.4.5 - modify:	digital signature tool replaced 
::	     	 				   modify:	bug fixes
:: --------------------------------------------------------------------------------------------------------------------------
:: --------------------------------------------------------------------------------------------------------------------------
:: Set Setting Script Variables
:: --------------------------------------------------------------------------------------------------------------------------
call :setESC

echo.
echo %ESC%[92m     #############     #####    ###  ######  ############  #######%ESC%[0m
echo %ESC%[92m       ##   ##    #   #       #     ##    #   ##   #     #   #    %ESC%[0m
echo %ESC%[92m      ##   ##     #  ##      #     ##     #  ##   #     #   #    %ESC%[0m
echo %ESC%[92m     ##   #######    ####   #     #######   ##   #    #    #    %ESC%[0m
echo %ESC%[92m    ##   ## ##          #  #     ## ##     ##   ####      #   %ESC%[0m
echo %ESC%[92m   ##   ##  ##         #  #     ##  ##    ##   ##        #   %ESC%[0m
echo %ESC%[92m###### ##   ##   ######    ### ##   ##  ##### ##        ##   %ESC%[0m
echo							      %ESC%[96mv1.4.5 @FFS%ESC%[0m
call :main

:setESC
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

:: --------------------------------------------------------------------------------------------------------------------------
echo --------------------------------------------------------------------------------------------------------------------
echo %DATE% %TIME% - Start running IR_Script.cmd on %COMPUTERNAME%
echo --------------------------------------------------------------------------------------------------------------------

if not exist %COLLECTION_FOLDER% (
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Creating Collection Folders
	echo --------------------------------------------------------------------------------------------------------------------
	REM Create Collection Folder
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
	mkdir %COLLECTION_FOLDER%\sus
	
	REM Recording the time and date of the data collection
	echo [+] Logging initiated for %COMPUTERNAME% > %COLLECTION_FOLDER%\Collection.log
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Recording Collection Time
	echo --------------------------------------------------------------------------------------------------------------------

	echo Log Created at %DATE% %TIME%
	
	REM Collecting SystemInfo
	echo [+] %DATE% %TIME% - Collecting SystemInfo >> %COLLECTION_FOLDER%\Collection.log
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting SystemInfo
	echo --------------------------------------------------------------------------------------------------------------------
	systeminfo > %COLLECTION_FOLDER%\%COMPUTERNAME%_Systeminfo.txt

	REM Making System Timeline
	echo [+] %DATE% %TIME% - Making System Timeline >> %COLLECTION_FOLDER%\Collection.log
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Making System Timeline
	echo --------------------------------------------------------------------------------------------------------------------
	for /f "skip=1 delims=" %%i in ('wmic logicaldisk where "DriveType='3'" get DeviceID') do @for /f "tokens=1 delims=:" %%j in ("%%i") do (	
		dir %%j:\ /a/s/od/ta > %COLLECTION_FOLDER%\Timeline\%COMPUTERNAME%_%%j_AccessTime.txt
		dir %%j:\ /a/s/od/tc/q > %COLLECTION_FOLDER%\Timeline\%COMPUTERNAME%_%%j_CreationTime.txt
		dir %%j:\ /a/s/od/tw > %COLLECTION_FOLDER%\Timeline\%COMPUTERNAME%_%%j_WriteTime.txt
	)
	
	REM Collecting Network Activity Information
	echo [+] %DATE% %TIME% - Collecting Network Activity Information >> %COLLECTION_FOLDER%\Collection.log
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Network Activity Information
	echo --------------------------------------------------------------------------------------------------------------------
	ipconfig /all > %COLLECTION_FOLDER%\NetworkInfo\%COMPUTERNAME%_NIC.txt
	route print > %COLLECTION_FOLDER%\NetworkInfo\%COMPUTERNAME%_Route.txt
	nbtstat -c > %COLLECTION_FOLDER%\NetworkInfo\%COMPUTERNAME%_NetNameCache.txt
	nbtstat -rn > %COLLECTION_FOLDER%\NetworkInfo\%COMPUTERNAME%_NetRoute.txt
	netstat -ano > %COLLECTION_FOLDER%\NetworkInfo\%COMPUTERNAME%_NetStat.txt
	arp.exe -a > %COLLECTION_FOLDER%\NetworkInfo\%COMPUTERNAME%_Arp.txt
	net session > %COLLECTION_FOLDER%\NetworkInfo\%COMPUTERNAME%_Session.txt
	net share > %COLLECTION_FOLDER%\NetworkInfo\%COMPUTERNAME%_SharedDrives.txt
	if %ARCH% == 32 (
		%COLLECTFILESTOOLS_FOLDER%\psfile\psfile.exe /accepteula > %COLLECTION_FOLDER%\NetworkInfo\%COMPUTERNAME%_Openfileremote.txt
	)
	if %ARCH% == 64 (
		%COLLECTFILESTOOLS_FOLDER%\psfile\psfile64.exe /accepteula > %COLLECTION_FOLDER%\NetworkInfo\%COMPUTERNAME%_Openfileremote.txt
	)
	%COLLECTFILESTOOLS_FOLDER%\promqry.exe > %COLLECTION_FOLDER%\NetworkInfo\%COMPUTERNAME%_NSniff.txt

	REM Collecting User Information, Logon users
	echo [+] %DATE% %TIME% - Collecting User Information, Logon users >> %COLLECTION_FOLDER%\Collection.log
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting User Information, Logon users
	echo --------------------------------------------------------------------------------------------------------------------
	net user > %COLLECTION_FOLDER%\AccountInfo\%COMPUTERNAME%_AccountInfo.txt
	net user Administrator > %COLLECTION_FOLDER%\AccountInfo\%COMPUTERNAME%_LocalAdminInfo.txt
	net localgroup > %COLLECTION_FOLDER%\AccountInfo\%COMPUTERNAME%_GroupInfo.txt
	net localgroup Administrators > %COLLECTION_FOLDER%\AccountInfo\%COMPUTERNAME%_AdminGroupInfo.txt
	if %ARCH% == 32 (
		%COLLECTFILESTOOLS_FOLDER%\PsLoggedon\PsLoggedon.exe /accepteula > %COLLECTION_FOLDER%\AccountInfo\%COMPUTERNAME%_LoggedUsers.txt
		%COLLECTFILESTOOLS_FOLDER%\logonsessions\logonsessions.exe /accepteula -p > %COLLECTION_FOLDER%\AccountInfo\%COMPUTERNAME%_LoggedOnUsers.txt
	)
	if %ARCH% == 64 (
		%COLLECTFILESTOOLS_FOLDER%\PsLoggedon\PsLoggedon64.exe /accepteula > %COLLECTION_FOLDER%\AccountInfo\%COMPUTERNAME%_LoggedUsers.txt
		%COLLECTFILESTOOLS_FOLDER%\logonsessions\logonsessions64.exe /accepteula -p > %COLLECTION_FOLDER%\AccountInfo\%COMPUTERNAME%_LoggedOnUsers.txt
	)

	REM Collecting Running Processes Information
	echo [+] %DATE% %TIME% - Collecting Running Processes Information >> %COLLECTION_FOLDER%\Collection.log
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Running Processes Information
	echo --------------------------------------------------------------------------------------------------------------------
	tasklist /svc > %COLLECTION_FOLDER%\ProcessInfo\%COMPUTERNAME%_Taskserv.txt
	tasklist /v > %COLLECTION_FOLDER%\ProcessInfo\%COMPUTERNAME%_Taskinfo.txt
	if %ARCH% == 32 (
		%COLLECTFILESTOOLS_FOLDER%\pslist\pslist.exe /accepteula /t > %COLLECTION_FOLDER%\ProcessInfo\%COMPUTERNAME%_Tasktree.txt
		%COLLECTFILESTOOLS_FOLDER%\Listdlls\Listdlls.exe /accepteula > %COLLECTION_FOLDER%\ProcessInfo\%COMPUTERNAME%_Lstdlls.txt
		%COLLECTFILESTOOLS_FOLDER%\handle\handle.exe /accepteula -a > %COLLECTION_FOLDER%\ProcessInfo\%COMPUTERNAME%_Lsthandles.txt
		%COLLECTFILESTOOLS_FOLDER%\PsService\PsService.exe /accepteula config > %COLLECTION_FOLDER%\ProcessInfo\%COMPUTERNAME%_Tasklst.txt
	)
	if %ARCH% == 64 (
		%COLLECTFILESTOOLS_FOLDER%\pslist\pslist64.exe /accepteula /t > %COLLECTION_FOLDER%\ProcessInfo\%COMPUTERNAME%_Tasktree.txt
		%COLLECTFILESTOOLS_FOLDER%\Listdlls\Listdlls64.exe /accepteula > %COLLECTION_FOLDER%\ProcessInfo\%COMPUTERNAME%_Lstdlls.txt
		%COLLECTFILESTOOLS_FOLDER%\handle\handle64.exe /accepteula -a > %COLLECTION_FOLDER%\ProcessInfo\%COMPUTERNAME%_Lsthandles.txt
		%COLLECTFILESTOOLS_FOLDER%\PsService\PsService64.exe /accepteula config > %COLLECTION_FOLDER%\ProcessInfo\%COMPUTERNAME%_Tasklst.txt
	)

	REM Collecting Automatically Start Programs
	echo [+] %DATE% %TIME% - Collecting Automatically Start Programs >> %COLLECTION_FOLDER%\Collection.log
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Automatically Start Programs
	echo --------------------------------------------------------------------------------------------------------------------
	if %ARCH% == 32 (
		%COLLECTFILESTOOLS_FOLDER%\autoruns\autorunsc.exe /accepteula -a * > %COLLECTION_FOLDER%\TaskInfo\%COMPUTERNAME%_Autoruns.txt
		%COLLECTFILESTOOLS_FOLDER%\autoruns\Autoruns.exe /accepteula -e -a %COLLECTION_FOLDER%\TaskInfo\%COMPUTERNAME%_Autoruns.arn 
	)
	if %ARCH% == 64 (
		%COLLECTFILESTOOLS_FOLDER%\autoruns\autorunsc64.exe /accepteula -a * > %COLLECTION_FOLDER%\TaskInfo\%COMPUTERNAME%_Autoruns.txt
		%COLLECTFILESTOOLS_FOLDER%\autoruns\Autoruns64.exe /accepteula -e -a %COLLECTION_FOLDER%\TaskInfo\%COMPUTERNAME%_Autoruns.arn 
	)
	at > %COLLECTION_FOLDER%\TaskInfo\%COMPUTERNAME%_At.txt
	schtasks /query > %COLLECTION_FOLDER%\TaskInfo\%COMPUTERNAME%_Schtask.txt
	%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %SYSTEM_DRIVE%\Windows\Tasks %COLLECTION_FOLDER%\TaskInfo\Tasks\ /ZB /copy:DAT /r:0 /ts /FP /np

	REM Collecting Registry
	echo [+] %DATE% %TIME% - Collecting Registry >> %COLLECTION_FOLDER%\Collection.log
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Registry
	echo --------------------------------------------------------------------------------------------------------------------
	
	if %ARCH% == 32 (
		"%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SYSTEM /OutputPath:%COLLECTION_FOLDER%\Registry\
		"%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SOFTWARE /OutputPath:%COLLECTION_FOLDER%\Registry\
		"%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SECURITY /OutputPath:%COLLECTION_FOLDER%\Registry\
		"%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SAM /OutputPath:%COLLECTION_FOLDER%\Registry\
	) 
	if %ARCH% == 64 (
		"%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SYSTEM /OutputPath:%COLLECTION_FOLDER%\Registry\
		"%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SOFTWARE /OutputPath:%COLLECTION_FOLDER%\Registry\
		"%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SECURITY /OutputPath:%COLLECTION_FOLDER%\Registry\
		"%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SAM /OutputPath:%COLLECTION_FOLDER%\Registry\
	)
	
	REM Collecting Amcache.hve
	echo [+] %DATE% %TIME% - Collecting Amcache.hve >> %COLLECTION_FOLDER%\Collection.log
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Amcache.hve
	echo --------------------------------------------------------------------------------------------------------------------
	if %ARCH% == 32 (
		%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\appcompat\Programs\Amcache.hve /OutputPath:%COLLECTION_FOLDER%\Registry\
	)
	if %ARCH% == 64 (
		%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\appcompat\Programs\Amcache.hve /OutputPath:%COLLECTION_FOLDER%\Registry\
	)
	%ANALYSISTOOLS_FOLDER%\AmcacheParser.exe -f %COLLECTION_FOLDER%\Registry\Amcache.hve --csv %COLLECTION_FOLDER%\Registry --csvf Amcache.csv -i

	REM Collecting Each User's Registry Hive (NTUSER.DAT, USRCLASS.DAT)
	echo [+] %DATE% %TIME% - Collecting Each User's Registry Hive >> %COLLECTION_FOLDER%\Collection.log
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Each User's Registry Hive
	echo --------------------------------------------------------------------------------------------------------------------
	if NOT %OS% == legacy (set USERPATH=%SYSTEM_DRIVE%\Users) else set (USERPATH="%SYSTEM_DRIVE%\Documents and Settings")
	
	REM Change Path To %USERPATH%
	%SYSTEM_DRIVE%
	cd %USERPATH%
	
	REM start collecting ntuser.dat and usrclass.dat
	for /f "tokens=*" %%i in ('dir /ah /b /s NTUSER.DAT') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
		if not exist %COLLECTION_FOLDER%\Registry\%%j (
			mkdir %COLLECTION_FOLDER%\Registry\%%j

			if %ARCH% == 32 (
				%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe /FileNamePath:"%%i" /OutputPath:%COLLECTION_FOLDER%\Registry\%%j\
			)
			if %ARCH% == 64 (
				%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:"%%i" /OutputPath:%COLLECTION_FOLDER%\Registry\%%j\
			)
		)
	)
	
	for /f "tokens=*" %%i in ('dir /ah /b /s UsrClass.dat') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
			
		if %ARCH% == 32 (
			%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe /FileNamePath:"%%i" /OutputPath:%COLLECTION_FOLDER%\Registry\%%j\
		)
		if %ARCH% == 64 (
			%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:"%%i" /OutputPath:%COLLECTION_FOLDER%\Registry\%%j\
		)		
	)

	REM Collecting Each User's Recent Folder
	echo [+] %DATE% %TIME% - Collecting Each User's Recent Folder >> %COLLECTION_FOLDER%\Collection.log
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Each User's Recent Folder
	echo --------------------------------------------------------------------------------------------------------------------	
	for /f "tokens=*" %%i in ('dir /ah /b /s Recent') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
		if not exist %COLLECTION_FOLDER%\Recent\%%j (
			mkdir %COLLECTION_FOLDER%\Recent\%%j
			%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%%i" %COLLECTION_FOLDER%\Recent\%%j /ZB /copy:DAT /r:0 /ts /FP /np /E /A-:SH			
		)
	)
	
	REM Collecting Each User's Bitmap Cache
	echo [+] %DATE% %TIME% - Collecting Each User's Bitmap Cache >> %COLLECTION_FOLDER%\Collection.log
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Each User's Bitmap Cache
	echo --------------------------------------------------------------------------------------------------------------------
	for /f "tokens=*" %%i in ('dir /ad /b /s "Terminal Server Client"') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
		if not exist %COLLECTION_FOLDER%\BMC\%%j (
			mkdir %COLLECTION_FOLDER%\BMC\%%j
			%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%%i\Cache" %COLLECTION_FOLDER%\BMC\%%j /ZB /copy:DAT /r:0 /ts /FP /np /E /A-:SH			
		)
		mkdir %COLLECTION_FOLDER%\BMC\%%j\bmc-tools-output
		%ANALYSISTOOLS_FOLDER%\bmc-tools.exe -s %COLLECTION_FOLDER%\BMC\%%j -d %COLLECTION_FOLDER%\BMC\%%j\bmc-tools-output -b
	)
	
	REM Collecting PowerShell Console logs
	echo [+] %DATE% %TIME% - Collecting PowerShell Console logs >> %COLLECTION_FOLDER%\Collection.log
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting PowerShell Console logs
	echo --------------------------------------------------------------------------------------------------------------------
	for /f "tokens=*" %%i in ('dir /ad /b /s PSReadLine') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
		if not exist %COLLECTION_FOLDER%\PowerShell\%%j (
			mkdir %COLLECTION_FOLDER%\PowerShell\%%j
			%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %%i %COLLECTION_FOLDER%\PowerShell\%%j ConsoleHost_history.txt		
		)
	)
	
	REM Collecting Win10 timeline ActivitiesCache.db
	echo [+] %DATE% %TIME% - Collecting Win10 timeline ActivitiesCache.db >> %COLLECTION_FOLDER%\Collection.log
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Win10 timeline ActivitiesCache.db
	echo --------------------------------------------------------------------------------------------------------------------
	for /f "tokens=*" %%i in ('dir /ad /b /s ConnectedDevicesPlatform') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
		if not exist %COLLECTION_FOLDER%\ActivitiesCache\%%j (
			mkdir %COLLECTION_FOLDER%\ActivitiesCache\%%j
			%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %%i\L.%%j\ %COLLECTION_FOLDER%\ActivitiesCache\%%j /ZB /copy:DAT /r:0 /ts /FP /np /E /A-:SH			
		)
		mkdir %COLLECTION_FOLDER%\ActivitiesCache\%%j\WxT-output
		%ANALYSISTOOLS_FOLDER%\WxTCmd.exe -f %COLLECTION_FOLDER%\ActivitiesCache\%%j\ActivitiesCache.db --csv %COLLECTION_FOLDER%\ActivitiesCache\%%j\WxT-output
	)
	
	REM Collecting FTP related logs
	echo [+] %DATE% %TIME% - Collecting FTP related logs >> %COLLECTION_FOLDER%\Collection.log
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting FTP related logs
	echo --------------------------------------------------------------------------------------------------------------------
	REM FileZilla Client
	for /f "tokens=*" %%i in ('dir /ad /b /s FileZilla*') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
		if not exist %COLLECTION_FOLDER%\FTP\%%j (
			mkdir %COLLECTION_FOLDER%\FTP\%%j
			%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %%i %COLLECTION_FOLDER%\FTP\%%j *.xml			
		)
	)

	REM switch back to script path
	%SCRIPT_DRIVE%

	REM Collecting Windows Event Logs
	echo [+] %DATE% %TIME% - Collecting Windows Event Logs >> %COLLECTION_FOLDER%\Collection.log
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Windows Event Logs
	echo --------------------------------------------------------------------------------------------------------------------
	
	"%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\System32\config\AppEvent.Evt /OutputPath:%COLLECTION_FOLDER%\EventLog
	"%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\System32\config\SecEvent.Evt /OutputPath:%COLLECTION_FOLDER%\EventLog
	"%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\System32\config\SysEvent.Evt /OutputPath:%COLLECTION_FOLDER%\EventLog
	robocopy "%SYSTEM_DRIVE%\Windows\System32\winevt\Logs" "%COLLECTION_FOLDER%\EventLog" /ZB /copy:DAT /r:0 /ts /FP /np /E
	
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
	echo [+] %DATE% %TIME% - Collecting MBR >> %COLLECTION_FOLDER%\Collection.log
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting MBR
	echo --------------------------------------------------------------------------------------------------------------------
	%COLLECTFILESTOOLS_FOLDER%\dd.exe if=\\.\PhysicalDrive0 of=%COLLECTION_FOLDER%\MBR\%COMPUTERNAME%_MBR.dump bs=512 count=32

	REM Collecting Each Fixed Disk's MFT and parsing to csv
	echo [+] %DATE% %TIME% - Collecting Each Fixed Disk's $MFT, $LogFile and parsing to csv >> %COLLECTION_FOLDER%\Collection.log
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Each Fixed Disk's MFT, LogFile, UsnJrnl and parsing to csv
	echo --------------------------------------------------------------------------------------------------------------------
	for /f "skip=1 delims=" %%i in ('wmic logicaldisk where "DriveType='3'" get DeviceID') do @for /f "tokens=1 delims=:" %%j in ("%%i") do (
	
		if %ARCH% == 32 (
			%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe /FileNamePath:%%j:0 /OutputPath:%COLLECTION_FOLDER%\NTFS\ /OutputName:%COMPUTERNAME%_$MFT_%%j			
		)
		if %ARCH% == 64 (
			%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:%%j:0 /OutputPath:%COLLECTION_FOLDER%\NTFS\ /OutputName:%COMPUTERNAME%_$MFT_%%j			
		)
		%ANALYSISTOOLS_FOLDER%\MFTECmd.exe -f %COLLECTION_FOLDER%\NTFS\%COMPUTERNAME%_$MFT_%%j --csv %COLLECTION_FOLDER%\NTFS\ --csvf %COMPUTERNAME%_MFT_%%j.csv
	)
	
	REM Collecting Each Fixed Disk's $LogFile
	for /f "skip=1 delims=" %%i in ('wmic logicaldisk where "DriveType='3'" get DeviceID') do @for /f "tokens=1 delims=:" %%j in ("%%i") do (
	
		if %ARCH% == 32 (
			%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe /FileNamePath:%%j:2 /OutputPath:%COLLECTION_FOLDER%\NTFS\ /OutputName:%COMPUTERNAME%_$LogFile_%%j			
		)
		if %ARCH% == 64 (
			%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:%%j:2 /OutputPath:%COLLECTION_FOLDER%\NTFS\ /OutputName:%COMPUTERNAME%_$LogFile_%%j
		)
		REM %ANALYSISTOOLS_FOLDER%\MFTECmd.exe -f %COLLECTION_FOLDER%\NTFS\%COMPUTERNAME%_$LogFile_%%j --csv %COLLECTION_FOLDER%\NTFS\ --csvf %COMPUTERNAME%_LogFile_%%j.csv --not supported yet
	)
	
	REM Collecting Each Fixed Disk's $UsnJrnl and parsing to csv
	for /f "skip=1 delims=" %%i in ('wmic logicaldisk where "DriveType='3'" get DeviceID') do @for /f "tokens=1 delims=:" %%j in ("%%i") do (
		if %ARCH% == 32 (
			%COLLECTFILESTOOLS_FOLDER%\ExtractUsnJrnl\ExtractUsnJrnl.exe /DevicePath:%%j: /OutputPath:%COLLECTION_FOLDER%\NTFS\ /OutputName:%COMPUTERNAME%_$J_%%j
		)
		if %ARCH% == 64 (
			%COLLECTFILESTOOLS_FOLDER%\ExtractUsnJrnl\ExtractUsnJrnl64.exe /DevicePath:%%j: /OutputPath:%COLLECTION_FOLDER%\NTFS\ /OutputName:%COMPUTERNAME%_$J_%%j
		)
		%ANALYSISTOOLS_FOLDER%\MFTECmd.exe -f %COLLECTION_FOLDER%\NTFS\%COMPUTERNAME%_$J --csv %COLLECTION_FOLDER%\NTFS\ --csvf %COMPUTERNAME%_$J_%%j.csv
	)
	
	REM Collecting Shellbags InformSation
	echo [+] %DATE% %TIME% - Collecting Shellbags Information >> %COLLECTION_FOLDER%\Collection.log
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Shellbags Information
	echo --------------------------------------------------------------------------------------------------------------------
	%ANALYSISTOOLS_FOLDER%\SBECmd.exe -l --csv %COLLECTION_FOLDER%\Shellbags -q
	
	REM Collecting Shimcache Information
	echo [+] %DATE% %TIME% - Collecting Shimcache Information >> %COLLECTION_FOLDER%\Collection.log
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Shimcache Information
	echo --------------------------------------------------------------------------------------------------------------------
	%ANALYSISTOOLS_FOLDER%\AppCompatCacheParser.exe -t --csv %COLLECTION_FOLDER%\RecentExecution\ --csvf AppCompatCacheParser_output.csv

	REM Collecting Prefetch File
	echo [+] %DATE% %TIME% - Collecting Prefetch File >> %COLLECTION_FOLDER%\Collection.log
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Prefetch File
	echo --------------------------------------------------------------------------------------------------------------------
	%ANALYSISTOOLS_FOLDER%\PECmd.exe -d %SYSTEM_DRIVE%\Windows\Prefetch --csv %COLLECTION_FOLDER%\Prefetch --csvf %COMPUTERNAME%_pf.csv -q
	
	if %ARCH% == 32 (
		%ANALYSISTOOLS_FOLDER%\winprefetchview\x86\WinPrefetchView.exe /sort "Last Run Time" /scomma %COLLECTION_FOLDER%\Prefetch\%COMPUTERNAME%_Prefetch.csv
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %SYSTEM_DRIVE%\Windows\Prefetch %COLLECTION_FOLDER%\Prefetch\ *.pf /ZB /copy:DAT /r:0 /ts /FP /np
	)
	if %ARCH% == 64 (
		%ANALYSISTOOLS_FOLDER%\winprefetchview\x64\WinPrefetchView.exe /sort "Last Run Time" /scomma %COLLECTION_FOLDER%\Prefetch\%COMPUTERNAME%_Prefetch.csv
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %SYSTEM_DRIVE%\Windows\Prefetch %COLLECTION_FOLDER%\Prefetch\ *.pf /ZB /copy:DAT /r:0 /ts /FP /np
	)

	REM Collecting Browsing history
	echo [+] %DATE% %TIME% - Collecting Browsing History >> %COLLECTION_FOLDER%\Collection.log
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Browsing History
	echo --------------------------------------------------------------------------------------------------------------------
	if %ARCH% == 32 (
		%COLLECTFILESTOOLS_FOLDER%\browsinghistoryview\BrowsingHistoryView.exe /HistorySource 1 /LoadIE 1 /LoadFirefox 1 /LoadChrome 1 /LoadSafari 1 /sort "Visit Time" /scomma %COLLECTION_FOLDER%\BrowsingHistory\%COMPUTERNAME%_BrowsingHistory.csv
	)
	if %ARCH% == 64 (
		%COLLECTFILESTOOLS_FOLDER%\browsinghistoryview\BrowsingHistoryView64.exe /HistorySource 1 /LoadIE 1 /LoadFirefox 1 /LoadChrome 1 /LoadSafari 1 /sort "Visit Time" /scomma %COLLECTION_FOLDER%\BrowsingHistory\%COMPUTERNAME%_BrowsingHistory.csv
	)
	
	REM Collecting Web Servers logs
	echo [+] %DATE% %TIME% - Collecting Web Servers logs >> %COLLECTION_FOLDER%\Collection.log
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Web Servers logs
	echo --------------------------------------------------------------------------------------------------------------------

	%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %SYSTEM_DRIVE%\inetpub\logs\LogFiles\ %COLLECTION_FOLDER%\WebServer\ *.log /E /ZB /copy:DAT /r:0 /ts /FP /np
	%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %SYSTEM_DRIVE%\Windows\nginx\logs\ %COLLECTION_FOLDER%\WebServer\ *.log /E /ZB /copy:DAT /r:0 /ts /FP /np
	
	REM Collecting Sign InformSation
	REM echo [+] %DATE% %TIME% - Collecting Sign InformSation >> %COLLECTION_FOLDER%\Collection.log
	REM echo --------------------------------------------------------------------------------------------------------------------
	REM echo %DATE% %TIME% - Collecting Sign InformSation
	REM echo --------------------------------------------------------------------------------------------------------------------
	if %ARCH% == 32 (
		"%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck.exe" /accepteula -h -c -w %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_Windows_exe.csv C:\Windows\*.exe
		"%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck.exe" /accepteula -h -c -w %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_Windows_dll.csv C:\Windows\*.dll
		"%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck.exe" /accepteula -h -c -w %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_System32_exe.csv C:\Windows\System32\*.exe 
		"%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck.exe" /accepteula -h -c -w %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_System32_dll.csv C:\Windows\System32\*.dll
		"%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck.exe" /accepteula -h -c -w %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_Syswow64_exe.csv C:\Windows\syswow64\*.exe
		"%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck.exe" /accepteula -h -c -w %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_Syswow64_dll.csv C:\Windows\syswow64\*.dll
	)
	if %ARCH% == 64 (
		"%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula -h -c -w %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_Windows_exe.csv C:\Windows\*.exe
		"%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula -h -c -w %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_Windows_dll.csv C:\Windows\*.dll
		"%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula -h -c -w %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_System32_exe.csv C:\Windows\System32\*.exe 
		"%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula -h -c -w %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_System32_dll.csv C:\Windows\System32\*.dll
		"%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula -h -c -w %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_Syswow64_exe.csv C:\Windows\syswow64\*.exe
		"%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula -h -c -w %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_Syswow64_dll.csv C:\Windows\syswow64\*.dll
	)
	REM "%COLLECTFILESTOOLS_FOLDER%\signtool\x64\signtool.exe" verify /pa /q C:\Windows\*.exe 2> %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_Windows_exe.txt
	REM "%COLLECTFILESTOOLS_FOLDER%\signtool\x64\signtool.exe" verify /pa /q C:\Windows\*.dll 2> %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_Windows_dll.txt
	REM "%COLLECTFILESTOOLS_FOLDER%\signtool\x64\signtool.exe" verify /pa /q C:\Windows\System32\*.exe 2> %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_System32_exe.txt
	REM "%COLLECTFILESTOOLS_FOLDER%\signtool\x64\signtool.exe" verify /pa /q C:\Windows\System32\*.dll 2> %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_System32_dll.txt
	REM "%COLLECTFILESTOOLS_FOLDER%\signtool\x64\signtool.exe" verify /pa /q C:\Windows\syswow64\*.exe 2> %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_Syswow64_exe.txt
	REM "%COLLECTFILESTOOLS_FOLDER%\signtool\x64\signtool.exe" verify /pa /q C:\Windows\syswow64\*.dll 2> %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_Syswow64_dll.txt
	
	REM Collecting Recycle Bin files
	echo [+] %DATE% %TIME% - Collecting Recycle Bin files >> %COLLECTION_FOLDER%\Collection.log
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Recycle Bin files
	echo --------------------------------------------------------------------------------------------------------------------
	
	%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %SYSTEM_DRIVE%\$Recycle.Bin %COLLECTION_FOLDER%\RecycleBin /ZB /copy:DAT /r:0 /ts /FP /np /E /A-:SH
	%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %SYSTEM_DRIVE%\RECYCLER %COLLECTION_FOLDER%\RecycleBin /ZB /copy:DAT /r:0 /ts /FP /np /E /A-:SH
	
	REM if NOT %OS% == "legacy" (

		REM %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %SYSTEM_DRIVE%\$Recycle.Bin %COLLECTION_FOLDER%\RecycleBin /ZB /copy:DAT /r:0 /ts /FP /np /E /A-:SH
		
	REM ) else (
		REM %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %SYSTEM_DRIVE%\RECYCLER %COLLECTION_FOLDER%\RecycleBin /ZB /copy:DAT /r:0 /ts /FP /np /E /A-:SH
	REM )
	
	REM Collecting Windows.edb
	echo [+] %DATE% %TIME% - Collecting Windows.edb >> %COLLECTION_FOLDER%\Collection.log
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Windows.edb
	echo --------------------------------------------------------------------------------------------------------------------
	if %ARCH% == 32 (
		%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe /FileNamePath:%SYSTEM_DRIVE%\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb /OutputPath:%COLLECTION_FOLDER%\Windows.edb\
	)
	if %ARCH% == 64 (
		%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb /OutputPath:%COLLECTION_FOLDER%\Windows.edb\
	)
	
	REM Collecting SRUM
	echo [+] %DATE% %TIME% - Collecting SRUM >> %COLLECTION_FOLDER%\Collection.log
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting SRUM
	echo --------------------------------------------------------------------------------------------------------------------

	if %ARCH% == 32 (
		%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\sru\SRUDB.dat /OutputPath:%COLLECTION_FOLDER%\SRUM
	)
	if %ARCH% == 64 (
		%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\sru\SRUDB.dat /OutputPath:%COLLECTION_FOLDER%\SRUM
	)
	
	%ANALYSISTOOLS_FOLDER%\SrumECmd.exe -f %COLLECTION_FOLDER%\SRUM\SRUDB.dat -r %COLLECTION_FOLDER%\Registry\SOFTWARE --csv  %COLLECTION_FOLDER%\SRUM\
		
	REM Collecting FTP related logs
	echo [+] %DATE% %TIME% - Collecting FTP related logs >> %COLLECTION_FOLDER%\Collection.log
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting FTP related logs
	echo --------------------------------------------------------------------------------------------------------------------
	REM FileZilla Server logs
	%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\Windows\Program Files (x86)\FileZilla Server\Logs\" %COLLECTION_FOLDER%\FTP *.log
	
	REM WinSCP ini file
	REM %COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe %SYSTEM_DRIVE%\Windows\ %COLLECTION_FOLDER%\FTP WinSCP.ini
	
	REM Collecting AntiVirus logs
	echo [+] %DATE% %TIME% - Collecting AntiVirus logs >> %COLLECTION_FOLDER%\Collection.log
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting AntiVirus logs
	echo --------------------------------------------------------------------------------------------------------------------
	if %OS% == legacy (

		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\Documents And Settings\All Users\Application Data\Avast Software\Avast\Log\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\AVG\Antivirus\log\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\AVG\Antivirus\report\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\ESET\ESET NOD32 Antivirus\Logs\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\ESET\ESET NOD32 Antivirus\Logs\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\McAfee\DesktopProtection\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\Sophos\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\Symantec\Symantec Endpoint Protection\Logs\AV\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\Symantec\Symantec Endpoint Protection\Quarantine\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		
	) else (
		
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\Avast Software\Avast\Log\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\Avast Software\Avast\Chest\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\AVG\Antivirus\log\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\AVG\Antivirus\report\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\Avira\Antivirus\LOGFILES\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\ESET\ESET NOD32 Antivirus\Logs\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\F-Secure\Log\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\F-Secure\Antivirus\ScheduledScanReports\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\McAfee\DesktopProtection\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\McAfee\Endpoint Security\Logs\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\McAfee\Endpoint Security\Logs_Old\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\Mcafee\VirusScan\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\Sophos\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\Symantec\Symantec Endpoint Protection\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\Trend Micro\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\Microsoft\Microsoft AntiMalware\Support\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy.exe "%SYSTEM_DRIVE%\ProgramData\Microsoft\Windows Defender\Support\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E		
	)

	REM REM Acquiring Memory
	REM echo --------------------------------------------------------------------------------------------------------------------
	REM echo %DATE% %TIME% - Acquiring Memory
	REM echo --------------------------------------------------------------------------------------------------------------------
	REM if %ARCH% == 32 (
		REM %COLLECTFILESTOOLS_FOLDER%\winpmem\winpmem_mini_x86.exe %COLLECTION_FOLDER%\MemoryInfo\%COMPUTERNAME%_physmem.raw
	REM )
	REM if %ARCH% == 64 (
		REM %COLLECTFILESTOOLS_FOLDER%\winpmem\winpmem_mini_x64_rc2.exe %COLLECTION_FOLDER%\MemoryInfo\%COMPUTERNAME%_physmem.raw		
	REM )
	
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - %COMPUTERNMAE% Collecting Finished.
	echo --------------------------------------------------------------------------------------------------------------------
) else echo %COMPUTERNAME% has already collected. 	

pause
