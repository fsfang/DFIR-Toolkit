@echo off
:: --------------------------------------------------------------------------------------------------------------------------
:: Name:     DF_Script.cmd
:: Purpose:  Collect artifacts in a incident response case with image file based on Windows operating system.
:: Author:   FS FANG
:: Version:  1.0.3
:: Revision: Nov 2021 v1.0.0 - initial version
::			 Aug 2022 v1.0.1 - bug fixes
::	     	 Dec 2022 v1.0.2 - add:    collect and parse UsnJrnl
::			 Jan 2023 v1.0.3 - modify: digital signature tool replaced
:: --------------------------------------------------------------------------------------------------------------------------

call :setESC

echo.
echo %ESC%[92m      #####     ######  #####    ###  ######  ############  ########%ESC%[0m
echo %ESC%[92m     ##    #   ##      #       #     ##    #   ##   #     #   #    %ESC%[0m
echo %ESC%[92m    ##     #  ##      ##      #     ##     #  ##   #     #   #    %ESC%[0m
echo %ESC%[92m   ##      # #######  ####   #     #######   ##   #     #   #    %ESC%[0m
echo %ESC%[92m  ##      # ##           #  #     ## ##     ##   #####     #   %ESC%[0m
echo %ESC%[92m ##      # ##           #  #     ##  ##    ##   ##        #   %ESC%[0m
echo %ESC%[92m #######  ##      ######    ### ##   ##  ##### ##        ##   %ESC%[0m
echo							        %ESC%[96mv1.0.3 @FFS%ESC%[0m
call :header

:setESC
for /F "tokens=1,2 delims=#" %%a in ('"prompt #$H#$E# & echo on & for %%b in (1) do rem"') do (
  set ESC=%%b
  exit /B 0
)
exit /B 0

:header
echo.
echo DF_Script version 1.0.3
echo Author: FS FANG
echo Collect artifacts in a incident response case with image file based on Windows operating system.
echo.
set /p CASE_NAME=Case Name:
set /p SYSTEM_DRIVE=System Drive Letter(C:):
set /p OS=Enter 1 if image file is legacy OS. Otherwise, leave blank:

if %OS% == 1 (
	set OS=legacy
)
call :main

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
echo --------------------------------------------------------------------------------------------------------------------
echo %DATE% %TIME% - Start running DF_Script.cmd on %CASE_NAME%
echo --------------------------------------------------------------------------------------------------------------------

if not exist %COLLECTION_FOLDER% (
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Creating Collection Folders
	echo --------------------------------------------------------------------------------------------------------------------
	REM Create Collection Folder
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
	mkdir %COLLECTION_FOLDER%\sus
	
	REM Recording the time and date of the data collection
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Recording Collection Time
	echo --------------------------------------------------------------------------------------------------------------------
	((date /t) & (time /t)) > %COLLECTION_FOLDER%\%CASE_NAME%_CollectionTime.txt
	
	REM Making System Timeline
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Making System Timeline
	echo --------------------------------------------------------------------------------------------------------------------
	dir %SYSTEM_DRIVE%\ /a/s/od/ta > %COLLECTION_FOLDER%\Timeline\%CASE_NAME%_AccessTime.txt
	dir %SYSTEM_DRIVE%\ /a/s/od/tc/q > %COLLECTION_FOLDER%\Timeline\%CASE_NAME%_CreationTime.txt
	dir %SYSTEM_DRIVE%\ /a/s/od/tw > %COLLECTION_FOLDER%\Timeline\%CASE_NAME%_WriteTime.txt

	REM Collecting Automatically Start Programs
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Task files
	echo --------------------------------------------------------------------------------------------------------------------

	%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe %SYSTEM_DRIVE%\Windows\Tasks %COLLECTION_FOLDER%\Tasks\ /ZB /copy:DAT /r:0 /ts /FP /np

	REM Collecting Registry
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Registry
	echo --------------------------------------------------------------------------------------------------------------------

	"%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SYSTEM /OutputPath:%COLLECTION_FOLDER%\Registry\
	"%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SOFTWARE /OutputPath:%COLLECTION_FOLDER%\Registry\
	"%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SECURITY /OutputPath:%COLLECTION_FOLDER%\Registry\
	"%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe" /FileNamePath:%SYSTEM_DRIVE%\Windows\system32\config\SAM /OutputPath:%COLLECTION_FOLDER%\Registry\
	
	REM Collecting Amcache.hve
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Amcache.hve
	echo --------------------------------------------------------------------------------------------------------------------
	
	%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\appcompat\Programs\Amcache.hve /OutputPath:%COLLECTION_FOLDER%\Registry\
	%ANALYSISTOOLS_FOLDER%\AmcacheParser.exe -f %COLLECTION_FOLDER%\Registry\Amcache.hve --csv %COLLECTION_FOLDER%\Registry\ --csvf Amcache.csv -i

	REM Collecting Each User's Registry Hive (NTUSER.DAT, USRCLASS.DAT)
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
			mkdir %COLLECTION_FOLDER%\Registry\%%j\Shellbags
			%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:%%i /OutputPath:%COLLECTION_FOLDER%\Registry\%%j\
		)
	)
	
	for /f "tokens=*" %%i in ('dir /ah /b /s UsrClass.dat') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
		
		%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:%%i /OutputPath:%COLLECTION_FOLDER%\Registry\%%j\
		%ANALYSISTOOLS_FOLDER%\SBECmd.exe -d %COLLECTION_FOLDER%\Registry\%%j\ --csv %COLLECTION_FOLDER%\Registry\%%j\Shellbags -q
	)
	call %SCRIPT_DRIVE%\Windows\Scripts\RegRipper_Script.bat %CASE_NAME%

	REM Collecting Each User's Recent Folder
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Each User's Recent Folder
	echo --------------------------------------------------------------------------------------------------------------------	
	for /f "tokens=*" %%i in ('dir /ah /b /s Recent') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
		if not exist %COLLECTION_FOLDER%\Recent\%%j (
			mkdir %COLLECTION_FOLDER%\Recent\%%j
			mkdir %COLLECTION_FOLDER%\Recent\%%j\JLECmd-output
			%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe %%i %COLLECTION_FOLDER%\Recent\%%j /ZB /copy:DAT /r:0 /ts /FP /np /E /A-:SH
			%ANALYSISTOOLS_FOLDER%\JLECmd.exe -d %COLLECTION_FOLDER%\Recent\%%j\AutomaticDestinations --csv %COLLECTION_FOLDER%\Recent\%%j\JLECmd-output --csvf JLECmd_AutomaticDestinations.csv -q
			%ANALYSISTOOLS_FOLDER%\JLECmd.exe -d %COLLECTION_FOLDER%\Recent\%%j\CustomDestinations --csv %COLLECTION_FOLDER%\Recent\%%j\JLECmd-output --csvf JLECmd_CustomDestinations.csv -q
		)
	)
	
	REM Collecting Each User's Bitmap Cache
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Each User's Bitmap Cache
	echo --------------------------------------------------------------------------------------------------------------------
	for /f "tokens=*" %%i in ('dir /ad /b /s "Terminal Server Client"') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
		if not exist %COLLECTION_FOLDER%\BMC\%%j (
			mkdir %COLLECTION_FOLDER%\BMC\%%j
			%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe "%%i\Cache" %COLLECTION_FOLDER%\BMC\%%j /ZB /copy:DAT /r:0 /ts /FP /np /E /A-:SH
		)
		mkdir %COLLECTION_FOLDER%\BMC\%%j\bmc-tools-output
		%ANALYSISTOOLS_FOLDER%\bmc-tools.exe -s %COLLECTION_FOLDER%\BMC\%%j -d %COLLECTION_FOLDER%\BMC\%%j\bmc-tools-output -b
	)
	
	REM Collecting PowerShell Console logs
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting PowerShell Console logs
	echo --------------------------------------------------------------------------------------------------------------------
	for /f "tokens=*" %%i in ('dir /ad /b /s PSReadLine') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
		if not exist %COLLECTION_FOLDER%\PowerShell\%%j (
			mkdir %COLLECTION_FOLDER%\PowerShell\%%j
			%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe %%i %COLLECTION_FOLDER%\PowerShell\%%j ConsoleHost_history.txt
		)
	)
	
	REM Collecting Win10 timeline ActivitiesCache.db
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Win10 timeline ActivitiesCache.db
	echo --------------------------------------------------------------------------------------------------------------------
	for /f "tokens=*" %%i in ('dir /ad /b /s ConnectedDevicesPlatform') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
		if not exist %COLLECTION_FOLDER%\ActivitiesCache\%%j (
			mkdir %COLLECTION_FOLDER%\ActivitiesCache\%%j			
			%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe %%i\L.%%j\ %COLLECTION_FOLDER%\ActivitiesCache\%%j /ZB /copy:DAT /r:0 /ts /FP /np /E /A-:SH
		)
		mkdir %COLLECTION_FOLDER%\ActivitiesCache\%%j\WxT-output
		%ANALYSISTOOLS_FOLDER%\WxTCmd.exe -f ActivitiesCache.db --csv %COLLECTION_FOLDER%\ActivitiesCache\%%j\WxT-output
	)

	REM switch back to script path
	%SCRIPT_DRIVE%

	REM Collecting Windows Event Logs
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Windows Event Logs
	echo --------------------------------------------------------------------------------------------------------------------
	if %OS% == legacy (
		
		%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\System32\config\AppEvent.Evt /OutputPath:%COLLECTION_FOLDER%\EventLog\
		%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\System32\config\SecEvent.Evt /OutputPath:%COLLECTION_FOLDER%\EventLog\
		%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\Windows\System32\config\SysEvent.Evt /OutputPath:%COLLECTION_FOLDER%\EventLog\
	) else (
		
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe %SYSTEM_DRIVE%\Windows\system32\winevt\Logs %COLLECTION_FOLDER%\EventLog /ZB /copy:DAT /r:0 /ts /FP /np /E
	)
	call %SCRIPT_DRIVE%\Windows\Scripts\EvtxECmd_Script.bat %CASE_NAME%
	
	REM Collecting MBR
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting MBR
	echo --------------------------------------------------------------------------------------------------------------------
	%COLLECTFILESTOOLS_FOLDER%\dd.exe if=\\.\PhysicalDrive0 of=%COLLECTION_FOLDER%\MBR\%CASE_NAME%_MBR.dump bs=512 count=32

	REM Collecting $MFT and parsing to csv
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Each Fixed Disk's MFT, LogFile, UsnJrnl and parsing to csv
	echo --------------------------------------------------------------------------------------------------------------------
	
	%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%0 /OutputPath:%COLLECTION_FOLDER%\NTFS\ /OutputName:%CASE_NAME%_$MFT
	%ANALYSISTOOLS_FOLDER%\MFTECmd.exe -f %COLLECTION_FOLDER%\NTFS\%CASE_NAME%_$MFT --csv %COLLECTION_FOLDER%\NTFS --csvf %CASE_NAME%_MFT.csv

	REM Collecting $LogFile
	%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%2 /OutputPath:%COLLECTION_FOLDER%\NTFS\ /OutputName:%CASE_NAME%_$LogFile
	
	REM Collecting $UsnJrnl and parsing to csv
	%COLLECTFILESTOOLS_FOLDER%\ExtractUsnJrnl\ExtractUsnJrnl64.exe /DevicePath:%SYSTEM_DRIVE% /OutputPath:%COLLECTION_FOLDER%\NTFS\ /OutputName:%CASE_NAME%_$J
	%ANALYSISTOOLS_FOLDER%\MFTECmd.exe -f %COLLECTION_FOLDER%\NTFS\%CASE_NAME%_$J --csv %COLLECTION_FOLDER%\NTFS --csvf %CASE_NAME%_J.csv
	
	REM Collecting Shimcache Information
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Shimcache Information
	echo --------------------------------------------------------------------------------------------------------------------
	%ANALYSISTOOLS_FOLDER%\AppCompatCacheParser.exe -t -f %COLLECTION_FOLDER%\Registry\SYSTEM --csv %COLLECTION_FOLDER%\RecentExecution\ --csvf AppCompatCacheParser_output.csv
	%ANALYSISTOOLS_FOLDER%\ShimCacheParser_PY.exe -i %COLLECTION_FOLDER%\Registry\ -o %COLLECTION_FOLDER%\RecentExecution\%CASE_NAME%_Shimcache.csv

	REM Collecting Prefetch File
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Prefetch File
	echo --------------------------------------------------------------------------------------------------------------------
	%ANALYSISTOOLS_FOLDER%\PECmd.exe -d %SYSTEM_DRIVE%\Windows\Prefetch --csv %COLLECTION_FOLDER%\Prefetch --csvf %CASE_NAME%_pf.csv -q		
	%ANALYSISTOOLS_FOLDER%\winprefetchview\x64\WinPrefetchView.exe /sort "Last Run Time" /scomma %COLLECTION_FOLDER%\Prefetch\%CASE_NAME%_Prefetch.csv
	%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe %SYSTEM_DRIVE%\Windows\Prefetch %COLLECTION_FOLDER%\Prefetch\ *.pf /ZB /copy:DAT /r:0 /ts /FP /np

	
	REM Collecting Web Servers logs
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Web Servers logs
	echo --------------------------------------------------------------------------------------------------------------------
	
	%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe %SYSTEM_DRIVE%\inetpub\logs\LogFiles\ %COLLECTION_FOLDER%\WebServer\ *.log /E /ZB /copy:DAT /r:0 /ts /FP /np
	%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe %SYSTEM_DRIVE%\Windows\nginx\logs\ %COLLECTION_FOLDER%\WebServer\ *.log /E /ZB /copy:DAT /r:0 /ts /FP /np
	
	REM Collecting Sign Information
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Sign Information
	echo --------------------------------------------------------------------------------------------------------------------
	"%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula -h -c -w %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_Windows_exe.csv %SYSTEM_DRIVE%\Windows\*.exe
	"%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula -h -c -w %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_Windows_dll.csv %SYSTEM_DRIVE%\Windows\*.dll
	"%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula -h -c -w %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_System32_exe.csv %SYSTEM_DRIVE%\Windows\System32\*.exe 
	"%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula -h -c -w %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_System32_dll.csv %SYSTEM_DRIVE%\Windows\System32\*.dll
	"%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula -h -c -w %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_Syswow64_exe.csv %SYSTEM_DRIVE%\Windows\syswow64\*.exe
	"%COLLECTFILESTOOLS_FOLDER%\sigcheck\sigcheck64.exe" /accepteula -h -c -w %COLLECTION_FOLDER%\SignInfo\%COMPUTERNAME%_Syswow64_dll.csv %SYSTEM_DRIVE%\Windows\syswow64\*.dll
	
	REM Collecting Recycle Bin files
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Recycle Bin files
	echo --------------------------------------------------------------------------------------------------------------------
	%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe %SYSTEM_DRIVE%\$Recycle.Bin %COLLECTION_FOLDER%\RecycleBin /ZB /copy:DAT /r:0 /ts /FP /np /E /A-:SH

	REM Collecting Windows.edb
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting Windows.edb
	echo --------------------------------------------------------------------------------------------------------------------
	%COLLECTFILESTOOLS_FOLDER%\RawCopy\RawCopy64.exe /FileNamePath:%SYSTEM_DRIVE%\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb /OutputPath:%COLLECTION_FOLDER%\Windows.edb\
	
	REM Collecting SRUM
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting SRUM
	echo --------------------------------------------------------------------------------------------------------------------
	%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe %SYSTEM_DRIVE%\Windows\system32\sru %COLLECTION_FOLDER%\SRUM /ZB /copy:DAT /r:0 /ts /FP /np /E
	%ANALYSISTOOLS_FOLDER%\SrumECmd.exe -f %COLLECTION_FOLDER%\SRUM\SRUDB.dat -r %COLLECTION_FOLDER%\Registry\SOFTWARE --csv  %COLLECTION_FOLDER%\SRUM\
		
	REM Collecting FTP related logs
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting FTP related logs
	echo --------------------------------------------------------------------------------------------------------------------
	REM FileZilla Server logs
	%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe "%SYSTEM_DRIVE%\Windows\Program Files (x86)\FileZilla Server\Logs\\" %COLLECTION_FOLDER%\FTP *.log
	
	REM FileZilla Client
	for /f "tokens=*" %%i in ('dir /ad /b /s FileZilla*') do @for /f "tokens=3 delims=\" %%j in ("%%i") do (
		if not exist %COLLECTION_FOLDER%\FTP\%%j (
			mkdir %COLLECTION_FOLDER%\FTP\%%j
			%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe %%i %COLLECTION_FOLDER%\FTP\%%j *.xml
		)
	)

	REM WinSCP ini file
	%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe %SYSTEM_DRIVE%\Windows\ %COLLECTION_FOLDER%\FTP WinSCP.ini
	
	REM Collecting AntiVirus logs
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Collecting AntiVirus logs
	echo --------------------------------------------------------------------------------------------------------------------
	if %OS% == legacy (
		
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe "%SYSTEM_DRIVE%\Documents And Settings\All Users\Application Data\Avast Software\Avast\Log\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\AVG\Antivirus\log\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\AVG\Antivirus\report\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\ESET\ESET NOD32 Antivirus\Logs\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\ESET\ESET NOD32 Antivirus\Logs\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\McAfee\DesktopProtection\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\Sophos\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\Symantec\Symantec Endpoint Protection\Logs\AV\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe "%SYSTEM_DRIVE%\Documents and Settings\All Users\Application Data\Symantec\Symantec Endpoint Protection\Quarantine\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E

	) else (
		
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe "%SYSTEM_DRIVE%\ProgramData\Avast Software\Avast\Log\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe "%SYSTEM_DRIVE%\ProgramData\Avast Software\Avast\Chest\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe "%SYSTEM_DRIVE%\ProgramData\AVG\Antivirus\log\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe "%SYSTEM_DRIVE%\ProgramData\AVG\Antivirus\report\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe "%SYSTEM_DRIVE%\ProgramData\Avira\Antivirus\LOGFILES\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe "%SYSTEM_DRIVE%\ProgramData\ESET\ESET NOD32 Antivirus\Logs\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe "%SYSTEM_DRIVE%\ProgramData\F-Secure\Log\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe "%SYSTEM_DRIVE%\ProgramData\F-Secure\Antivirus\ScheduledScanReports\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe "%SYSTEM_DRIVE%\ProgramData\McAfee\DesktopProtection\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe "%SYSTEM_DRIVE%\ProgramData\McAfee\Endpoint Security\Logs\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe "%SYSTEM_DRIVE%\ProgramData\McAfee\Endpoint Security\Logs_Old\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe "%SYSTEM_DRIVE%\ProgramData\Mcafee\VirusScan\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe "%SYSTEM_DRIVE%\ProgramData\Sophos\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe "%SYSTEM_DRIVE%\ProgramData\Symantec\Symantec Endpoint Protection\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe "%SYSTEM_DRIVE%\ProgramData\Trend Micro\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe "%SYSTEM_DRIVE%\ProgramData\Microsoft\Microsoft AntiMalware\Support\\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
		%COLLECTFILESTOOLS_FOLDER%\Robocopy\Robocopy64.exe "%SYSTEM_DRIVE%\ProgramData\Microsoft\Windows Defender\Support\" %COLLECTION_FOLDER%\Antivirus\ /ZB /copy:DAT /r:0 /ts /FP /np /E
	)
	
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - %CASE_NAME% Collecting Finished.
	echo --------------------------------------------------------------------------------------------------------------------
) else echo %CASE_NAME% has already collected. 	

pause
