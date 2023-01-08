@echo off
:: --------------------------------------------------------------------------------------------------------------------------
:: Name:     RegRipper_Script.cmd
:: Purpose:  Parse registry hive.
:: Author:   FS FANG
:: Version:  1.0.2
:: Revision: Oct 2020 v1.0.0 - initial version
::	     Dec 2020 v1.0.1 - add:		create collection folder automatically
::			       		   modify:  parse each user's NTUSER.DAT, UsrClass
::	     Nov 2021 v1.0.2 - modify:  could be called by DF_Script.cmd
:: --------------------------------------------------------------------------------------------------------------------------
:: --------------------------------------------------------------------------------------------------------------------------
:: Set Setting Script Variables
:: --------------------------------------------------------------------------------------------------------------------------
REM Define Script Header and Usage
:header
echo.
echo RegRipper_Script version 1.0.2
echo Author: FS FANG
echo Parses Registry Hive
echo.
set CASE_NAME=%1

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
chcp 65001

echo --------------------------------------------------------------------------------------------------------------------
echo %DATE% %TIME% - Start running regrip.cmd on %CASE_NAME%
echo --------------------------------------------------------------------------------------------------------------------

if not exist %PARSE_FOLDER% (
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Creating RegParse Folders
	echo --------------------------------------------------------------------------------------------------------------------
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
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Recording parse Time
	echo --------------------------------------------------------------------------------------------------------------------
	((date /t) & (time /t)) > %PARSE_FOLDER%\%CASE_NAME%_RegParseTime.txt

	REM Parse the SAM hive file for user/group membership info
	echo --------------------------------------------------------------------------------------------------------------------
	echo Parsing User/Group Membership Info
	echo --------------------------------------------------------------------------------------------------------------------
	%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SAM -p samparse > %PARSE_FOLDER%\SAM\samparse.txt

	echo --------------------------------------------------------------------------------------------------------------------
	echo Parsing System Configuration
	echo --------------------------------------------------------------------------------------------------------------------
	REM TimeZoneInformation 
	%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SYSTEM -p timezone > %PARSE_FOLDER%\SystemConfiguration\timezone.txt

	REM winver
	%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SOFTWARE -p winver > %PARSE_FOLDER%\SystemConfiguration\winver.txt

	REM installer
	%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SOFTWARE -p installer > %PARSE_FOLDER%\SystemConfiguration\installer.txt

	REM networkcards
	%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SOFTWARE -p networkcards > %PARSE_FOLDER%\SystemConfiguration\networkcards.txt

	REM nic2
	%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SYSTEM -p nic2 > %PARSE_FOLDER%\SystemConfiguration\NIC.txt

	REM networklist
	%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SOFTWARE -p networklist > %PARSE_FOLDER%\SystemConfiguration\networklist.txt

	echo --------------------------------------------------------------------------------------------------------------------
	echo Parsing System Autostart Programs
	echo --------------------------------------------------------------------------------------------------------------------
	
	REM runonceex
	%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SOFTWARE -p runonceex >> %PARSE_FOLDER%\SystemConfiguration\SystemAutostartPrograms.txt

	REM services
	%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SYSTEM -p services > %PARSE_FOLDER%\SystemConfiguration\services.txt

	REM Shares of the System
	%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SYSTEM -p shares > %PARSE_FOLDER%\SystemConfiguration\shares.txt

	REM Last Shutdown Time
	%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SYSTEM -p shutdown > %PARSE_FOLDER%\SystemConfiguration\shutdown.txt

	echo --------------------------------------------------------------------------------------------------------------------
	echo Parsing Windows Prefetch
	echo --------------------------------------------------------------------------------------------------------------------
	REM prefetch
	%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SYSTEM -p prefetch > %PARSE_FOLDER%\WindowsPrefetch\prefetch.txt

	echo --------------------------------------------------------------------------------------------------------------------
	echo Parsing AppCompatCache
	echo --------------------------------------------------------------------------------------------------------------------
	REM AppCompatCache
	%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SYSTEM -p appcompatcache > %PARSE_FOLDER%\AppCompatCache\appcompatcache.txt

	REM Shimcache
	%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SYSTEM -p shimcache > %PARSE_FOLDER%\AppCompatCache\shimcache.txt

	echo --------------------------------------------------------------------------------------------------------------------
	echo Parsing SRUM
	echo --------------------------------------------------------------------------------------------------------------------
	REM System Resource Usage Monitor
	%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SOFTWARE -p srum > %PARSE_FOLDER%\SRUM\srum.txt

	

	echo --------------------------------------------------------------------------------------------------------------------
	echo Parsing Remote Info
	echo --------------------------------------------------------------------------------------------------------------------
	REM remoteaccess
	%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SYSTEM -p remoteaccess > %PARSE_FOLDER%\SoftwareExecutedHistory\remoteaccess.txt
	REM termserv
	%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SYSTEM -r %REG_FOLDER%\SOFTWARE -p termserv > %PARSE_FOLDER%\SoftwareExecutedHistory\termserv.txt

	echo --------------------------------------------------------------------------------------------------------------------
	echo Parsing At/Schtasks Info
	echo --------------------------------------------------------------------------------------------------------------------
	REM at
	%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SOFTWARE -p at > %PARSE_FOLDER%\At\at.txt
	REM tasks
	%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SOFTWARE -p tasks > %PARSE_FOLDER%\At\tasks.txt
	REM taskcache
	%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SOFTWARE -p taskcache > %PARSE_FOLDER%\At\taskcache.txt
	
	REM Parsing Each User's Registry Hive (NTUSER.DAT, USRCLASS.DAT)
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Parsing Each User's Registry Hive
	echo --------------------------------------------------------------------------------------------------------------------

	for /f %%i in ('dir /ad /b %REG_FOLDER%\') do (
			
		mkdir %PARSE_FOLDER%\UserActivity\%%i
		REM Microsoft OS version
		%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p osversion > %PARSE_FOLDER%\UserActivity\%%i\OSversion.txt
		
		REM environment
		%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SYSTEM -r %REG_FOLDER%\%%i\NTUSER.DAT -p environment > %PARSE_FOLDER%\UserActivity\%%i\environment.txt
		
		REM run
		%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p run >> %PARSE_FOLDER%\UserActivity\%%i\SystemAutostartPrograms.txt
		
		echo --------------------------------------------------------------------------------------------------------------------
		echo Parsing User Activity
		echo --------------------------------------------------------------------------------------------------------------------
		REM Search History
		%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p wordwheelquery > %PARSE_FOLDER%\UserActivity\%%i\wordwheelquery.txt

		REM Typed Paths
		%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p typedpaths > %PARSE_FOLDER%\UserActivity\%%i\typedpaths.txt

		REM typedurls
		%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p typedurls > %PARSE_FOLDER%\UserActivity\%%i\typedurls.txt

		REM Recent Docs
		%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p recentdocs > %PARSE_FOLDER%\UserActivity\%%i\recentdocs.txt

		REM recentapps
		%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p recentapps > %PARSE_FOLDER%\UserActivity\%%i\recentapps.txt

		REM OpenSaveMRU
		%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p comdlg32 > %PARSE_FOLDER%\UserActivity\%%i\comdlg32.txt

		REM Last Commands Executed
		%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p runmru > %PARSE_FOLDER%\UserActivity\%%i\runmru.txt

		REM UserAssist
		%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p userassist > %PARSE_FOLDER%\UserActivity\%%i\userassist.txt

		REM Shell Item Analysis
		REM JumpList
		%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p jumplistdata > %PARSE_FOLDER%\UserActivity\%%i\jumplistdata.txt

		REM parse (Vista, Win7/Win2008R2) shell bags
		%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\UsrClass.DAT -p shellbags > %PARSE_FOLDER%\UserActivity\%%i\shellbags.txt

		REM shellfolders
		%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p shellfolders > %PARSE_FOLDER%\UserActivity\%%i\shellfolders.txt

		REM lastloggedon
		%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SOFTWARE -p lastloggedon > %PARSE_FOLDER%\UserActivity\%%i\lastloggedon.txt

		REM mndmru
		%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p mndmru > %PARSE_FOLDER%\UserActivity\%%i\mndmru.txt

		REM muicache
		%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -r %REG_FOLDER%\%%i\UsrClass.DAT -p muicache > %PARSE_FOLDER%\UserActivity\%%i\muicache.txt

		REM profilelist
		%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\SOFTWARE -p profilelist > %PARSE_FOLDER%\UserActivity\%%i\profilelist.txt

		REM pslogging
		%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -r %REG_FOLDER%\SOFTWARE -p pslogging > %PARSE_FOLDER%\UserActivity\%%i\pslogging.txt
		
		echo --------------------------------------------------------------------------------------------------------------------
		echo Parsing Software Executed History
		echo --------------------------------------------------------------------------------------------------------------------
		REM putty
		%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p putty > %PARSE_FOLDER%\UserActivity\%%i\putty.txt
		
		REM sevenzip
		%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p sevenzip > %PARSE_FOLDER%\UserActivity\%%i\sevenzip.txt
		
		REM winrar
		%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p winrar > %PARSE_FOLDER%\UserActivity\%%i\winrar.txt
		
		REM winscp
		%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p winscp > %PARSE_FOLDER%\UserActivity\%%i\winscp.txt
		
		REM WinZip
		%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p winzip > %PARSE_FOLDER%\UserActivity\%%i\winzip.txt
		
		REM tsclient
		%RIP_FOLDER%\rip.exe -r %REG_FOLDER%\%%i\NTUSER.DAT -p tsclient > %PARSE_FOLDER%\UserActivity\%%i\tsclient.txt		
	)
	
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - %CASE_NAME% Registry Parsing Finished.
	echo --------------------------------------------------------------------------------------------------------------------
) else echo %CASE_NAME% Registry has already parsed.
