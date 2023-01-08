@echo off
:: --------------------------------------------------------------------------------------------------------------------------
:: Name:     EvtxECmd_Script.cmd
:: Purpose:  Parse Event Logs.
:: Author:   FS FANG
:: Version:  1.0.2
:: Revision: Jan 2021 v1.0.0 - initial version
::			 Apr 2021 v1.0.1 - add: RdpCoreTS 131
::			 Nov 2021 v1.0.2 - modify: Could be called by DF_Script.cmd
:: --------------------------------------------------------------------------------------------------------------------------
:: --------------------------------------------------------------------------------------------------------------------------

:: --------------------------------------------------------------------------------------------------------------------------
:: Set Setting Script Variables
:: --------------------------------------------------------------------------------------------------------------------------
REM Define Script Header and Usage
:header
echo.
echo EvtxECmd_Script version 1.0.2
echo Author: FS FANG
echo Parse Event Logs
echo.
set CASE_NAME=%1

REM Setting Batch Script Drive
set SCRIPT_PATH=%~d0

REM Setting EvtxECmd.exe Path
set EVTXECMD_FOLDER=%SCRIPT_PATH%\Windows\Tools\EvidenceAnalysis\EvtxExplorer

REM Setting Directory to process that contains evtx files
set EVTLOG_FOLDER=%SCRIPT_PATH%\Collection_%CASE_NAME%\EventLog

REM Setting Parse Result Path
set PARSE_FOLDER=%SCRIPT_PATH%\Collection_%CASE_NAME%\EvtLogParse

:: --------------------------------------------------------------------------------------------------------------------------

echo --------------------------------------------------------------------------------------------------------------------
echo %DATE% %TIME% - Start running EvtxECmd_Script.cmd on %CASE_NAME%
echo --------------------------------------------------------------------------------------------------------------------

if not exist %PARSE_FOLDER% (
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Creating EvtLogParse Folder
	echo --------------------------------------------------------------------------------------------------------------------
	REM Create EvtLogParse Folder
	mkdir %PARSE_FOLDER%
		
	REM Recording the time and date of the eventlogs parsing
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - Recording parse Time
	echo --------------------------------------------------------------------------------------------------------------------
	((date /t) & (time /t)) > %PARSE_FOLDER%\%CASE_NAME%_EvtLogParseTime.txt
	
	REM Parse all events
	echo --------------------------------------------------------------------------------------------------------------------
	echo Parsing all Event Logs
	echo --------------------------------------------------------------------------------------------------------------------
	%EVTXECMD_FOLDER%\EvtxECmd.exe -d %EVTLOG_FOLDER% --csv %PARSE_FOLDER% --csvf eventlog.csv
	
	REM Parse Account Management Events
	echo --------------------------------------------------------------------------------------------------------------------
	echo Parsing Account Management Events
	echo --------------------------------------------------------------------------------------------------------------------
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Security.evtx --inc 4720,4722,4723,4724,4725,4726,4727,4728,4729,4730,4731,4732,4733,4734,4735,4737,4738,4741,4742,4743,4754,4755,4756,4757,4758,4798,4799 --csv %PARSE_FOLDER% --csvf AccountManagement.csv
	
	REM Parse Account Logon and Logon Events
	echo --------------------------------------------------------------------------------------------------------------------
	echo Parsing Account Logon and Logon Events
	echo --------------------------------------------------------------------------------------------------------------------
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Security.evtx --inc 4624,4625,4634,4647,4648,4672,4778,4779 --csv %PARSE_FOLDER% --csvf AccountLogon.csv
	
	REM Parse Access to Shared Objects Events
	echo --------------------------------------------------------------------------------------------------------------------
	echo Parsing Access to Shared Objects Events
	echo --------------------------------------------------------------------------------------------------------------------
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Security.evtx --inc 5140,5142,5143,5144,5145 --csv %PARSE_FOLDER% --csvf NetworkShare.csv
	
	REM Parse Scheduled task activity Events
	echo --------------------------------------------------------------------------------------------------------------------
	echo Parsing Scheduled task activity Events
	echo --------------------------------------------------------------------------------------------------------------------
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Microsoft-Windows-TaskScheduler%%4Operational.evtx --inc 106,140,141,200,201 --csv %PARSE_FOLDER% --csvf TaskScheduler.csv
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Security.evtx --inc 4698,4699,4700,4701,4702 --csv %PARSE_FOLDER% --csvf ObjectAccess.csv
	
	REM Parse Object Handle Auditing Events
	echo --------------------------------------------------------------------------------------------------------------------
	echo Parsing Object Handle Events
	echo --------------------------------------------------------------------------------------------------------------------
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Security.evtx --inc 4656,4657,4658,4660,4663 --csv %PARSE_FOLDER% --csvf ObjectHandle.csv
	
	REM Parse Policy Changes Auditing Event
	echo --------------------------------------------------------------------------------------------------------------------
	echo Parsing Audit Policy Changes Events
	echo --------------------------------------------------------------------------------------------------------------------
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Security.evtx --inc 4719,1102 --csv %PARSE_FOLDER% --csvf AuditPolicyChange.csv
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\System.evtx --inc 104 --csv %PARSE_FOLDER% --csvf AuditPolicyChange_System.csv
	
	REM Parse Windows Services Auditing Event
	echo --------------------------------------------------------------------------------------------------------------------
	echo Parsing Audit Windows Services Events
	echo --------------------------------------------------------------------------------------------------------------------
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Security.evtx --inc 6005,6006,7034,7036,7040,7045,4697 --csv %PARSE_FOLDER% --csvf AuditWindowsService.csv
	
	REM Parse WiFi Connection Event
	echo --------------------------------------------------------------------------------------------------------------------
	echo Parsing WiFi Connection Events
	echo --------------------------------------------------------------------------------------------------------------------
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Security.evtx --inc 8001,8002 --csv %PARSE_FOLDER% --csvf WirelessLAN.csv
	
	REM Parse Process Tracking Event
	:: Enable Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Audit Policy -> Audit process tracking and
	::		  Computer Configuration -> Administrative Templates -> System -> Audit Process Creation -> Include command line in process creation events
	echo --------------------------------------------------------------------------------------------------------------------
	echo Parsing Process Tracking Events
	echo --------------------------------------------------------------------------------------------------------------------
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Security.evtx --inc 4688,5031,5152,5154,5156,5157,5158,5159 --csv %PARSE_FOLDER% --csvf TrackProcess.csv
	
	REM Parse Program Execution Event
	echo --------------------------------------------------------------------------------------------------------------------
	echo Parsing Program Execution Events
	echo --------------------------------------------------------------------------------------------------------------------
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Microsoft-Windows-AppLocker%%4EXE.evtx --csv %PARSE_FOLDER% --csvf AppLocker.csv
	
	REM Parse Sysmon Event
	echo --------------------------------------------------------------------------------------------------------------------
	echo Parsing Sysmon Events
	echo --------------------------------------------------------------------------------------------------------------------
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Microsoft-Windows-Sysmon%%4Operational.evtx --inc 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,255 --csv %PARSE_FOLDER% --csvf Sysmon.csv
	
	REM Parse PowerShell Event
	echo --------------------------------------------------------------------------------------------------------------------
	echo Parsing PowerShell Events
	echo --------------------------------------------------------------------------------------------------------------------
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Microsoft-Windows-PowerShell%%4Operational.evtx --inc 4103,4104 --csv %PARSE_FOLDER% --csvf PowerShell.csv
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f "%EVTLOG_FOLDER%\Windows PowerShell.evtx" --inc 400,800 --csv %PARSE_FOLDER% --csvf PowerShell.csv
		
	REM Parse Windows Defender suspicious Event
	echo --------------------------------------------------------------------------------------------------------------------
	echo Parsing Windows Defender suspicious Events
	echo --------------------------------------------------------------------------------------------------------------------
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f "%EVTLOG_FOLDER%\Microsoft-Windows-Windows Defender%%4Operational.evtx" --inc 1006,1007,1008,1013,1015,1116,1117,1118,1119,5001,5004,5007,5010,5012 --csv %PARSE_FOLDER% --csvf WindowsDefender.csv
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f "%EVTLOG_FOLDER%\Microsoft-Windows-Windows Defender%%4WHC.evtx" --csv %PARSE_FOLDER% --csvf WindowsDefenderWHC.csv
		
	REM Parse the Remote Desktop Protocol relative events
	echo --------------------------------------------------------------------------------------------------------------------
	echo Parsing the Remote Desktop Protocol Relation Events
	echo --------------------------------------------------------------------------------------------------------------------
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Microsoft-Windows-TerminalServices-LocalSessionManager%%4Operational.evtx --inc 21,22,23,24,25,39,40 --csv %PARSE_FOLDER% --csvf RDP_LocalSessionManager.csv
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Microsoft-Windows-TerminalServices-RemoteConnectionManager%%4Operational.evtx --inc 1149,1158 --csv %PARSE_FOLDER% --csvf RDP_RemoteConnectionManager.csv
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%%4Operational.evtx --inc 131 --csv %PARSE_FOLDER% --csvf RdpCoreTS.csv
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Security.evtx --inc 4624,4625,4634,4647,4778,4779 --csv %PARSE_FOLDER% --csvf RDP_Security.csv
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\System.evtx --inc 9009 --csv %PARSE_FOLDER% --csvf RDP_System.csv

	REM more +1 %PARSE_FOLDER%\RDP_LocalSessionManager.csv > %PARSE_FOLDER%\RDP_LocalSessionManager.csv
	REM more +1 %PARSE_FOLDER%\RDP_System.csv > %PARSE_FOLDER%\RDP_System.csv
	REM copy %PARSE_FOLDER%\*.csv %PARSE_FOLDER%\RDP.csv 
	
	echo --------------------------------------------------------------------------------------------------------------------
	echo %DATE% %TIME% - %CASE_NAME% Eventlogs Parsing Finished.
	echo --------------------------------------------------------------------------------------------------------------------

) else echo %CASE_NAME% Eventlog has already parsed.
