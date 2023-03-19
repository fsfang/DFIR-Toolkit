@echo off
:: --------------------------------------------------------------------------------------------------------------------------
:: Name:     EvtxECmd_Script.cmd
:: Purpose:  Parse Event Logs.
:: Author:   FS FANG
:: Version:  1.0.3
:: Revision: Jan 2021 v1.0.0 - initial version
::			 Apr 2021 v1.0.1 - add:    RdpCoreTS 131
::			 Nov 2021 v1.0.2 - modify: Could be called by DF_Script.cmd
::           Mar 2023 v1.0.3 - modify: improved display of messages and bug fixes
:: --------------------------------------------------------------------------------------------------------------------------

:: --------------------------------------------------------------------------------------------------------------------------
:: Set Setting Script Variables
:: --------------------------------------------------------------------------------------------------------------------------
REM Define Script Header and Usage
:header
call :setESC

echo.
echo %ESC%%G%EvtxECmd_Script v1.0.3 %ESC%%END%
echo %ESC%%G%Developed by: FS FANG %ESC%%END%
echo %ESC%%G%Parse Event Logs %ESC%%END%
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

REM Setting EvtxECmd.exe Path
set EVTXECMD_FOLDER=%SCRIPT_PATH%\Windows\Tools\EvidenceAnalysis\EvtxExplorer

REM Setting Directory to process that contains evtx files
set EVTLOG_FOLDER=%SCRIPT_PATH%\Collection_%CASE_NAME%\EventLog

REM Setting Parse Result Path
set PARSE_FOLDER=%SCRIPT_PATH%\Collection_%CASE_NAME%\EvtLogParse
:: --------------------------------------------------------------------------------------------------------------------------

echo %ESC%%C%[+] Start running EvtxECmd_Script.cmd for %CASE_NAME% %ESC%%END%

if not exist %PARSE_FOLDER% (
	
	echo %ESC%%C%[+] Creating EvtLogParse Folder for %CASE_NAME% %ESC%%END%
	
	REM Create EvtLogParse Folder
	mkdir %PARSE_FOLDER%
		
	REM Recording the time and date of the eventlogs parsing
    echo [+] Logging initiated for %CASE_NAME% on %DATE% %TIME% > %PARSE_FOLDER%\EvtLogParse.log
    echo %ESC%%C%[+] Logging initiated for %CASE_NAME% on %DATE% %TIME% %ESC%%END%
	
	REM Parse all events	
	echo [+] Parsing all Event Logs on %DATE% %TIME% >> %PARSE_FOLDER%\EvtLogParse.log
	echo %ESC%%C%[+] Parsing all Event Logs on %DATE% %TIME% %ESC%%END%
	
	%EVTXECMD_FOLDER%\EvtxECmd.exe -d %EVTLOG_FOLDER% --csv %PARSE_FOLDER% --csvf eventlog.csv >> %PARSE_FOLDER%\EvtLogParse.log 2>&1
	
	REM Parse Account Management Events	
	echo [+] Parsing Account Management Events on %DATE% %TIME% >> %PARSE_FOLDER%\EvtLogParse.log
	echo %ESC%%C%[+] Parsing Account Management Events on %DATE% %TIME% %ESC%%END%
	
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Security.evtx --inc 4720,4722,4723,4724,4725,4726,4727,4728,4729,4730,4731,4732,4733,4734,4735,4737,4738,4741,4742,4743,4754,4755,4756,4757,4758,4798,4799 --csv %PARSE_FOLDER% --csvf AccountManagement.csv >> %PARSE_FOLDER%\EvtLogParse.log 2>&1
	
	REM Parse Account Logon and Logon Events	
	echo [+] Parsing Account Logon and Logon Events on %DATE% %TIME% >> %PARSE_FOLDER%\EvtLogParse.log
	echo %ESC%%C%[+] Parsing Account Logon and Logon Events on %DATE% %TIME% %ESC%%END%
	
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Security.evtx --inc 4624,4625,4634,4647,4648,4672,4778,4779 --csv %PARSE_FOLDER% --csvf AccountLogon.csv >> %PARSE_FOLDER%\EvtLogParse.log 2>&1
	
	REM Parse Access to Shared Objects Events	
	echo [+] Parsing Access to Shared Objects Events on %DATE% %TIME% >> %PARSE_FOLDER%\EvtLogParse.log
	echo %ESC%%C%[+] Parsing Access to Shared Objects Events on %DATE% %TIME% %ESC%%END%
	
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Security.evtx --inc 5140,5142,5143,5144,5145 --csv %PARSE_FOLDER% --csvf NetworkShare.csv >> %PARSE_FOLDER%\EvtLogParse.log 2>&1
	
	REM Parse Scheduled task activity Events	
	echo [+] Parsing Scheduled task activity Events on %DATE% %TIME% >> %PARSE_FOLDER%\EvtLogParse.log
	echo %ESC%%C%[+] Parsing Scheduled task activity Events on %DATE% %TIME% %ESC%%END%
	
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Microsoft-Windows-TaskScheduler%%4Operational.evtx --inc 106,140,141,200,201 --csv %PARSE_FOLDER% --csvf TaskScheduler.csv >> %PARSE_FOLDER%\EvtLogParse.log 2>&1
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Security.evtx --inc 4698,4699,4700,4701,4702 --csv %PARSE_FOLDER% --csvf ObjectAccess.csv >> %PARSE_FOLDER%\EvtLogParse.log 2>&1
	
	REM Parse Object Handle Auditing Events	
	echo [+] Parsing Object Handle Events on %DATE% %TIME% >> %PARSE_FOLDER%\EvtLogParse.log
	echo %ESC%%C%[+] Parsing Object Handle Events on %DATE% %TIME% %ESC%%END%
    
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Security.evtx --inc 4656,4657,4658,4660,4663 --csv %PARSE_FOLDER% --csvf ObjectHandle.csv >> %PARSE_FOLDER%\EvtLogParse.log 2>&1
	
	REM Parse Policy Changes Auditing Event	
	echo [+] Parsing Audit Policy Changes Events on %DATE% %TIME% >> %PARSE_FOLDER%\EvtLogParse.log
	echo %ESC%%C%[+] Parsing Audit Policy Changes Events on %DATE% %TIME% %ESC%%END%
	
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Security.evtx --inc 4719,1102 --csv %PARSE_FOLDER% --csvf AuditPolicyChange.csv >> %PARSE_FOLDER%\EvtLogParse.log 2>&1
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\System.evtx --inc 104 --csv %PARSE_FOLDER% --csvf AuditPolicyChange_System.csv >> %PARSE_FOLDER%\EvtLogParse.log 2>&1
	
	REM Parse Windows Services Auditing Event	
	echo [+] Parsing Audit Windows Services Events on %DATE% %TIME% >> %PARSE_FOLDER%\EvtLogParse.log
	echo %ESC%%C%[+] Parsing Audit Windows Services Events on %DATE% %TIME% %ESC%%END%
	
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Security.evtx --inc 6005,6006,7034,7036,7040,7045,4697 --csv %PARSE_FOLDER% --csvf AuditWindowsService.csv >> %PARSE_FOLDER%\EvtLogParse.log 2>&1
	
	REM Parse WiFi Connection Event	
	echo [+] Parsing WiFi Connection Events on %DATE% %TIME% >> %PARSE_FOLDER%\EvtLogParse.log
	echo %ESC%%C%[+] Parsing WiFi Connection Events on %DATE% %TIME% %ESC%%END%
	
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Security.evtx --inc 8001,8002 --csv %PARSE_FOLDER% --csvf WirelessLAN.csv >> %PARSE_FOLDER%\EvtLogParse.log 2>&1
	
	REM Parse Process Tracking Event
	::  Enable Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Audit Policy -> Audit process tracking and
	::		   Computer Configuration -> Administrative Templates -> System -> Audit Process Creation -> Include command line in process creation events
	
	echo [+] Parsing Process Tracking Events on %DATE% %TIME% >> %PARSE_FOLDER%\EvtLogParse.log
	echo %ESC%%C%[+] Parsing Process Tracking Events on %DATE% %TIME% %ESC%%END%
	
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Security.evtx --inc 4688,5031,5152,5154,5156,5157,5158,5159 --csv %PARSE_FOLDER% --csvf TrackProcess.csv >> %PARSE_FOLDER%\EvtLogParse.log 2>&1
	
	REM Parse Program Execution Event	
	echo [+] Parsing Program Execution Events on %DATE% %TIME% >> %PARSE_FOLDER%\EvtLogParse.log
	echo %ESC%%C%[+] Parsing Program Execution Events on %DATE% %TIME% %ESC%%END%
	
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f "%EVTLOG_FOLDER%\Microsoft-Windows-AppLocker%%4EXE and DLL.evtx" --csv %PARSE_FOLDER% --csvf AppLocker.csv >> %PARSE_FOLDER%\EvtLogParse.log 2>&1
	
	REM Parse Sysmon Event
	echo [+] Parsing Sysmon Events on %DATE% %TIME% >> %PARSE_FOLDER%\EvtLogParse.log
	echo %ESC%%C%[+] Parsing Sysmon Events on %DATE% %TIME% %ESC%%END%
	
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Microsoft-Windows-Sysmon%%4Operational.evtx --inc 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,255 --csv %PARSE_FOLDER% --csvf Sysmon.csv >> %PARSE_FOLDER%\EvtLogParse.log 2>&1
	
	REM Parse PowerShell Event	
	echo [+] Parsing PowerShell Events on %DATE% %TIME% >> %PARSE_FOLDER%\EvtLogParse.log
	echo %ESC%%C%[+] Parsing PowerShell Events on %DATE% %TIME% %ESC%%END%
	
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Microsoft-Windows-PowerShell%%4Operational.evtx --inc 4103,4104 --csv %PARSE_FOLDER% --csvf PowerShell.csv >> %PARSE_FOLDER%\EvtLogParse.log 2>&1
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f "%EVTLOG_FOLDER%\Windows PowerShell.evtx" --inc 400,800 --csv %PARSE_FOLDER% --csvf PowerShell.csv >> %PARSE_FOLDER%\EvtLogParse.log 2>&1
		
	REM Parse Windows Defender suspicious Event
	echo [+] Parsing Windows Defender suspicious Events on %DATE% %TIME% >> %PARSE_FOLDER%\EvtLogParse.log
	echo %ESC%%C%[+] Parsing Windows Defender suspicious Events on %DATE% %TIME% %ESC%%END%
	
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f "%EVTLOG_FOLDER%\Microsoft-Windows-Windows Defender%%4Operational.evtx" --inc 1006,1007,1008,1013,1015,1116,1117,1118,1119,5001,5004,5007,5010,5012 --csv %PARSE_FOLDER% --csvf WindowsDefender.csv >> %PARSE_FOLDER%\EvtLogParse.log 2>&1
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f "%EVTLOG_FOLDER%\Microsoft-Windows-Windows Defender%%4WHC.evtx" --csv %PARSE_FOLDER% --csvf WindowsDefenderWHC.csv >> %PARSE_FOLDER%\EvtLogParse.log 2>&1
		
	REM Parse the Remote Desktop Protocol relative events	
	echo [+] Parsing the Remote Desktop Protocol Relation Events on %DATE% %TIME% >> %PARSE_FOLDER%\EvtLogParse.log
	echo %ESC%%C%[+] Parsing the Remote Desktop Protocol Relation Events on %DATE% %TIME% %ESC%%END%
	
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Microsoft-Windows-TerminalServices-LocalSessionManager%%4Operational.evtx --inc 21,22,23,24,25,39,40 --csv %PARSE_FOLDER% --csvf RDP_LocalSessionManager.csv >> %PARSE_FOLDER%\EvtLogParse.log 2>&1
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Microsoft-Windows-TerminalServices-RemoteConnectionManager%%4Operational.evtx --inc 1149,1158 --csv %PARSE_FOLDER% --csvf RDP_RemoteConnectionManager.csv >> %PARSE_FOLDER%\EvtLogParse.log 2>&1
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%%4Operational.evtx --inc 131 --csv %PARSE_FOLDER% --csvf RdpCoreTS.csv >> %PARSE_FOLDER%\EvtLogParse.log 2>&1
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\Security.evtx --inc 4624,4625,4634,4647,4778,4779 --csv %PARSE_FOLDER% --csvf RDP_Security.csv >> %PARSE_FOLDER%\EvtLogParse.log 2>&1
	%EVTXECMD_FOLDER%\EvtxECmd.exe -f %EVTLOG_FOLDER%\System.evtx --inc 9009 --csv %PARSE_FOLDER% --csvf RDP_System.csv >> %PARSE_FOLDER%\EvtLogParse.log 2>&1

	REM more +1 %PARSE_FOLDER%\RDP_LocalSessionManager.csv > %PARSE_FOLDER%\RDP_LocalSessionManager.csv
	REM more +1 %PARSE_FOLDER%\RDP_System.csv > %PARSE_FOLDER%\RDP_System.csv
	REM copy %PARSE_FOLDER%\*.csv %PARSE_FOLDER%\RDP.csv 

	echo [+] Finished Parsing Eventlogs for %CASE_NAME% on %DATE% %TIME% >> %PARSE_FOLDER%\EvtLogParse.log
	echo %ESC%%P%[+] Finished Parsing Eventlogs for %CASE_NAME% on %DATE% %TIME% %ESC%%END%
	
) else echo %ESC%%P%[-] %CASE_NAME% Eventlog has already parsed. %ESC%%END%
