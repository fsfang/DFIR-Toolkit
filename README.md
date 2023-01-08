# DFIR-Toolkit

```
.
│
└───📁Linux
│   └───📁LiME
│   │
│   └───📁Scripts
│       │   🗎IR_Script.sh
│       └───🗎crtime.sh
│   
└───📁OS X
│   └───🗎IR_Script.sh
│  
└───📁Windows
    └───📁Scripts
    │   │    🗎DF_Script.bat
    │   │    🗎dumpcap.bat
    │   │    🗎EvtxECmd_Script.bat
    │   │    🗎IR_Script.bat
    │   └─── 🗎RegRipper_Script.bat
    └───📁Tools
        │    📁CryptoCurrency
        │    📁DiskImage
        │    📁EvidenceAnalysis
        │    📁EvidenceCollection
        │    📁LogAnalysis
        │    📁MemoryAnalysis
        │    📁Miscellaneous
        └─── 📁Webshell-Scan
```
## Windows
### DF Script

![DF_Script](https://user-images.githubusercontent.com/16744374/211188008-6ab676c3-7de5-4599-8696-1bc50cb09735.png)

- Case Name
- System Drive: mounting drive
- legacy OS: Enter 1 if run on XP, 2000, 2003 Windows operation system platform

#### Collecting artifacts and parsing automatically

- System Timeline (MAC)
- Automatically Start Programs
    - Task files
- Registry (System, Software, Security, SAM, Amcache.hve(Win8+), USRCLASS.DAT, NTUSER.DAT)
    - AmcacheParser
    - SBECmd
    - Call RegRipper_Script.bat
- Recent files (AutomaticDestinations, CustomDestinations, *.lnk)
    - JLECmd
- Bitmap Cache
    - bmc-tools
- PowerShell console log
- ActivitiesCache.db (Win10)
    - WxTCmd
- FTP logs (FileZilla, WinSCP)
- Event Logs (AppEvent.evt, SecEvent.evt, SysEvent.evt, *.evtx)
    - Call EvtxECmd_Script.bat
- MBR
- MFT, LogFile, UsnJrnl
    - MFTECmd
- Shimcache
    - AppCompatCacheParser
- Prefetch (*.pf)
    - PECmd
    - winprefetchview
- Web Servers logs
    - inetpub
    - nginx
- Windows exe, dll sign information
    - sigcheck
- $Recycle.Bin
- Windows.edb
- SRUM
    - SrumECmd
- AntiVirus logs (Avast, AVG, ESET, McAfee, Sophos, Symantec)

### IR Script

![IR_Script](https://user-images.githubusercontent.com/16744374/211188017-33c79e9a-1472-440a-b35e-bf91f5dabaaf.png)

#### Setting Script Variables

- %1 - system drive: default (C:)
- Script Drive: `SCRIPT_DRIVE=%~d0`
- Collection Folder: `%SCRIPT_DRIVE%\Collection_%COMPUTERNAME%`
- CollectFilesTools Path: `%SCRIPT_DRIVE%\Windows\Tools\EvidenceCollection`
- AnalysisTools Path: `%SCRIPT_DRIVE%\Windows\Tools\EvidenceAnalysis`

#### Collecting artifacts and parsing automatically

- System Info
- System Timeline (MAC)
- Network Activity
    - ipconfig
    - route
    - nbtstat
    - netstat
    - arp
    - net session
    - net share
    - promqry
- User accounts, Logon users
    - net user
    - net user Administrator
    - net localgroup
    - net localgroup Administrators
    - PsLoggedon
- Processes Information
    - tasklist
    - pslist
    - Listdlls
    - handle
    - PsService
- Automatically Start Programs
    - at
    - schtasks
    - Task files
- Registry (System, Software, Security, SAM, Amcache.hve(Win8+), USRCLASS.DAT, NTUSER.DAT)
    - AmcacheParser
    - SBECmd
- Recent files (AutomaticDestinations, CustomDestinations, *.lnk)
    - JLECmd
- Bitmap Cache
    - bmc-tools
- PowerShell console log
- ActivitiesCache.db (Win10)
    - WxTCmd
- FTP logs (FileZilla, WinSCP)
- Event Logs (AppEvent.evt, SecEvent.evt, SysEvent.evt, *.evtx)
- MBR
- MFT, LogFile, UsnJrnl
    - MFTECmd
- Shimcache
    - AppCompatCacheParser
    - ShimCacheParser_PY
- Prefetch (*.pf)
    - PECmd
    - winprefetchview
- Web Servers logs
    - inetpub
    - nginx
- Windows exe, dll sign information
    - sigcheck
- $Recycle.Bin
- Windows.edb
- SRUM
    - SrumECmd
- AntiVirus logs (Avast, AVG, ESET, McAfee, Sophos, Symantec)

> Note: Acquiring Memory default is disabled

### EvtxECmd Script (*.evtx)

#### Setting Script Variables

- %1 - Case Name
- Script Drive: `SCRIPT_DRIVE=%~d0`
- EvtxECmd.exe Path: `%SCRIPT_PATH%\Windows\Tools\EvidenceAnalysis\EvtxExplorer`
- Event log folder Path: `%SCRIPT_PATH%\Collection_%CASE_NAME%\EventLog`
- Parse Result Path: `%SCRIPT_PATH%\Collection_%CASE_NAME%\EvtLogParse`

#### Parse Event Logs

- All events
- Account management (Security.evtx)
- Account Logon and Logon Events (Security.evtx)
- Network Share Objects (Security.evtx)
- Scheduled task activity Events
    - Task Scheduler (Microsoft-Windows-TaskScheduler%%4Operational.evtx)
    - Object Access (Security.evtx)
- Object Handle Auditing (Security.evtx)
- Policy Changes Auditing
    - Audit Policy Change (Security.evtx)
    - Audit Policy Change System (System.evtx)
- Windows Services Auditing (Security.evtx)
- WiFi Connection (Security.evtx)
- Process Tracking (Security.evtx) ***EID: 4688 Default disabled***
- Program Execution (Microsoft-Windows-AppLocker%%4EXE.evtx)
- Sysmon Events (Microsoft-Windows-Sysmon%%4Operational.evtx) ***Default No Such File***
- PowerShell Events
    - PowerShell (Microsoft-Windows-PowerShell%%4Operational.evtx)
    - (Windows PowerShell.evtx)
- Windows Defender
    - Windows Defender (Microsoft-Windows-Windows Defender%%4Operational.evtx)
    - WHC (Microsoft-Windows-Windows Defender%%4WHC.evtx)
- Remote Desktop Protocol
    - RDP_LocalSessionManager (Microsoft-Windows-TerminalServices-LocalSessionManager%%4Operational.evtx)
    - RDP_RemoteConnectionManager (Microsoft-Windows-TerminalServices-RemoteConnectionManager%%4Operational.evtx)
    - RDP_Security (Security.evtx)
    - RDP_System (System.evtx)

### RegRipper Script

#### Setting Script Variables

- %1 - Case Name
- Script Drive: `SCRIPT_DRIVE=%~d0`
- rip.exe Path: `%SCRIPT_PATH%\Windows\Tools\EvidenceAnalysis\RegRipper3.0-master`
- registry folder Path: `%SCRIPT_PATH%\Collection_%CASE_NAME%\Registry`
- Parse Result Path: `%SCRIPT_PATH%\Collection_%CASE_NAME%\RegParse`

#### Parses Registry Hive

- At
- SAM
- SRUM
- UserActivity
- AppCompatCache
    - appcompatcache (SYSTEM)
    - shimcache (SYSTEM)
-  WindowsPrefetch
    - Prefetch (SYSTEM)
- SystemConfiguration
- SoftwareExecutedHistory

## Linux
### IR Script

![IR_Scritp_linux](https://user-images.githubusercontent.com/16744374/211159961-97c84fe5-4c97-408b-9f2c-0dccd63f9a45.png)

**Make sure executed script as root or with sudo command.**

```bash
./IR_Script.sh
```

## Collecting artifacts

- System state and Configuration
    - `uptime`
    - Operating system version: `uname -a`
    - Mounted filesystems: `df`, `mount`
    - Loaded kernel modules: `lsmod`
- Network and Connection State
    - Network interfaces: `ifconfig -a`
    - Network connections: `netstat -anlp`
    - Routing Tables: `netstat -rn`, `route`
- Processes State
    - Open Files: `lsof -V`
    - Running Processes: `ps -ef`, `ps aux --forest`, `pstree -ah`
- Users
    - `cat /etc/passwd`
    - `cat /etc/shadow`
    - Login user session: `w`
    - `who -H`
    - Users past and present: `last`
    - failed login attempts: `lastb`
- Timeline (Access Date;Access Time;Modify Date;Modify Time;Change Date;Change Time;Permissions;UID;Username;GID;Groupname;Size;File)
    - `find / -printf "%Ax;%AT;%Tx;%TT;%Cx;%CT;%m;%U;%u;%G;%g;%s;%p\n"`
- bash_history
    
    ```bash
    find /home -type f -regextype posix-extended -regex '/home/[a-zA-Z\.]+(/\.bash_history)'
    find /root -maxdepth 1 -type f -regextype posix-extended -regex '/root/\.bash_history'
    ```
    
- /var/log
    
    ```bash
    find /var/log -type f -regextype posix-extended -regex '/var/log/[a-zA-Z\.]+(/[a-zA-Z\.]+)*'
    ```
    
    ```bash
    cp /var/log/*.log*
    ```
    
- crontab
    
    ```bash
    cp -r /etc/cron*
    ```
    
- utmp/wtmp/btmp
    
    ```bash
    utmpdump /var/run/utmp
    utmpdump /var/log/wtmp
    utmpdump /var/log/btmp
    ```
    
    > Note: `/var/log/wtmp` - all valid past logins
    > 
    > 
    >           `/var/log/btmp` - bad logins
    > 
    >           `/var/log/lastlog` - recently login user
    > 
    >           `/var/run/utmp` - current login user → in memory
    > 
- disk image file **(default disabled)**
    
    ```bash
    sudo fdisk -l
    ```
    
    ```bash
    dd if=/dev/INPUT/DEVICE-NAME-HERE conv=sync,noerror bs=64K | gzip -c > /path/to/my-disk.image.gz
    ```

# crtime.sh
Get File Creation Date/Time
```bash
./crtime.sh file
```

## OS X
### IR Script

<img width="1057" alt="IR_Scritp_osx" src="https://user-images.githubusercontent.com/16744374/211160275-d7d0dcb7-3ca6-43c5-b556-95f6ee77b21d.png">

**Make sure executed script as root or with sudo command.**

```bash
./IR_Script.sh
```

> Note: Conver file from DOS to UNIX via VIM: `:set fileformat=unix`
> 

## OS X File System

- User: User specific files
- Local: Apps/Resources
- System
- Network

## Collecting artifacts

- System Information
    - uptime
    - Name of the computer: `hostname`
    - Operating system version: `uname -a`, `sw_vers`
    - Gatekeeper status: `spctl --status`
    - To know system using what bash version: `bash --version`
- UserInfo
    - User identity and information: `id`, `groups`, `finger -m`
    - Current user id and name: `whoami`
    - Currently logged on users: `who`
    - Login user session: `w`
    - Users past and present: `last`
    - Command history list: `history`
- Network Activity Information
    - Network status: `netstat`
    - Routing table: `netstat -ru`
    - networksetup -listallhardwareports
    - Network connections sorted by process: `lsof -i`
    - Arp table: `arp -a`
    - SMB share: `smbutil statshares -a`
    - Certificates used by system: `security dump-trust-settings`
    - Network interfaces: `ifconfig`
- Processes Information
    - Running Processes: `ps aux`, `ps axo user, pid, ppid, start, command`
    - Files that a process open: `lsof`
- Hard Drive Information
    - Information of connected hard drives: `diskutil list`
    - Mounted filesystems: `df -h`, `du -h`
- Collecting Startup Information
    - Currently loaded launch agents and daemons: `launchctl list`
    - At task: `atq`
- Browsing History
    - Safari
    - Chrome
    - Firefox
