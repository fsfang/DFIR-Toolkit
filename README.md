# DFIR-Toolkit

```
.
│
└───📁 Linux
│   └───📁 LiME
│   │
│   └───📁 Scripts
│       │   🗎 IR_Script.sh
│       └── 🗎 crtime.sh
│   
└───📁 OS X
│   └───🗎 IR_Script.sh
│  
└───📁 Windows
    └───📁 Scripts
    │   └── 🗎 DFIR.cmd
    └───📁 Tools
    　   │　 📁 EvidenceAnalysis
    　   │　 📁 EvidenceCollection
    　   └── 📁 Miscellaneous
```

## Windows

### DFIR.cmd

![2024-09-17 11_29_05-Windows 10 - VMware Workstation](https://github.com/user-attachments/assets/05191d5f-1a92-4c2b-a00a-f5f820e7b330)

```
Usage:
    DFIR.cmd [options] [optional argument] 

    /?, --help           Display help information
    /v, --version        Display version information
    /m, --memory         Dump memory when live response
    /l, --live           Run in live response mode. Collect artifacts for incident response investigation
    /f, --forensics      Run in forensics mode. Collection artifacts from mounting disk image for investigation
    /p, --parse          Analyze artifacts from collection files

Examples:
    DFIR.cmd /m /l                        Dump physical memory and collect artifacts on local machine
    DFIR.cmd /m /l /p ComputerName        Dump physical memory and collect artifacts with parsing on local machine (.net 6 software requires)
    DFIR.cmd /f F: CaseName /p CaseName   Collecting and parsing artifacts from image mounting drive (F:)
```
#### Setting Script Variables

Modify if needed:
- Script Drive: `SCRIPT_DRIVE=%~d0`
- Collection Folder: `%SCRIPT_DRIVE%\Collection_%COMPUTERNAME%`
- COLLECTION_TOOLS Path: `%SCRIPT_DRIVE%\Windows\Tools\EvidenceCollection`
- ANALYSIS_TOOLS Path: `%SCRIPT_DRIVE%\Windows\Tools\EvidenceAnalysis`

#### Dump memory mode
Memory dumping

```shell
DFIR.cmd /m
```

#### Live response mode
Collect artifacts on local machine.

```shell
DFIR.cmd /l
```

##### Extract artifacts
- System Information
- System Timeline (MAC)
- Network Activity (ipconfig, route, nbtstat, netstat, arp, net session, net share, promqry)
- User accounts, Logon users (net user, net localgroup, loggon user)
- Processes Information (tasklist, pslist, Listdlls, handle, service)
- TaskInfo (Autoruns, at / schtasks, task files)
- Registry Hive (System, Software, Security, SAM, NTUSER.dat, UsrClass,dat, Amcache)
- Recent files (AutomaticDestinations, CustomDestinations, *.lnk)
- Bitmap Cache
- PowerShell console log (ConsoleHost_history)
- ActivitiesCache.db (Win10)
- FTP logs (FileZilla, WinSCP)
- Event Logs (AppEvent.evt, SecEvent.evt, SysEvent.evt, *.evtx)
- MBR
- NTFS Information (MFT, LogFile, UsnJrnl)
- Prefetch(*.pf)
- Web Browser History
- IIS (sites, apppools, apps, wps, modules, config, u_ex*.log)
- Windows exe, dll sign information
- $Recycle.Bin
- Windows.edb
- SRUM (SRUDB.dat)
- USBInfo (setupapi.log)
- WMI (Repository, AutoRecover, mof)
- CryptnetUrlCache (certutil log)
- AntiVirus logs (Avast, AVG, ESET, McAfee, Sophos, Symantec, Windows Defender, F-Secure, Trend Micro)

### Forensics mode
Collect artifacts from disk image.

```shell
DFIR.cmd /f {Mount Point}
```

##### Extract artifacts
- System Timeline (MAC)
- TaskInfo (Autoruns, at / schtasks, task files)
- Registry Hive (System, Software, Security, SAM, NTUSER.dat, UsrClass,dat, Amcache)
- Recent files (AutomaticDestinations, CustomDestinations, *.lnk)
- Bitmap Cache
- PowerShell console log (ConsoleHost_history)
- ActivitiesCache.db (Win10)
- FTP logs (FileZilla, WinSCP)
- Event Logs (AppEvent.evt, SecEvent.evt, SysEvent.evt, *.evtx)
- MBR
- NTFS Information (MFT, LogFile, UsnJrnl)
- Prefetch(*.pf)
- Web Browser History
- Windows exe, dll sign information
- $Recycle.Bin
- Windows.edb
- SRUM (SRUDB.dat)
- USBInfo (setupapi.log)
- WMI (Repository, AutoRecover, mof)
- CryptnetUrlCache (certutil log)
- AntiVirus logs (Avast, AVG, ESET, McAfee, Sophos, Symantec, Windows Defender, F-Secure, Trend Micro)

### Parser mode

```shell
DFIR.cmd /p {CaseName}
```
#### Parse artifacts
- Registry Hive (SAM, Amcache, Schtasks, USBDevice, UserActivity, SystemConfiguration, SoftwareExecutedHistory)
- Bitmap cache
- ActivitiesCache.db
- Windows Event log
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
    - Sysmon Events (Microsoft-Windows-Sysmon%%4Operational.evtx) ***If installed***
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
- NTFS ($MFT, $LogFile, $J)
- Shellbag
- Recent Files (Jump list, LNK files)
- Prefetch
- SRUM

### Chaining

#### Dump memory mode + Live response mode
Dump physical memory and collect artifacts on local machine.
```shell
DFIR.cmd /m /l
```

#### Dump memory mode + Live response mode + Parser mode
Dump physical memory and collect artifacts with parsing on local machine (.net 6 software requires)
```shell
DFIR.cmd /m /l /p ComputerName
```

#### Forensics mode + Parser mode
Collecting and parsing artifacts from image mounting drive.
```shell
DFIR.cmd /f {Mount Point} {CaseName} /p {CaseName}
```

## Linux

### IR Script

**Make sure executed script as root or with sudo command.**

```bash
./IR_Script.sh
```

#### Collecting artifacts

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
    
- utmp / wtmp / btmp
    - utmp: current login user (in memory)
    - wtmp: all valid past logins
    - btmp: bad logins
    
    ```bash
    utmpdump /var/run/utmp
    utmpdump /var/log/wtmp
    utmpdump /var/log/btmp
    ```

- disk image file **(default disabled)**
    
    ```bash
    sudo fdisk -l
    ```
    
    ```bash
    dd if=/dev/INPUT/DEVICE-NAME-HERE conv=sync,noerror bs=64K | gzip -c > /path/to/my-disk.image.gz
    ```

### crtime.sh
Get File Creation Date/Time
```bash
./crtime.sh file
```

## OS X

### IR Script

**Make sure executed script as root or with sudo command.**

```bash
./IR_Script.sh
```

> Note: Conver file from DOS to UNIX via VIM: `:set fileformat=unix`

### OS X File System

- User: User specific files
- Local: Apps/Resources
- System
- Network

### Collecting artifacts

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
    
# Credit
- [Eric Zimmerman's tools](https://ericzimmerman.github.io/#!index.md)
- [RegRipper3.0 ](https://github.com/keydet89/RegRipper3.0)
- [Linux Forensics: With Python and Shell Scripting / Philip Polstra](https://github.com/ppolstra)
- [OS X Incident Response: Scripting and Analysis / Jaron Bradley](https://github.com/jbradley89/osx_incident_response_scripting_and_analysis)
- [Tsurugi Bento toolkit](https://tsurugi-linux.org/index.php)
- **Every awesome free / open source forensic analysis tools**

# TODO
- Windows: Determine legacy system in forensics mode.
