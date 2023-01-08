# Windows
## IR_Script
Collect artifacts in a incident response case based on Windows operating system.
- v1.0.0 - initial version
- v1.0.1 - add UsrClass.dat
- v1.1.0 - compatible with 32/64-bit operation system
- v1.1.1 - add: create collection folder automatically
- v1.2.0 - add: collect bitmap cache
- v1.3.0 - add: define legacy platform collection procedure
- v1.4.0 - add: collect Antivirus logs, browsing history, web server logs, powershell console logs, FTP related logs
- v1.4.1 - add: collect Win10 Timeline ActivitiesCache.db
- v1.4.2 - add: Collection.log
- v1.4.3 - modify: bug fixes
- v1.4.4 - add: collect and parse UsnJrnl and each fixed disk's NTFS timeline
- v1.4.5 - modify: digital signature tool replaced and bug fixes
## DF_Script
Collect artifacts in a incident response case with image file based on Windows operating system.
- v1.0.0 - initial version
- v1.0.1 - bug fixes
- v1.0.2 - add:	collect and parse UsnJrnl
- v1.0.3 - modify: digital signature tool replaced
## RegRipper_Script
Parse registry hive.
- v1.0.0 - initial version
- v1.0.1 - add: create collection folder automatically
- v1.0.2 - modify: Could be called by DF_Script.cmd
## EvtxECmd_Script
Parse Event Logs.
- v1.0.0 - initial version
- v1.0.1 - Add: RdpCoreTS 131
- v1.0.2 - modify: Could be called by DF_Script.cmd
