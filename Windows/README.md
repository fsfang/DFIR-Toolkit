# Windows
## DFIR.cmd
An artifacts collection and analysis script based on Windows operating system.
- v2.0.1 - modify: bug fixes and add task scheduler files path.
- v2.0.0 - new: merge the extraction and analysis modules into a single script.
- v1.4.7 - add: collect setupapi.log, WMI repository and port proxy detection.
- v1.4.6 - add: collect registry transaction logs to handle unreconciled data (dirty hive), 7zip tool for archive collection, collect recent execution, open files log and scan common directories where malware hide in.
- v1.4.5 - modify: digital signature tool replaced and bug fixes.
- v1.4.4 - add: collect and parse UsnJrnl and each fixed disk's NTFS timeline.
- v1.4.3 - modify: bug fixes.
- v1.4.2 - add: Collection.log.
- v1.4.1 - add: collect Win10 Timeline ActivitiesCache.db.
- v1.4.0 - add: collect Antivirus logs, browsing history, web server logs, powershell console logs, FTP related logs.
- v1.3.0 - new: define legacy platform collection procedure.
- v1.1.2 - add: collect bitmap cache.
- v1.1.1 - add: create collection folder automatically.
- v1.1.0 - new: compatible with 32/64-bit operation system.
- v1.0.1 - add: UsrClass.dat.
- v1.0.0 - initial version.