Introduction
This a console application that copy files off NTFS volumes by using low level disk reading method. 

Syntax
RawCopy /ImageFile:FullPath\ImageFilename /ImageVolume:[1,2...n] /FileNamePath:FullPath\Filename /OutputPath:FullPath /AllAttr:[0|1] /RawDirMode:[0|1|2] /WriteFSInfo:[0|1] /TcpSend:[0|1]

Explanation of parameters
/ImageFile:
The full path and filename of an image file to extract from. If this param is used, then /ImageVolume: must be set. Optional.
/ImageVolume:
The volume number to extract from. If volume is not NTFS nothing will be extracted. Only used with /ImageFile:.
/FileNamePath:
The full path and filename of file to extract. Can also be in the form of Volume:MftRef. Mandatory.
/OutputPath:
The output path to extract file to. Optional. If omitted, then extract path defaults to program directory.
/OutputName:
The output filename. Optional. If omitted, then filename be that of the original filename. Only used to override the original filename.
/AllAttr:
Boolean flag to trigger extraction of all attributes. Optional. Defaults to 0.
/RawDirMode:
An optional directory listing mode. 0 is no print. 1 is detailed print. 2 is basic print. If omitted it defaults to 0. Can be used in conjunction with any of the other parameters, however in order for this it is not possible to define FileNamePath with an MftRef.
/WriteFSInfo:
An optional boolean flag for writing a file with some volume information into VolInfo.txt in the defined output directory.
/TcpSend
An optional boolean flag for indicating that output should be sent over network. If this flag is set, then /OutputPath: value must be IP:PORT or DOMAIN:PORT

This tool will let you copy files that usually are not accessible because the system has locked them. For instance the registry hives like SYSTEM and SAM. Or files inside the "System Volume Information". Or pagefile.sys. Or any file on the filesystem.

It supports input file specified either with full file path, or by its $MFT record number (index number). 

So how do you get the index number of a given file that is not one of the known system files? Since version 1.0.0.13 the functionality of RawDir was ported into RawCopy. That way, one can do a search into directories such as the "System Volume Information" (RawCopy.exe /FileNamePath:"c:\System Volume Information" /RawDirMode:2).

For image files the volume letter in the /FileNamePath: parameter is ignored.

When specifying device paths in /FileNamePath it is possible to access attached devices that does not have any volumes mounted. Examples are HarddiskVolume1, Harddisk0Partition2, HarddiskVolumeShadowCopy1, PhysicalDrive1.

In order to extract files from a shadow copy within an image file, you will have to mount the image file beforehand so that Windows will present a symbolic link to the shadow copy such as \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy60. It is recommended to mount the image with a tool such as Arsenal Image Mounter (which is free).

The /WriteFSInfo: parameter can be useful when scripting since SectorsPerCluster and MFTRecordSize is used with LogFileParser and Mft2Csv.

When using /TcpSend:1 to send output to network you must obviously have something listening on the destination for this to work. For instance netcat. For now, the data is sent as is over network unencrypted.

This version is incompatible with Windows 2000 / NTFS 3.0. I have prepared a special build from v1.0.0.19 that can be used there; https://github.com/jschicht/RawCopy/releases/download/1.0.0.19/RawCopy_v1.0.0.19_.Win2000.zip  Earlier versions have not been tested.


Sample usage

Example for copying the hibernation file off a running system and save it to E:\output\hiberfil_c.sys
RawCopy.exe /FileNamePath:C:\hiberfil.sys /OutputPath:E:\output /OutputName:hiberfil_c.sys

Example for copying the SYSTEM hive off a running system
RawCopy.exe /FileNamePath:C:\WINDOWS\system32\config\SYSTEM /OutputPath:E:\output

Example for extracting the $MFT by specifying its index number, into to the program directory and override the default output filename to MFT_C.bin.
RawCopy.exe /FileNamePath:C:0 /OutputName:MFT_C.bin

Example for extracting MFT reference number 30224 and all attributes including $DATA, and dumping it into C:\tmp:
RawCopy.exe /FileNamePath:C:30224 /OutputPath:C:\tmp /AllAttr:1

Example for accessing a disk image and extracting MftRef ($LogFile) from volume number 2.
RawCopy.exe /ImageFile:e:\temp\diskimage.dd /ImageVolume:2 /FileNamePath:c:2 /OutputPath:e:\out

Example for accessing partition/volume image and extracting file.ext and dumping it into E:\out.
RawCopy.exe /ImageFile:e:\temp\partimage.dd /ImageVolume:1 /FileNamePath:c:\file.ext /OutputPath:e:\out

Example for making a raw dirlisting in detailed mode in c:\$Extend:
RawCopy.exe /FileNamePath:c:\$Extend /RawDirMode:1

Example for making a raw dirlisting in basic mode in c:\System Volume Information inside a disk image file:
RawCopy.exe /ImageFile:e:\temp\diskimage.dd /ImageVolume:1 /FileNamePath:"c:\System Volume Information" /RawDirMode:2

Example for making a raw dirlisting in detailed mode on the root level inside a shadow copy:
RawCopy.exe /FileNamePath:\\.\HarddiskVolumeShadowCopy1:x:\ /RawDirMode:1

Example for extracting $MFT from partition 2 on harddisk 1 and dumping it into e:\out:
RawCopy.exe /FileNamePath:\\.\Harddisk0Partition2:0 /OutputPath:e:\out

Example for extracting $MFT from second volume on PhysicalDrive0, and save it as E:\out\MFT_Pd0Vol2.bin:
RawCopy.exe /FileNamePath:\\.\PhysicalDrive0:0 /ImageVolume:2 /OutputPath:e:\out /OutputName:MFT_Pd0Vol2.bin

Example for extracting $LogFile from system volume and send it over the network:
RawCopy.exe /FileNamePath:c:\$LogFile /TcpSend:1 /OutputPath:10.10.10.10:6666
RawCopy.exe /FileNamePath:c:\$LogFile /TcpSend:1 /OutputPath:www.mypublicdomain.com:6666
