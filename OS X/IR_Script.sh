#!/bin/bash
# ------------------------------------------------------------------------------------------
# Name	  : IR_Script.sh
# Purpose : Collect artifacts in a incident response case based on OS X operating system.
# Author  : FS FANG
# Version : 1.0.1
# Revision: JAN 2023 v1.0.0 - initial version
#					 v1.0.1 - modify: improved display of messages
# ------------------------------------------------------------------------------------------

# Console color
R='\033[32m'
G='\033[32m'
Y='\033[33m'
P='\033[35m'
C='\033[36m'
END='\033[m'

echo
echo -e "${G} ___ ___  ___         _      _   ${END}"
echo -e "${G}|_ _| _ \/ __| __ _ _(_)_ __| |_ ${END}"
echo -e "${G} | ||   /\__ \/ _| '_| | '_ \  _|${END}"
echo -e "${G}|___|_|_\|___/\__|_| |_| .__/\__|${C} OS X ver.  ${END}"
echo -e "${G}                       |_|       ${C} v1.0.1 @FFS ${END}"
echo

echo -e "${P}Developed by: FS FANG ${END}"
echo -e "${P}Collect artifacts in a incident response case based on OS X operating system. ${END}"
echo

# check that the script is executed as root
if [[ $EUID -ne 0 ]]; then
	echo -e "${R}This script needs to be executed as root.${END}"
	exit 1
fi

sudo -k

COMPUTERNAME=`scutil --get ComputerName | tr ' ' '_'`
COLLECTION_FOLDER=Collection_$COMPUTERNAME

# Create Collection Folder
if [ ! -d $COLLECTION_FOLDER ] ; then
	mkdir $COLLECTION_FOLDER
	mkdir $COLLECTION_FOLDER/SystemInfo
	mkdir $COLLECTION_FOLDER/UserInfo
	mkdir $COLLECTION_FOLDER/NetworkInfo
	mkdir $COLLECTION_FOLDER/ProcessInfo
	mkdir $COLLECTION_FOLDER/HardDriveInfo
	mkdir $COLLECTION_FOLDER/StartupInfo
	mkdir $COLLECTION_FOLDER/BrowserInfo
fi

echo [+] Logging initiated for $COMPUTERNAME > $COLLECTION_FOLDER/Collection.log
echo -e "${Y}[+] Starting for case $COMPUTERNAME on `date` ${END}"

# Collecting System Information
echo -e [+] Collecting SystemInfo on `date` >> $COLLECTION_FOLDER/Collection.log
echo -e "${Y}[+] Collecting System Information on `date` ${END}"
echo -e "++++ uptime ++++\n `uptime` \n---- end ----\n" >> $COLLECTION_FOLDER/SystemInfo/sysInfo.txt 2>&1
echo -e "++++ hostname ++++\n `hostname` \n---- end ----\n" > $COLLECTION_FOLDER/SystemInfo/sysInfo.txt 2>&1
echo -e "++++ uname -a ++++\n `uname -a` \n---- end ----\n" >> $COLLECTION_FOLDER/SystemInfo/sysInfo.txt 2>&1
echo -e "++++ sw_vers ++++\n `sw_vers` \n---- end ----\n" >> $COLLECTION_FOLDER/SystemInfo/sysInfo.txt 2>&1
echo -e "++++ spctl --status ++++\n `spctl --status` \n---- end ----\n" >> $COLLECTION_FOLDER/SystemInfo/sysInfo.txt 2>&1
echo -e "++++ bash --version ++++\n `bash --version` \n---- end ----\n" >> $COLLECTION_FOLDER/SystemInfo/sysInfo.txt 2>&1

echo -e [+] Collecting UserInfo on `date` >> $COLLECTION_FOLDER/Collection.log
echo -e "${Y}[+] Collecting User Information on `date` ${END}"

echo -e "++++ User List ++++ \n" > $COLLECTION_FOLDER/UserInfo/users.txt 2>&1
ls -la /Users >> $COLLECTION_FOLDER/UserInfo/users.txt 2>&1
dscl . -ls /Users | egrep -v ^_ | while read user
	do 
		echo -e "++++ $user ++++" >> $COLLECTION_FOLDER/UserInfo/users.txt 2>&1
		echo -e "++++ id \($user\) ++++\n `id $user` \n---- end ----\n" >> $COLLECTION_FOLDER/UserInfo/users.txt 2>&1
		echo -e "++++ groups \($user\) ++++\n `groups $user` \n---- end ----\n" >> $COLLECTION_FOLDER/UserInfo/users.txt 2>&1
		echo -e "++++ finger \($user\) ++++\n `finger -m $user` \n---- end ----\n" >> $COLLECTION_FOLDER/UserInfo/users.txt 2>&1
	done
whoami > $COLLECTION_FOLDER/UserInfo/whoami.txt 2>&1
who > $COLLECTION_FOLDER/UserInfo/who.txt 2>&1
w > $COLLECTION_FOLDER/UserInfo/w.txt 2>&1
last > $COLLECTION_FOLDER/UserInfo/last.txt 2>&1
history > $COLLECTION_FOLDER/UserInfo/history.txt 2>&1

# Collecting Network Activity Information
echo -e [+] Collecting Network Activity Information on `date` >> $COLLECTION_FOLDER/Collection.log
echo -e "${Y}[+] Collecting Network Activity Information on `date` ${END}"
netstat > $COLLECTION_FOLDER/NetworkInfo/netstat.txt 2>&1
netstat -ru > $COLLECTION_FOLDER/NetworkInfo/netstat_ru.txt 2>&1
networksetup -listallhardwareports > $COLLECTION_FOLDER/NetworkInfo/networksetup_listallhadwarereports.txt 2>&1
lsof -i > $COLLECTION_FOLDER/NetworkInfo/lsof_i.txt 2>&1
arp -a > $COLLECTION_FOLDER/NetworkInfo/arp_a.txt 2>&1
smbutil statshares -a > $COLLECTION_FOLDER/NetworkInfo/smbutil_statshares.txt 2>&1
security dump-trust-settings > $COLLECTION_FOLDER/NetworkInfo/security_dump_trust_settings.txt 2>&1
ifconfig > $COLLECTION_FOLDER/NetworkInfo/ifconfig.txt 2>&1
smbutil statshares -a > $COLLECTION_FOLDER/NetworkInfo/smbutil_statshares.txt 2>&1

# Collecting Running Processes Information
echo -e [+] Collecting Running Processes Information on `date` >> $COLLECTION_FOLDER/Collection.log
echo -e "${Y}[+] Collecting Running Processes Information on `date` ${END}"
ps aux > $COLLECTION_FOLDER/ProcessInfo/ps_aux.txt 2>&1
ps axo user,pid,ppid,start,command > $COLLECTION_FOLDER/ProcessInfo/ps_axo.txt 2>&1
lsof > $COLLECTION_FOLDER/ProcessInfo/lsof.txt 2>&1

# Collecting Hard Drive Information
echo -e [+] Collecting Hard Drive Information on `date` >> $COLLECTION_FOLDER/Collection.log
echo -e "${Y}[+] Collecting Hard Drive Information on `date` ${END}"
echo -e "++++ diskutil list ++++\n `diskutil list` \n---- end ----\n" > $COLLECTION_FOLDER/HardDriveInfo/hardDriveInfo.txt 2>&1
echo -e "++++ df -h ++++\n `df -h` \n---- end ----\n" >> $COLLECTION_FOLDER/HardDriveInfo/hardDriveInfo.txt 2>&1
echo -e "++++ du -h ++++\n `du -h` \n---- end ----\n" >> $COLLECTION_FOLDER/HardDriveInfo/hardDriveInfo.txt 2>&1

# Collecting Startup Information
echo -e [+] Collecting Startup Information on `date` >> $COLLECTION_FOLDER/Collection.log
echo -e "${Y}[+] Collecting Startup Information on `date` ${END}"
echo -e "++++ launchctl list ++++\n `launchctl list` \n---- end ----\n" > $COLLECTION_FOLDER/StartupInfo/startupInfo.txt 2>&1
echo -e "++++ atq ++++\n `atq` \n---- end ----\n" >> $COLLECTION_FOLDER/StartupInfo/startupInfo.txt 2>&1

# Collecting Browsing History
echo -e [+] Collecting Browsing History on `date` >> $COLLECTION_FOLDER/Collection.log
echo -e "${Y}[+] Collecting Browsing History on `date` ${END}"
dscl . -ls /Users | egrep -v ^_ | while read user
do
	# check for and copy Safari data
	if [ -d "/Users/$user/Library/Safari/" ]; then
		plutil -convert xml1 /Users/$user/Library/Safari/History.plist -o "$COLLECTION_FOLDER/BrowserInfo/$user"_safariHistory.plist >> $COLLECTION_FOLDER/Collection.log 2>&1
		plutil -convert xml1 /Users/$user/Library/Safari/Downloads.plist -o "$COLLECTION_FOLDER/BrowserInfo/$user"_safariDownloads.plist >> $COLLECTION_FOLDER/Collection.log 2>&1

		ditto "/Users/$user/Library/Safari/History.db" "$COLLECTION_FOLDER/BrowserInfo/$user"_safariHistory.db >> $COLLECTION_FOLDER/Collection.log 2>&1
	fi
	# check for and copy Chrome data
	if [ -d "/Users/$user/Library/Application Support/Google/Chrome/" ]; then
		ditto "/Users/$user/Library/Application Support/Google/Chrome/Default/History" "$COLLECTION_FOLDER/BrowserInfo/$user"_chromeHistory.db >> $COLLECTION_FOLDER/Collection.log 2>&1
	fi
	
	#check for and copy Firefox data
	if [ -d "/Users/$user/Library/Application Support/Firefox/" ]; then
		for PROFILE in /Users/$user/Library/Application\ Support/Firefox/Profiles/*; do
			ditto "$PROFILE/places.sqlite" "$COLLECTION_FOLDER/BrowserInfo/$user"_firefoxHistory.db >> $COLLECTION_FOLDER/Collection.log 2>&1
		done
	fi
done

echo -e [+] Collecting finished on `date` >> $COLLECTION_FOLDER/Collection.log
echo -e "${P}[+] Collecting finished on `date` ${END}"

# Archiving Data
#echo -e "${Y}[+] Archiving Data on `date` >> $COLLECTION_FOLDER/Collection.log ${END}"
#ditto --zlibCompressionLevel 5 -k -c . $COMPUTERNAME$now.zip
