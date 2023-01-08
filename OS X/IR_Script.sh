#!/bin/bash
# ------------------------------------------------------------------------------------------
# Name	  : IR_Script.sh
# Purpose : Collect artifacts in a incident response case based on OS X operating system.
# Author  : FS FANG
# Version:  1.0.0
# Revision: JAN 2023 v1.0.0 - initial version
# ------------------------------------------------------------------------------------------

echo
echo -e '\033[32m     #############     #####    ###  ######  ############  #######\033[m'
echo -e '\033[32m       ##   ##    #   #       #     ##    #   ##   #     #   #    \033[m'
echo -e '\033[32m      ##   ##     #  ##      #     ##     #  ##   #     #   #    \033[m'
echo -e '\033[32m     ##   #######    ####   #     #######   ##   #    #    #    \033[m'
echo -e '\033[32m    ##   ## ##          #  #     ## ##     ##   ####      #   \033[m'
echo -e '\033[32m   ##   ##  ##         #  #     ##  ##    ##   ##        #   \033[m'
echo -e '\033[32m###### ##   ##   ######    ### ##   ##  ##### ##        ##   \033[m'
echo -e	'						      \033[33mv1.0.0 @FFS\033[m'
echo

COMPUTERNAME=`scutil --get ComputerName | tr ' ' '_'`
COLLECTION_FOLDER=Collection_$COMPUTERNAME

# check that the script is executed as root
if [[ $EUID -ne 0 ]]; then
	echo -e "This script needs to be executed as root."
	exit 1
fi

sudo -k

# if the directory doesn't exist create it
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

echo -e "Start time: `date`"

# Collecting System Information
echo [+] Logging initiated for $COMPUTERNAME > $COLLECTION_FOLDER/Collection.log
echo --------------------------------------------------------------------------------------------------------------------
echo `date` - Recording Collection Time
echo --------------------------------------------------------------------------------------------------------------------

echo [+] `date` - Collecting SystemInfo >> $COLLECTION_FOLDER/Collection.log
echo --------------------------------------------------------------------------------------------------------------------
echo `date` - Collecting System Information
echo --------------------------------------------------------------------------------------------------------------------
echo -e "++++ uptime ++++\n `uptime` \n---- end ----\n" >> $COLLECTION_FOLDER/SystemInfo/sysInfo.txt
echo -e "++++ hostname ++++\n `hostname` \n---- end ----\n" > $COLLECTION_FOLDER/SystemInfo/sysInfo.txt
echo -e "++++ uname -a ++++\n `uname -a` \n---- end ----\n" >> $COLLECTION_FOLDER/SystemInfo/sysInfo.txt
echo -e "++++ sw_vers ++++\n `sw_vers` \n---- end ----\n" >> $COLLECTION_FOLDER/SystemInfo/sysInfo.txt
echo -e "++++ spctl --status ++++\n `spctl --status` \n---- end ----\n" >> $COLLECTION_FOLDER/SystemInfo/sysInfo.txt
echo -e "++++ bash --version ++++\n `bash --version` \n---- end ----\n" >> $COLLECTION_FOLDER/SystemInfo/sysInfo.txt

echo [+] `date` - Collecting UserInfo >> $COLLECTION_FOLDER/Collection.log
echo --------------------------------------------------------------------------------------------------------------------
echo `date` - Collecting User Information
echo --------------------------------------------------------------------------------------------------------------------
echo -e "++++ User List ++++ \n" > $COLLECTION_FOLDER/UserInfo/users.txt
ls -la /Users >> $COLLECTION_FOLDER/UserInfo/users.txt
dscl . -ls /Users | egrep -v ^_ | while read user 
	do 
		echo -e "++++ $user ++++" >> $COLLECTION_FOLDER/UserInfo/users.txt
		echo -e "++++ id \($user\) ++++\n `id $user` \n---- end ----\n" >> $COLLECTION_FOLDER/UserInfo/users.txt
		echo -e "++++ groups \($user\) ++++\n `groups $user` \n---- end ----\n" >> $COLLECTION_FOLDER/UserInfo/users.txt
		echo -e "++++ finger \($user\) ++++\n `finger -m $user` \n---- end ----\n" >> $COLLECTION_FOLDER/UserInfo/users.txt
	done
whoami > $COLLECTION_FOLDER/UserInfo/whoami.txt
who > $COLLECTION_FOLDER/UserInfo/who.txt
w > $COLLECTION_FOLDER/UserInfo/w.txt
last > $COLLECTION_FOLDER/UserInfo/last.txt
history > $COLLECTION_FOLDER/UserInfo/history.txt

# Collecting Network Activity Information
echo [+] `date` - Collecting Network Activity Information >> $COLLECTION_FOLDER/Collection.log
echo --------------------------------------------------------------------------------------------------------------------
echo `date` - Collecting Network Activity Information
echo --------------------------------------------------------------------------------------------------------------------
netstat > $COLLECTION_FOLDER/NetworkInfo/netstat.txt
netstat -ru > $COLLECTION_FOLDER/NetworkInfo/netstat_ru.txt
networksetup -listallhardwareports > $COLLECTION_FOLDER/NetworkInfo/networksetup_listallhadwarereports.txt
lsof -i > $COLLECTION_FOLDER/NetworkInfo/lsof_i.txt
arp -a > $COLLECTION_FOLDER/NetworkInfo/arp_a.txt
smbutil statshares -a > $COLLECTION_FOLDER/NetworkInfo/smbutil_statshares.txt
security dump-trust-settings > $COLLECTION_FOLDER/NetworkInfo/security_dump_trust_settings.txt
ifconfig > $COLLECTION_FOLDER/NetworkInfo/ifconfig.txt
smbutil statshares -a > $COLLECTION_FOLDER/NetworkInfo/smbutil_statshares.txt

# Collecting Running Processes Information
echo [+] `date` - Collecting Running Processes Information >> $COLLECTION_FOLDER/Collection.log
echo --------------------------------------------------------------------------------------------------------------------
echo `date` - Collecting Running Processes Information
echo --------------------------------------------------------------------------------------------------------------------
ps aux > $COLLECTION_FOLDER/ProcessInfo/ps_aux.txt
ps axo user,pid,ppid,start,command > $COLLECTION_FOLDER/ProcessInfo/ps_axo.txt
lsof > $COLLECTION_FOLDER/ProcessInfo/lsof.txt

# Collecting Hard Drive Information
echo [+] `date` - Collecting Hard Drive Information >> $COLLECTION_FOLDER/Collection.log
echo --------------------------------------------------------------------------------------------------------------------
echo `date` - Collecting Hard Drive Information
echo --------------------------------------------------------------------------------------------------------------------
echo -e "++++ diskutil list ++++\n `diskutil list` \n---- end ----\n" > $COLLECTION_FOLDER/HardDriveInfo/hardDriveInfo.txt
echo -e "++++ df -h ++++\n `df -h` \n---- end ----\n" >> $COLLECTION_FOLDER/HardDriveInfo/hardDriveInfo.txt
echo -e "++++ du -h ++++\n `du -h` \n---- end ----\n" >> $COLLECTION_FOLDER/HardDriveInfo/hardDriveInfo.txt

# Collecting Startup Information
echo [+] `date` - Collecting Startup Information >> $COLLECTION_FOLDER/Collection.log
echo --------------------------------------------------------------------------------------------------------------------
echo `date` - Collecting Startup Information 
echo --------------------------------------------------------------------------------------------------------------------
echo -e "++++ launchctl list ++++\n `launchctl list` \n---- end ----\n" > $COLLECTION_FOLDER/StartupInfo/startupInfo.txt
echo -e "++++ atq ++++\n `atq` \n---- end ----\n" >> $COLLECTION_FOLDER/StartupInfo/startupInfo.txt

# Collecting Browsing History
echo [+] `date` - Collecting Browsing History >> $COLLECTION_FOLDER/Collection.log
dscl . -ls /Users | egrep -v ^_ | while read user
do
	# check for and copy Safari data
	if [ -d "/Users/$user/Library/Safari/" ]; then
		plutil -convert xml1 /Users/$user/Library/Safari/History.plist -o "$COLLECTION_FOLDER/BrowserInfo/$user"_safariHistory.plist
		plutil -convert xml1 /Users/$user/Library/Safari/Downloads.plist -o "$COLLECTION_FOLDER/BrowserInfo/$user"_safariDownloads.plist

		ditto "/Users/$user/Library/Safari/History.db" "$COLLECTION_FOLDER/BrowserInfo/$user"_safariHistory.db
	fi
	# check for and copy Chrome data
	if [ -d "/Users/$user/Library/Application Support/Google/Chrome/" ]; then
		ditto "/Users/$user/Library/Application Support/Google/Chrome/Default/History" "$COLLECTION_FOLDER/BrowserInfo/$user"_chromeHistory.db
	fi
	
	#check for and copy Firefox data
	if [ -d "/Users/$user/Library/Application Support/Firefox/" ]; then
		for PROFILE in /Users/$user/Library/Application\ Support/Firefox/Profiles/*; do
			ditto "$PROFILE/places.sqlite" "$COLLECTION_FOLDER/BrowserInfo/$user"_firefoxHistory.db
		done
	fi
done

# Archiving Data
#echo [+] `date` - Archiving Data >> $COLLECTION_FOLDER/Collection.log
#echo --------------------------------------------------------------------------------------------------------------------
#echo `date` - Archiving Data
#echo --------------------------------------------------------------------------------------------------------------------
#now=`date`
#ditto --zlibCompressionLevel 5 -k -c . $COMPUTERNAME$now.zip
