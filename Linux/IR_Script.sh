#!/bin/sh
# ------------------------------------------------------------------------------------------
# Name	  : IR_Script.sh
# Purpose : Collect artifacts in a incident response case based on linux operating system.
# Author  : FS FANG
# Version : 1.0.2
# Revision: Oct 2020 v1.0.0 - initial version
#			Nov 2022 v1.0.1 - add:	  collect utmp/wtmp/btmp
#			Mar 2023 v1.0.2 - add:    add Collection.log
#					          modify: improved display of messages
# ------------------------------------------------------------------------------------------

# Start with ./IR_Script.sh

# Console color
R='\033[32m' 
G='\033[32m'
O='\033[33m'
P='\033[35m'
C='\033[36m'
END='\033[m'

echo
echo "${G} ___ ___  ___         _      _   ${END}"
echo "${G}|_ _| _ \/ __| __ _ _(_)_ __| |_ ${END}"
echo "${G} | ||   /\__ \/ _| '_| | '_ \  _|${END}"
echo "${G}|___|_|_\|___/\__|_| |_| .__/\__|${C} Linux ver.  ${END}"
echo "${G}                       |_|       ${C} v1.0.2 @FFS ${END}"
echo

echo ${C}Developed by: FS FANG ${END}
echo ${C}Collect artifacts in a incident response case based on linux operating system. ${END}
echo

COMPUTERNAME=$(hostname -s)
COLLECTION_FOLDER=Collection_$COMPUTERNAME

# Create Collection Folder
if [ ! -d $COLLECTION_FOLDER ] ; then
   mkdir -p $COLLECTION_FOLDER
   mkdir -p $COLLECTION_FOLDER/logs/var
   mkdir -p $COLLECTION_FOLDER/logs/cron
   mkdir -p $COLLECTION_FOLDER/logins
fi

echo [+] Logging initiated for $COMPUTERNAME on $(date) > $COLLECTION_FOLDER/Collection.log
echo ${O}[+] Starting for case $COMPUTERNAME on $(date) ${END}

# Collect System Information
echo [+] Collecting System Information on $(date) >> $COLLECTION_FOLDER/Collection.log
echo ${O}[+] Collecting System Information on $(date) ${END}
echo -e "++++ Log for date at $(date) ++++\n $(date) \n----end----\n" > $COLLECTION_FOLDER/sysInfo.txt 2>>$COLLECTION_FOLDER/Collection.log
echo -e "++++ Log for hostname at $(date) ++++\n $(hostname) \n----end----\n" >> $COLLECTION_FOLDER/sysInfo.txt 2>>$COLLECTION_FOLDER/Collection.log
echo -e "++++ Log for uptime at $(date) ++++\n $(uptime) \n----end----\n" >> $COLLECTION_FOLDER/sysInfo.txt 2>>$COLLECTION_FOLDER/Collection.log
echo -e "++++ Log for uname -a at $(date) ++++\n $(uname -a) \n----end----\n" >> $COLLECTION_FOLDER/sysInfo.txt 2>>$COLLECTION_FOLDER/Collection.log
echo -e "++++ Log for df at $(date) ++++\n $(df) \n----end----\n" >> $COLLECTION_FOLDER/sysInfo.txt 2>>$COLLECTION_FOLDER/Collection.log
echo -e "++++ Log for mount at $(date) ++++\n $(mount) \n----end----\n" >> $COLLECTION_FOLDER/sysInfo.txt 2>>$COLLECTION_FOLDER/Collection.log
echo -e "++++ Log for lsmod at $(date) ++++\n $(lsmod) \n----end----\n" >> $COLLECTION_FOLDER/sysInfo.txt 2>>$COLLECTION_FOLDER/Collection.log
echo -e "++++ Log for ifconfig -a at $(date) ++++\n $(ifconfig -a) \n----end----\n" >> $COLLECTION_FOLDER/sysInfo.txt 2>>$COLLECTION_FOLDER/Collection.log
echo -e "++++ Log for netstat -anlp at $(date) ++++\n $(netstat -anlp) \n----end----\n" >> $COLLECTION_FOLDER/netstat.txt 2>>$COLLECTION_FOLDER/Collection.log
echo -e "++++ Log for netstat -rn at $(date) ++++\n $(netstat -rn) \n----end----\n" >> $COLLECTION_FOLDER/netstat.txt 2>>$COLLECTION_FOLDER/Collection.log
echo -e "++++ Log for route at $(date) ++++\n $(route) \n----end----\n" >> $COLLECTION_FOLDER/netstat.txt 2>>$COLLECTION_FOLDER/Collection.log
echo -e "++++ Log for lsof -V at $(date) ++++\n $(lsof -V) \n----end----\n" >> $COLLECTION_FOLDER/process.txt 2>>$COLLECTION_FOLDER/Collection.log
echo -e "++++ Log for ps -ef at $(date) ++++\n $(ps -ef) \n----end----\n" >> $COLLECTION_FOLDER/process.txt 2>>$COLLECTION_FOLDER/Collection.log
echo -e "++++ Log for ps aux --forest at $(date) ++++\n $(ps aux --forest) \n----end----\n" >> $COLLECTION_FOLDER/process.txt 2>>$COLLECTION_FOLDER/Collection.log
echo -e "++++ Log for pstree -ah at $(date) ++++\n $(pstree -ah) \n----end----\n" >> $COLLECTION_FOLDER/process.txt 2>>$COLLECTION_FOLDER/Collection.log
echo -e "++++ Log for cat /etc/passwd at $(date) ++++\n $(cat /etc/passwd) \n----end----\n" >> $COLLECTION_FOLDER/users.txt 2>>$COLLECTION_FOLDER/Collection.log
echo -e "++++ Log for cat /etc/shadow at $(date) ++++\n $(cat /etc/shadow) \n----end----\n" >> $COLLECTION_FOLDER/users.txt 2>>$COLLECTION_FOLDER/Collection.log
echo -e "++++ Log for w at $(date) ++++\n $(w) \n----end----\n" >> $COLLECTION_FOLDER/users.txt 2>>$COLLECTION_FOLDER/Collection.log
echo -e "++++ Log for who at $(date) ++++\n $(who) \n----end----\n" >> $COLLECTION_FOLDER/users.txt 2>>$COLLECTION_FOLDER/Collection.log
echo -e "++++ Log for last at $(date) ++++\n $(last) \n----end----\n" >> $COLLECTION_FOLDER/users.txt 2>>$COLLECTION_FOLDER/Collection.log
echo -e "++++ Log for lastb at $(date) ++++\n $(lastb) \n----end----\n" >> $COLLECTION_FOLDER/users.txt 2>>$COLLECTION_FOLDER/Collection.log

# Make file system timeline
echo [+] Making file system timeline on $(date) >> $COLLECTION_FOLDER/Collection.log
echo ${O}[+] Making file system timeline on $(date) ${END}
echo "Access Date;Access Time;Modify Date;Modify Time;Change Date;Change Time;Permissions;UID;Username;GID;Groupname;Size;File" > $COLLECTION_FOLDER/timeline.csv 2>>$COLLECTION_FOLDER/Collection.log
find / -printf "%Ax;%AT;%Tx;%TT;%Cx;%CT;%m;%U;%u;%G;%g;%s;%p\n" >> $COLLECTION_FOLDER/timeline.csv 2>>$COLLECTION_FOLDER/Collection.log

# Find only files, filename is .bash_history 
# execute echo, cat, and echo for all files found
echo [+] Collecting user bash history files on $(date) >> $COLLECTION_FOLDER/Collection.log
echo ${O}[+] Collecting user bash history files on $(date) ${END}
echo -e "++++ Log for find user.bash_history at $(date) ++++\n $(
   find /home -type f -regextype posix-extended -regex \
   '/home/[a-zA-Z\.]+(/\.bash_history)' \
   -exec echo -e "\n---dumping history file {} ---\n" \; \
   -exec cat {} \; -exec echo -e "\n---end of dump for history file {} ---\n" \;) \n" >> $COLLECTION_FOLDER/bash_history.txt 2>>$COLLECTION_FOLDER/Collection.log

# Repeat for the root
echo -e "++++ Log for find root.bash_history at $(date) ++++\n $(find /root -maxdepth 1 -type f -regextype posix-extended \
   -regex '/root/\.bash_history' \
   -exec echo -e "---dumping history file {} ---\n" \; \
   -exec cat {} \; -exec echo -e "---end of dump for history file {} ---\n" \;) \n" >> $COLLECTION_FOLDER/bash_history.txt 2>>$COLLECTION_FOLDER/Collection.log

# Log for /var/log files
echo [+] Collecting /var/log files on $(date) >> $COLLECTION_FOLDER/Collection.log
echo ${O}[+] Collecting /var/log files on $(date) ${END}
echo -e "++++ Log for find /var/log at $(date) ++++\n $(find /var/log -type f -regextype posix-extended \
   -regex '/var/log/[a-zA-Z\.]+(/[a-zA-Z\.]+)*' \
   -exec echo -e "---dumping logfile {} ---\n" \; \
   -exec cat {} \; -exec echo -e "---end of dump for logfile {} ---\n" \;) \n" >> $COLLECTION_FOLDER/var-logs.txt 2>>$COLLECTION_FOLDER/Collection.log

# utmpdump for utmp/wtmp/btmp
echo [+] Dumping utmp, wtmp, btmp on $(date) >> $COLLECTION_FOLDER/Collection.log
echo ${O}[+] Dumping utmp, wtmp, btmp on $(date) ${END}
echo -e "++++ Dump for utmp at $(date) ++++\n $(utmpdump /var/run/utmp) \n----end---- \n" >> $COLLECTION_FOLDER/logins/utmp.txt 2>>$COLLECTION_FOLDER/Collection.log
echo -e "++++ Dump for wtmp at $(date) ++++\n $(utmpdump /var/log/wtmp) \n----end---- \n" >> $COLLECTION_FOLDER/logins/wtmp.txt 2>>$COLLECTION_FOLDER/Collection.log
echo -e "++++ Dump for btmp at $(date) ++++\n $(utmpdump /var/log/btmp) \n----end---- \n" >> $COLLECTION_FOLDER/logins/btmp.txt 2>>$COLLECTION_FOLDER/Collection.log

# copy file in LOGS
echo [+] Collecting /var/log and crontab files on $(date) >> $COLLECTION_FOLDER/Collection.log
echo ${O}[+] Collecting /var/log and crontab files on $(date) ${END}
cp /var/log/*.log* $COLLECTION_FOLDER/logs/var
cp -r /etc/cron* $COLLECTION_FOLDER/logs/cron

echo [+] Collecting finished on $(date) >> $COLLECTION_FOLDER/Collection.log
echo ${P}[+] Collecting finished on $(date) ${END}

# create disk image file
# lsblk or fdisk -l to find /dev/sdX
# dd if=/dev/INPUT/DEVICE-NAME-HERE conv=sync,noerror bs=64K | gzip -c > /path/to/my-disk.image.gz