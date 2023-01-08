#!/bin/sh
# ------------------------------------------------------------------------------------------
# Name	  : IR_Script.sh
# Purpose : Collect artifacts in a incident response case based on linux operating system.
# Author  : FS FANG
# Version:  1.0.1
# Revision: Oct 2020 v1.0.0 - initial version
#			Nov 2022 v1.0.1 - add:	collect utmp/wtmp/btmp
# ------------------------------------------------------------------------------------------

# Start with ./IR_Script.sh

echo
echo -e '\033[32m     #############     #####    ###  ######  ############  #######\033[m'
echo -e '\033[32m       ##   ##    #   #       #     ##    #   ##   #     #   #    \033[m'
echo -e '\033[32m      ##   ##     #  ##      #     ##     #  ##   #     #   #    \033[m'
echo -e '\033[32m     ##   #######    ####   #     #######   ##   #    #    #    \033[m'
echo -e '\033[32m    ##   ## ##          #  #     ## ##     ##   ####      #   \033[m'
echo -e '\033[32m   ##   ##  ##         #  #     ##  ##    ##   ##        #   \033[m'
echo -e '\033[32m###### ##   ##   ######    ### ##   ##  ##### ##        ##   \033[m'
echo -e	'						      \033[33mv1.0.1 @FFS\033[m'
echo

cname=$(hostname -s)
ts=$(date +%Y%m%d_%H%M%S)
casename=$cname\_$ts

echo "Starting for case $casename on $(date)"

# Create Collection Folder
if [ ! -d $casename ] ; then
   mkdir -p $casename
   mkdir -p $casename/logs/var
   mkdir -p $casename/logs/cron
   mkdir -p $casename/logins
fi

# Collect artifacts
echo -e "++++ Log for date at $(date) ++++\n $(date) \n----end----\n" >> $casename/Collection_$cname.txt
echo -e "++++ Log for hostname at $(date) ++++\n $(hostname) \n----end----\n" >> $casename/Collection_$cname.txt
echo -e "++++ Log for uptime at $(date) ++++\n $(uptime) \n----end----\n" >> $casename/Collection_$cname.txt
echo -e "++++ Log for uname -a at $(date) ++++\n $(uname -a) \n----end----\n" >> $casename/Collection_$cname.txt
echo -e "++++ Log for df at $(date) ++++\n $(df) \n----end----\n" >> $casename/Collection_$cname.txt
echo -e "++++ Log for mount at $(date) ++++\n $(mount) \n----end----\n" >> $casename/Collection_$cname.txt
echo -e "++++ Log for lsmod at $(date) ++++\n $(lsmod) \n----end----\n" >> $casename/Collection_$cname.txt
echo -e "++++ Log for ifconfig -a at $(date) ++++\n $(ifconfig -a) \n----end----\n" >> $casename/Collection_$cname.txt
echo -e "++++ Log for netstat -anlp at $(date) ++++\n $(netstat -anlp) \n----end----\n" >> $casename/Collection_$cname.txt
echo -e "++++ Log for netstat -rn at $(date) ++++\n $(netstat -rn) \n----end----\n" >> $casename/Collection_$cname.txt
echo -e "++++ Log for route at $(date) ++++\n $(route) \n----end----\n" >> $casename/Collection_$cname.txt
echo -e "++++ Log for lsof -V at $(date) ++++\n $(lsof -V) \n----end----\n" >> $casename/Collection_$cname.txt
echo -e "++++ Log for ps -ef at $(date) ++++\n $(ps -ef) \n----end----\n" >> $casename/Collection_$cname.txt
echo -e "++++ Log for ps aux --forest at $(date) ++++\n $(ps aux --forest) \n----end----\n" >> $casename/Collection_$cname.txt
echo -e "++++ Log for pstree -ah at $(date) ++++\n $(pstree -ah) \n----end----\n" >> $casename/Collection_$cname.txt
echo -e "++++ Log for cat /etc/passwd at $(date) ++++\n $(cat /etc/passwd) \n----end----\n" >> $casename/Collection_$cname.txt
echo -e "++++ Log for cat /etc/shadow at $(date) ++++\n $(cat /etc/shadow) \n----end----\n" >> $casename/Collection_$cname.txt
echo -e "++++ Log for w at $(date) ++++\n $(w) \n----end----\n" >> $casename/Collection_$cname.txt
echo -e "++++ Log for who at $(date) ++++\n $(who) \n----end----\n" >> $casename/Collection_$cname.txt
echo -e "++++ Log for last at $(date) ++++\n $(last) \n----end----\n" >> $casename/Collection_$cname.txt
echo -e "++++ Log for lastb at $(date) ++++\n $(lastb) \n----end----\n" >> $casename/Collection_$cname.txt

# Make timeline
echo "Access Date;Access Time;Modify Date;Modify Time;Change Date;Change Time;Permissions;UID;Username;GID;Groupname;Size;File" > $casename/timeline.csv
find / -printf "%Ax;%AT;%Tx;%TT;%Cx;%CT;%m;%U;%u;%G;%g;%s;%p\n" >> $casename/timeline.csv

# Find only files, filename is .bash_history 
# execute echo, cat, and echo for all files found 
echo -e "++++ Log for find user.bash_history at $(date) ++++\n $(
   find /home -type f -regextype posix-extended -regex \
   '/home/[a-zA-Z\.]+(/\.bash_history)' \
   -exec echo -e "\n---dumping history file {} ---\n" \; \
   -exec cat {} \; -exec echo -e "\n---end of dump for history file {} ---\n" \;) \n" >> $casename/bash_history.txt

# Repeat for the root
echo -e "++++ Log for find root.bash_history at $(date) ++++\n $(find /root -maxdepth 1 -type f -regextype posix-extended \
   -regex '/root/\.bash_history' \
   -exec echo -e "---dumping history file {} ---\n" \; \
   -exec cat {} \; -exec echo -e "---end of dump for history file {} ---\n" \;) \n" >> $casename/bash_history.txt

# Log for /var/log files
echo -e "++++ Log for find /var/log at $(date) ++++\n $(find /var/log -type f -regextype posix-extended \
   -regex '/var/log/[a-zA-Z\.]+(/[a-zA-Z\.]+)*' \
   -exec echo -e "---dumping logfile {} ---\n" \; \
   -exec cat {} \; -exec echo -e "---end of dump for logfile {} ---\n" \;) \n" >> $casename/var-logs.txt

# utmpdump for utmp/wtmp/btmp
echo -e "++++ Dump for utmp at $(date) ++++\n $(utmpdump /var/run/utmp) \n----end---- \n" >> $casename/logins/utmp.txt
echo -e "++++ Dump for wtmp at $(date) ++++\n $(utmpdump /var/log/wtmp) \n----end---- \n" >> $casename/logins/wtmp.txt
echo -e "++++ Dump for btmp at $(date) ++++\n $(utmpdump /var/log/btmp) \n----end---- \n" >> $casename/logins/btmp.txt

# copy file in LOGS
cp /var/log/*.log* $casename/logs/var
cp -r /etc/cron* $casename/logs/cron

# create disk image file
# lsblk or fdisk -l to find /dev/sdX
# dd if=/dev/INPUT/DEVICE-NAME-HERE conv=sync,noerror bs=64K | gzip -c > /path/to/my-disk.image.gz
