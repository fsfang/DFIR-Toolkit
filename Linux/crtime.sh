# Get file creation time 
# usage: crtime.sh file

for target in "${@}"; do
	inode=$(ls -di "${target}" | cut -d ' ' -f 1)
	fs=$(df "${target}"  | tail -1 | awk '{print $1}')
	crtime=$(sudo debugfs -R 'stat <'"${inode}"'>' "${fs}" 2>/dev/null | 
	grep -oP 'crtime.*--\s*\K.*')
	printf "%s\t%s\n" "${crtime}" "${target}"
done