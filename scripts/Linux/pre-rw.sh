#!/bin/bash

scriptStart=`date +%s`

sourceFiles () {
	echo "ACTION: Reading Variables"
	if [ -r ./${1} ];then
		source ./${1}
	else
		echo "ERROR: "${1}" file is missing or unreadable."
		exit 8
	fi
}


#############################
####       EXECUTE       ####
#############################

# Logging to stdout and stderr
exec 1> >(logger -s -t $(basename $0)) 2>&1

# Read functions file
sourceFiles functions

# Read config file
sourceFiles config

# Determine Running User
whoAmI

# Check for VMware Tools
verifyVMwareTools

# Check VMware Tools Service
checkService vmware-tools

# Set Working/Backup Directories
setWorkingDirectory
setBackupDir

# genRootPasswd &>/dev/null
distroDetect

if [[ "$distroID" == "centos" ]] || [[ "$distroID" == "redhat" ]]; then
	sshKeys
	sshdConfig
	selinuxConfig
	checkInstalledRwPre
	installPackages
	forceNetCatUpdate
	initdConfig iscsi
	checkGenPasswdFile
elif [[ "$distroID" == "ubuntu" ]]; then
	echo "ERROR: Unsupported OS, please configure manually."
#	echo "ACTION: Installing Packages"
#	apt-get --assume-yes remove open-iscsi
#	apt-get --assume-yes install "${reqPkgUbuntu[*]}"
#	dnsFix
fi

thisDate=`date  "+%Y-%m-%d"`
echo "PRE COMPLETED: "$thisDate
echo "PRE COMPLETED: "$thisDate >> ${workingDir}/run.log
echo