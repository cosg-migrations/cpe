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

# Set Working/Backup Directories
setWorkingDirectory
setBackupDir

# Verify Elements of Config File
checkIp
eth0IP
verifyRMM
verifyDCSet
verifyHostNameSet
verifyDNSSet

# Detect what Linux Distro, Release and Architecture we are running
distroDetect

# Remove Savvis Management Accounts
deSavvisize

# Call function to reconfigure DNS
reconfigureDns

# Call function to delete static routes
deleteRoutes

# Call function to update hostname
setHostname

# Uninstall SIA

# Sysadmin files
getSysAdminZip

# Call function to remove old VMware Tools
removeOldVMwareTools

# Install RHUI
clcRHUIInstall

# Call function to clean YUM repos
cleanPkgMgrCache

# Call function to import VMware package keys
importVMwarePkgKeys

# Call function to create VMware Tools repo
createVMwareToolsRepo

# Call function to install VMware Tools
installVMwareTools

# Call function to verify VMware Tools ware installed
verifyVMwareTools

# Check for POST required packages (bind-utils redhat-lsb libxslt)
checkInstalledPost

# Install POST required packages
installPackages

# Opsware Uninstall
opswareUninstall

# SNMP Reconfigure
snmpdConfig

# Reconfigure SELINUX
selinuxConfig

# Kill IPTABLES
disableIpTables

# Change the root password
changeRootPwd

# Leave the Active Directory Domain
adleave -rf

scriptEnd=`date +%s`
scriptRunTime=$((scriptEnd-scriptStart))

thisDate=`date  "+%Y-%m-%d"`
echo "POST COMPLETED:" $thisDate >> ${workingDir}/run.log

# Reboot the server
echo
echo "Script Run Time: ${scriptRunTime} seconds"
echo
rebootInstance
