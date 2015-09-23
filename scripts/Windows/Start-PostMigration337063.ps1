[CmdletBinding(SupportsShouldProcess=$false)]
Param (
 
	# New computer name for server in CLC
	[parameter(Mandatory=$true)]
	[Alias("Name")]
	[string[]]$ComputerName,

	# Administrator user password
	[parameter(Mandatory=$false)]
	[Alias("PW")]
	[string]$AdminPassword="",
   
	# Comma-separated list (array) of DNS Server IP Addresses
	[parameter(Mandatory=$true)]
	[Alias("DNS")]
	[string[]]$DNSServers,
    
	# IP Address for the KMS server
	[parameter(Mandatory=$false)]
	[Alias("KMS")]
	[string]$KMSServer="172.17.1.21",
	
    # IP Address for the WEB server
	[parameter(Mandatory=$true)]
	[Alias("WEB")]
	[string]$WebServer,
	
    # File name for VMware Tools executable, if not default value
	[parameter(Mandatory=$false)]
	[Alias("Tools","VMTools")]
	[string]$VMwareTools = 'VMware-tools-9.4.10-2092844-x86_64.zip',
	
    # Specify to reboot after completed
	[parameter(Mandatory=$false)]
	[switch]$Reboot,
	
    # Specify to flag as migrating an unmanaged system in the source environment
	[parameter(Mandatory=$false)]
	[switch]$Unmanaged,

    # Specify this to skip the cleanup of local groups. 
	[parameter(Mandatory=$false)]
	[switch]$SkipGroupCleanup,	
	
 	# Firewall Rulename when creating Firewall port(s)
	# Example:	-SetFWRule CLCHosting
	[parameter(Mandatory=$false)]
	[Alias("SFWRule")]
	[string]$SetFWRule,
	
	# Sets Firewall Profile On/Off (Domain, Private, Public)
	# Example:	-SetFWProfile Domain:On
	# Example:	-SetFWProfile ALL:off
	[parameter(Mandatory=$false)]
	[Alias("SFWProfile","SFWProf")]
	[string]$SetFWProfile,

	# Firewall Program Profile (Rackware, no others currently)
	# Example:	-SetFWProgProf Rackware
	[parameter(Mandatory=$false)]
	[Alias("SFWProg")]
	[string]$SetFWProgProf,
		
    # Firewall Port, or Range of ports to all Firewall Profiles
	# Example:	-SetFWPort tcp:80
	# Example:	-SetFWPort tcp80,udp:45,icmp:8.4
	# Example:	-SetFWPort tcp:5540-7890,tcp:80,udp:161-180
	[parameter(Mandatory=$false)]
	[Alias("SFWPort","SFWPT")]
	[array]$SetFWPort,
	
	# Firewall Service Start Mode (Automatic, Disabled, Manual)
	# Example:	-SetFWService Disabled
	[parameter(Mandatory=$false)]
	[Alias("SFWService","SFWSV")]
	[string]$SetFWService,
   
	# Firewall Service State (Stop, Start)
	# Example:	-SetFWService Stop
	[parameter(Mandatory=$false)]
	[Alias("SFWState","SFWST")]
	[string]$SetFWState,

	# Firewall Reset
	# Example: -Reset
	[parameter(Mandatory=$false)]
	[switch]$Reset
)

$ScriptVersion = "1.1"


if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("debug")) {$DebugPreference="Continue"}

New-Variable -Option 'AllScope' -Name 'indent' -Value (0 -as [int]) 
New-Variable -Option 'AllScope' -Name 'FWService'
New-Variable -Option 'AllScope' -Name 'KeepFWOriginalStartState' -value $true
New-Variable -Option 'Allscope' -Name 'FWOriginalStartState'
New-Variable -Option 'AllScope' -Name 'IsError'
New-Variable -Option 'AllScope' -Name 'FromFunction'

function Trace {
    Param(
        # The text to output to screen
        [parameter(Position=0, Mandatory=$true)]
        [Alias("text","input")]
        [string]$data,
        
        # The foreground (text) colour
        [parameter(Position=1, Mandatory=$false)]
        [Alias("fore","f")]
        [ValidateSet("Black","DarkBlue","DarkGreen","DarkCyan","DarkRed","DarkMagenta","DarkYellow","Gray","DarkGray","Blue","Green","Cyan","Red","Magenta","Yellow","White")]
        [string]$ForegroundColor,
        
        # The background colour
        [parameter(Position=2, Mandatory=$false)]
        [Alias("back","b")]
        [ValidateSet("Black","DarkBlue","DarkGreen","DarkCyan","DarkRed","DarkMagenta","DarkYellow","Gray","DarkGray","Blue","Green","Cyan","Red","Magenta","Yellow","White")]
        [string]$BackgroundColor,
        
        # Makes this line a warning
        [parameter(Mandatory=$false)]
        [Alias("w")]
        [switch]$warn,
        
        # Makes this line an error.  Overrides the -warn switch
        [parameter(Mandatory=$false)]
        [Alias("e")]
        [switch]$Err
    )
    
	$type = " INFO"
    if ($Warn) {$type = " WARN"; if ($ForegroundColor -eq "") {$ForegroundColor = 'Yellow'}}
    
	if ($Err)  {
		$type = "ERROR $($FromFunction)"
		[array]$IsError += $FromFunction + $Error[0]
		if ($ForegroundColor -eq "") {$ForegroundColor = 'Red'}
	}
	
	if ($ForegroundColor -eq '') {$ForegroundColor = 'White'}
    if ($BackgroundColor -eq '') {$BackgroundColor = 'Black'}
    if ($indent -lt 0) {$indent = 0}
    Write-Host "$(Get-Date -format 'HH:mm:ss.f') :$($type): $('  ' * $indent)$data`r" -ForegroundColor $ForegroundColor -BackgroundColor $BackgroundColor
    
    <#
        .SYNOPSIS
            A quick and dirty Write-Host extension
        
        .DESCRIPTION
            Extends Write-Host by adding a timestamp and log type. The type defaults to :INFO:,
            but can be changed to :WARN: or : ERR: using the -warn or -err switches.
            There are also aliases of -w and -e to save keystrokes
        
        .EXAMPLE
            Trace "testing, 1,2,3"
            18:14:31.4 :INFO: testing, 1,2,3
        
        .EXAMPLE
            Trace "testing, 1,2,3" -warn
            18:14:34.9 :WARN: testing, 1,2,3
        
        .EXAMPLE
            Trace "testing, 1,2,3" -e -fore cyan
            18:14:43.1 : ERR: testing, 1,2,3
    #>
}
 
Function ResetUserFlag()
{Param ($userName)
	$FromFunction = "ResetUserFlag()"
    $Flag=512
    $u = [adsi]"WinNT://$env:computername/$userName,user"
    if ($u.UserFlags[0] -BAND $flag)
    {
        $u.invokeSet("userFlags", ($u.userFlags[0] -BAND $flag))
        $u.PasswordExpired = 0
        $u.commitChanges()
    }
   
	if (($u.userFlags.value -eq $flag) -and ($u.PasswordExpired.value -eq 0))
	{
	  Trace "Account flags have been reset"
	  }
	 else
	 {
	  Trace "Account flags failed to be reset. Please reset manually..." -err
	 }
}

function Set-LocalAdmin {
	Param(
		$TempPW
	)
	$FromFunction = "Set-LocalAdmin"
	Trace "Reconfiguring BUILTIN Admin account name and password"
	$indent++
	Trace "Checking for 'Administrator' account"
	$AdminUser = Get-WmiObject -Query "SELECT * FROM Win32_UserAccount WHERE LocalAccount=True AND SID LIKE 's-1-5-21-%-500'"
	$Adm = "Administrator"
    Trace "Resetting built-in Administrator account flags..."
    ResetUserFlag -Username $AdminUser.Name
	$indent++
	if ($AdminUser.Name -ne $Adm) {
		Trace "BUILTIN Admin account '$($AdminUser.Name)' was found"
		Trace "Renaming to 'Administrator'"

		$AdminResult = $AdminUser.Rename("Administrator")
		if ($AdminResult.ReturnValue -eq 0) {
			Trace "Successfully renamed BUILTIN Admin account to 'Administrator'"
			
		} else {
			Trace "Failed to rename BUITLTIN Admin account - please change by hand" -err
			$Adm = $AdminUser.Name
		}
	} else {
		Trace "BUILTIN Admin account is already named $($Adm)"
	}
	$indent--

	$changeLAdminCMD = "net user $($Adm) ""$($TempPW)"""
	$Result = Invoke-Expression $changeLAdminCMD

	if ($Result -Contains "The command completed successfully.") {
		Trace "BUILTIN Admin account password successfully set"
	} else {
		Trace "BUILTIN Admin account password reset failed - please change by hand" -Err
	}
	$indent--
 }
 
function Expand-ZIPFile($file, $destination)
{
    $FromFunction = "Expand-ZIPFile"
    if((Test-path($Destination)) -eq $false ){mkdir $Destination}
	$file = (Get-ChildItem $file).FullName
	$Destination = (Get-Item $Destination).FullName
	$shell = new-object -com shell.application
	$zip = $shell.NameSpace($file)
	foreach($item in $zip.items())
	{
		$shell.Namespace($destination).copyhere($item)
	}
}


function New-Password {
    [CmdletBinding(SupportsShouldProcess=$false,ConfirmImpact="Medium")]
    Param (
        [Parameter(Position=0,Mandatory=$false)]
        # The desired quantity of passwords to be generated. Defaults to 1
        [int]$quantity = 1,
        
        [Parameter(Position=1,Mandatory=$false)]
        # The desired length, in characters, of the password. Defaults to 14
        [int]$length = 14,
        
        [Parameter(Position=2,Mandatory=$false)]
        [Alias("web")]
        # Exclude characters '<', '>', '&' to prevent issues with web-based password safes
        [switch]$webSafe,
        
        [Parameter(Position=2,Mandatory=$false)]
        [Alias("safe","url")]
        # Exclude characters '< > & / \ ; : =' to prevent issues with JDBC URLs
        [switch]$UrlSafe
    )
	
	$FromFunction = "New-Password"
    $numb = "0123456789"
    $lett = "abcdefghijklmnopqrstuvwxyz"
    $punc = '!�%^&*()_+-={}[]:@~;''"#<>?,./|\'
    if ($webSafe) {$punc = '!*()_+-={}[]:./\'}
    if ($UrlSafe) {$punc = '!*()_+-.'}
 
    for ($ii = 1; $ii -le $quantity; $ii++) {
        $password = ""
        for ($jj = 1; $jj -le $length; $jj++) {
            switch ($(Get-Random -Minimum 1 -Maximum 5)) {
                1 {$password += $punc.SubString($(Get-Random -Maximum $($punc.Length)), 1)}
                2 {$password += $lett.SubString($(Get-Random -Maximum $($lett.Length)), 1)}
                3 {$password += $numb.SubString($(Get-Random -Maximum $($numb.Length)), 1)}
                4 {$password += $lett.ToUpper().SubString($(Get-Random -Maximum $($lett.Length)), 1)}
            }
        }
        $password
    }
 
<#
.SYNOPSIS
    Produces one or more complex passwords
.DESCRIPTION
    Produces one or more complex passwords
.EXAMPLE
    C:\PS>New-Password
    WAuLK2xO){26cT
.EXAMPLE
    C:\PS>New-Password 5
    r.*25wf970N4e)
    Y2y.\$lPH:0S4X
    ?x+r$3,6450d[8
    V7%K3A)87rj%Hy
    jP52w$J(sioi!5
.EXAMPLE
    C:\PS>New-Password -length 8
    5VX*jm3v
.EXAMPLE
    C:\PS>New-Password -quantity 5 -length 25 -webSafe $true
    h9y0AtMo^8KcyCaD~VprX#hzW
    jQBP3:V-26{XYo07{4m8TAi*0
    9g0894Q3i#*8MuqE:ryOLS{Ic
    UU{ne70[jzL6Ox31h9(yxq%U6
    }-[hN}D3fefI0Y75af$^9zV-'
#>
 
}


function Remove-GhostedNICs 
{
	##region <Remove Ghosted NICs>
	$FromFunction = "Remove-GhostedNics"
	Trace "Identifying and Removing Ghosted NICs from OS"
	$action = "remove"
	$a1 = (invoke-expression "$($destPath) findall =net")
	$a2 = (invoke-expression "$($destPath) listclass net")
	$found=$False
	$indent++

	foreach ($a in $a1) {

		 if ($a -like "PCI\*") {
			if ($a2 -notcontains $a) {
			  $indent++
			  $Found=$True
			  $ghostednic = $a.split(":")[0].trim()
			  Trace "Found Ghosted NIC: $ghostednic"
			  
			  # foreach ($i in $ghostednic) {
				   $rootname = "'@"+$ghostednic+"'"
				   Trace "Removing Ghosted NIC Root Device ID: $rootname"
				   Trace "Running: $destPath $action $rootname"
				   [array]$result = invoke-expression "$destPath $action $rootname"
				   Trace "Command presented - $destPath $action $rootname"
						## Successful removal
						if ($result[-1] -eq "1 device(s) removed.") {
							#Trace "Command presented - $destPath $action $rootname"
							#Trace "$rootname was removed"
							Trace "$result"
							#$indent--
						}
						 
						## Error handling                                        
						if ($result[-1] -eq "Invalid use of remove.") {
							Trace "Syntax Error - Should be in the form of PathOfDevcon\devcon.exe remove '@PCI\PathOfDevice'!" -e
							#Trace "Command presented - $destPath $action $rootname" -e
							Trace "$result" -e
							#$indent--
						}
						
						## Error handling 
						if ($result[-1] -eq $NULL) {
							Trace "A device believed to be a ghosted NIC may not have been removed!" -e
							Trace "Devcon gave no reply of action taken!" -e
							#Trace "Command presented - $destPath $action $rootname" -e
							#$indent--
						}
						
						## Error handling 
						if ($result[-1] -eq "No devices removed.") {
							Trace "A device believed to be a ghosted NIC was NOT removed!" -e
							Trace "Device presented for removal either not present, or invalid!" -e
							Trace "$result" -e
							#Trace "Command presented - $destPath $action $rootname" -e
							#$indent--
						}
					$indent--
				   #}
			  }
		 }   
	}

	if ($found -ne $true) {

		 Trace "No Ghosted NICs were found"
		 $indent--
	}

$indent--


<#
.SYNOPSIS
    Command-line utility that functions as an alternative to Device Manager
        
.DESCRIPTION
    The DevCon utility is a command-line utility that acts as an alternative to Device Manager. 
    Using DevCon, you can enable, disable, restart, update, remove, and query individual devices
    or groups of devices. DevCon also provides information that is relevant to the driver developer 
    and is not available in Device Manager.  You can use DevCon with Microsoft Windows 2000, 
    Windows XP, and Windows Server 2003. You cannot use DevCon with Windows 95, Windows 98, or 
    Windows Millennium Edition.
        
.EXAMPLE
    devcon findall =ports
    Lists "nonpresent" devices and devices that are present for the ports class. This includes 
    devices that have been removed, devices that have been moved from one slot to another, and, 
    in some cases, devices that have been enumerated differently due to a BIOS change. 

.EXAMPLE
    devcon listclass usb 1394
    Lists all devices that are present for each class named (in this case, USB and 1394). 
        
.EXAMPLE
    devcon remove @usb\*
    Removes all USB devices. Devices that are removed are listed with their removal status. 

.Results Table:
    
    "Invalid use of remove." - Syntax issue, should be in form of : 
     PathOfDevcon\devcon.exe remove '@PCI\PathOfDevice'
    "No devices were removed." - A value was fed to .\devcon remove, but the value wasn't found 
     as a registered device

.NOTES
    #AUTHOR  : Jeffrey Chaney, CenturyLink, Cloud Product Engineering
	#DATE    : 2015-07-10
	#TAGS    : CLC, VPDC, Migration
	#VERSION : 01.01.00
		        |  |  +- Bug fix version
		        |  +---- Feature version
		        +------- Major version

#>


}
##end region <Remove Ghosted NICs>

##region <Remove Errored NICs>
function Remove-ErroredNICs 
{
	##region <Remove-Error'd NICs>
	$FromFunction = "Remove-ErroredNICS"
	Trace "Identifying and Removing Error'd NICs from OS"
	$action = "remove"
	$found=$False
	[array]$a1 = gwmi win32_networkadapter | where {$_.configmanagererrorcode -eq "10"} | select pnpdeviceid
	
	if ($a1 -ne $NULL) {
	
		for ($i=0; $i -le $a1.count -1; $i++) {
			$indent++
			$Found=$True
			Trace "Found Errored NIC: $($a1[$i].pnpdeviceid)"
			$rootname = "'@"+$($a1[$i].pnpdeviceid)+"'"
			Trace "Removing Errored NIC Root Device ID: $rootname"
			Trace "Executing: $destPath $action $rootname"
			[array]$result = invoke-expression "$destPath $action $rootname"
			
				## Successful removal
				if ($result[-1] -eq "1 device(s) removed.") {
					Trace "$result"
					}
						 
				## Error handling                                        
				if ($result[-1] -eq "Invalid use of remove.") {
					Trace "Syntax Error - Should be in the form of PathOfDevcon\devcon.exe remove '@PCI\PathOfDevice'!" -e
					Trace "$result" -e
					}
						
				## Error handling 
				if ($result[-1] -eq $NULL) {
					Trace "A device believed to be a Errored NIC may not have been removed!" -e
					Trace "Devcon gave no reply of action taken!" -e
					}
					
				## Error handling 
				if ($result[-1] -eq "No devices removed.") {
					Trace "A device believed to be a Errored NIC was NOT removed!" -e
					Trace "Device presented for removal either not present, or invalid!" -e
					Trace "$result" -e
					}
								
			$indent--
	
		}
	
	}   

	if ($found -ne $true) {
		 $indent++
		 Trace "No Errored NICs were found"
		 $indent--
	}

}
##end region

#region Add Community Name and Security
function AddCommunityName_Security {

$FromFunction = "AddCommunityName_Security"
Trace "Modifying Community Name and Security"
$indent++
#find out where we are
$origpath = get-location
set-location "HKLM:"
trace "Checking to see if 'ValidCommunities' folder exists under HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SNMP\Parameters\"
$path = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SNMP\Parameters\ValidCommunities"

#if there's a ValidCommunities folder, is there a tier3-snmp key?
if (test-path $path) {
    trace "'ValidCommunities' Folder found under HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\..."
	$result = get-itemproperty $path 
	trace "Checking to see if a tier3-snmp key exists..."			

#if there's a tier3-snmp key, and its value is 4, we're done
	if ($result."tier3-snmp" -eq "4") { 
		trace "Tier3-snmp key exists, and already has a value of 4"

#There's a tier3-snmp key, but its value isn't 4.
	} elseif ($result."tier3-snmp") {
		trace "Tier3-snmp key existed, but was a different value than 4"
		$result = set-itemproperty -path $path -name "tier3-snmp" -propertytype dword -value "4" 
				
#there's no tier3-snmp key		
	} else {
		trace "There was no tier3-snmp key, creating key and setting value to 4"
		$result = new-itemproperty -path $path -name "tier3-snmp" -propertytype dword -value "4"
	}

#there's no ValidCommunities folder, and we're creating a "snmp-tier3" key
} else { 
	trace "There was no 'ValidCommunities' folder, creating new folder..."
	$result = new-item "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SNMP\Parameters\ValidCommunities"
	trace "There was no tier3-snmp key, creating key and setting value to 4"
	$result = new-itemproperty -path $path -name "tier3-snmp" -propertytype dword -value "4"
}

trace "Checking to see if 'PermittedManagers' folder exists under HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SNMP\Parameters\"
$path = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"

#if there's a PermittedManagers folder, is there a '1' key?
if (test-path $path) {
	trace "'PermittedManagers' Folder found under HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\..."
	$result = get-itemproperty $path
	
#We've found there's a '1' key? We'll remove it.
	if ($result."1" -ne $null) {
		trace "Removing Key '1' from HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"
		Remove-ItemProperty -Path $path -Name 1
		
	} else {
		trace "'1' Key not found..."
	}	
	
} else {
	trace "There was no 'PermittedManagers' folder..."
}
	
#return back to path
set-location $origpath
$indent--

}
#end region

#Region <Firewall Actions>
#report status of the Firewall
function QueryFirewallStatus {
$FromFunction = "QueryFirewallStatus"
trace  "Querying Firewall Status -"
$indent++
$FWService = Get-WMIObject win32_Service | where-object {$_.displayname -match "Firewall"}
$FWOriginalStartState = $FWService.Startmode
if ($FWOriginalStartState -eq "Auto") { $FWOriginalStartState = "Automatic" }

trace "Windows Firewall Start Mode is set to $($FWOriginalStartState), and the Service is $($FWService.State)"
if ($FWService.State -eq "Stopped") {
	if ($FWService.Startmode -eq "disabled") {
		trace "Temporarily setting Firewall Service to Manual"
		$result = Set-Service -name $FWService.Name -Startuptype "manual"
		}
	trace "Temporarily starting Firewall Service"
	$result = Start-Service -name $FWService.Name
}
$indent--
}

#query Windows Firewall Profiles
function QueryProfileStatus {
$FromFunction = "QueryProfileStatus"
trace "Querying Profiles -"
$indent++
$FWProfileState = New-Object PSobject
$result = Invoke-Expression "netsh advFirewall show allProfiles State"
$result | foreach-object {
	if ($_ -match "Profile Settings") {
		$a = $_.split()[0]
	} elseif ($_ -match "State") {
		$b = $_.split()[-1]
		$FWProfileState | Add-Member -MemberType NoteProperty -Name $a -value $b
	}
}
trace "Windows Firewall Profiles - Domain: $($FWProfileState.domain) Private: $($FWProfileState.private) Public: $($FWProfileState.public)"
$indent--
}

#set Firewall Startup mode
function SetFWService {
$FromFunction = "SetFWService"
trace "Setting Startup Mode -"
$indent++
$KeepFWOriginalStartState = $False
$StartModes = "Manual","Disabled","Automatic","Auto"
if ($StartModes -contains $SetFWService) {
	if ($SetFWService -eq "Auto") { $SetFWService = "Automatic" }
	trace "Setting Firewall Service to $($SetFWService)"
	$indent--
	Set-Service -name $FWService.Name -Startuptype $($SetFWService)
} else { 
	trace "Invalid StartMode _$($SetFWService)_ selected for Firewall Service, should be i.e. Disabled, Auto, Manual" -e
	
}
$indent--
}

#set Firewall Service state
function SetFWState {
$FromFunction = "SetFWState"
trace "Setting Service State -"
$indent++
$SetFWStates = "Start","Stop"
if ($SetFWStates -contains $SetFWState) { 
	if ($SetFWState -eq "Start") { 
		if ($FWService.State -eq "Running") {
		trace "Firewall Service is already Running"
		} else {
		trace "Starting Firewall Service"
		Start-Service -name $FWService.Name
		}
	} else { 
		trace "Stopping Firewall Service"
		Stop-Service -name $FWService.Name	} 
} else {
	trace "Invalid State _$($SetFWState)_ selected for Firewall Service, should be i.e. Start or Stop" -e
	
}
$indent--
}

#Set Firewall Profile and Profile State
function SetFWProfile {
$FromFunction = "SetFWProfile"
trace "Setting Firewall Profiles and States -"
$indent++
$Profiles = "Domain","Private","Public","ALL"
$ProfileStat = "On","Off"
if ($SetFWProfile -notmatch "ALL") {
	$SetFWProfile = $SetFWProfile.split(",")
	if ($SetFWProfile.count -lt 4) {
		foreach ($a in $SetFWProfile) {
			if ($Profiles -contains $a.split(":")[0] -and $ProfileStat -contains $a.split(":")[-1])	{
				$result = netsh advFirewall set $($a.split(":")[0]) state $($a.split(":")[-1])
					if ($result -notcontains "Ok.") {
						trace "Error -$result" -e
					} else { 
						trace "Setting Firewall Service Profile : $($a.split(":")[0]) - $($a.split(":")[-1])"
					}
			} else {
				trace "Invalid State or Profile Input _$($SetFWProfile)_, should be i.e. Domain:Off or On, Public:Off or On, Private:Off or On, All:Off or On" -e
			}
		}
	} else { 
		trace "Too many firewall profile parameters specified!" -e; break
	}
} else { 
	$SetFWProfile = $SetFWProfile.split(":")
	if ($SetFWProfile.count -le 2 -and $Profiles -contains $SetFWProfile[0] -and $ProfileStat -contains $SetFWProfile[-1]) {
		$result = netsh advFirewall set allProfiles state $SetFWProfile[-1]
		if ($result -notcontains "Ok.") {
			trace "Error -$result" -e
		} else { 
			trace "Setting all Profiles State to $($SetFWProfile[-1])"
		}
	} else {
		trace "Invalide State or Profile Input _$($SetFWProfile)_" -e ; break
	}
}	
$indent--
}

#Set Firwall Rules and Ports
function SetFWPort {
$FromFunction = "SetFWPort"
trace "Setting Firewall Rules and Ports -"
$indent++
foreach ($a in $SetFWPort) {
	#if the ports are a range of values
	if ($a -match "-") { 
		$validproto = "TCP","UDP"
		[string]$proto = [string]$a.split(":")[0].toupper()
		[string]$values = [string]$a.split(":")[-1]
		if ($validproto -notcontains $proto) { trace "Invalid protocol specified $($proto):$($values)" -e 
											   trace "Specify UDP, TCP, or echo in parameters and re-run script" -e; break }
		
		#test to see if our values are numbers
		try { [int]$values.split("-")[0] + [int]$values.split("-")[-1] + 1 | out-null } catch { trace "$($a.split("-")[0]):$($a.split("-")[-1]) contains characters, not numbers for port creation!" -e ; break }
		
		[int]$r1 = [string]$values.split("-")[0]
		[int]$r2 = [string]$values.split("-")[-1]
			if ($r1 -lt $r2) {
				if (($r1 -gt 0 -and $r1 -le 65535) -and ($r2 -gt 0 -and $r2 -le 65535)) {
					if ($SetFWRule -eq "") { 
						$Rule = "$($proto)-$($values) IN" 
					} else { 
						$Rule = "$($SetFWRule) $($proto)-$($values) IN" 
					}
					trace "Creating Firewall Rule `"$($Rule)`""
					$result = netsh advFirewall Firewall add Rule name=$($Rule.toupper()) new dir=in action=allow enable=yes Profile=any localip=any remoteip=any protocol=$proto localport=$values interfacetype=any edge=yes
					if ($result -notcontains "Ok.") {
						trace "Error -$result" -e
					}
				} else {
					trace "$($r1) or $($r2) outside of possible port range" -e; break
				}
			} else { trace "$($r1) is a larger value than $($r2). For range values, the lesser value must be on the left!" -e ; break		
			}
		
	#if the port is a single value
	} else {
		if ($a -match "echo") {
			if ($a -ne "echo") { trace "$($a) is not a valid input for creating echo rule!" -e ; break }
			$seticmp = "protocol=icmpv4:8,any"
			trace "Creating Firewall icmp Rule `"$($SetFWRule) ECHO IN`""
			$Rule = "`"$($SetFWRule) ECHO IN`""
            $exe = "netsh advFirewall Firewall add Rule name=$($Rule.toupper()) new dir=in action=allow enable=yes Profile=any localip=any remoteip=any `"$($seticmp)`" interfacetype=any edge=yes"
			$result = invoke-expression $exe
			if ($result -notcontains "Ok.") {
				trace "Error -$result" -e
			}
		} else {
			$validproto = "TCP","UDP"
			[string]$proto = [string]$a.split(":")[0].toupper()
			
			#test to see if our value is a number
			try { [int]$a.split(":")[-1] + 1 | out-null } catch { trace "$($a.split(":")[0]):$($a.split(":")[-1]) is not a valid input for port creation!" -e ; break}
			
			[int]$values = [string]$a.split(":")[-1]
			if ($values -gt 0 -and $values -lt 65535) {
				if ($validproto -notcontains $proto) { trace "Invalid protocol specified $($proto):$($values)" -e 
													   trace "Specify UDP, TCP, or echo in parameters and re-run script" -e ; break }	
				if ($SetFWRule -eq "") { $Rule = "$($proto)-$($values) IN" 
				} else { 
					$Rule = "$($SetFWRule) $($proto)-$($values) IN" 
				}
				trace "Creating Firewall Rule `"$($Rule)`""
				$result = netsh advFirewall Firewall add Rule name=$($Rule.toupper()) new dir=in action=allow enable=yes Profile=any localip=any remoteip=any protocol=$proto localport=$values interfacetype=any edge=yes
				if ($result -notcontains "Ok.") {
					trace "Error -$result" -e
				}
			}
		}
	}
}
$indent--
}					

#function to disable a firewall group
function DisableFWGroup {
	$FromFunction = "DisableFWGroup"
	trace "Disabling Firewall Groups -"
	$indent++
	trace "Setting $($DisableFWGroup) Group to Disabled"
	$exe = "netsh advFirewall Firewall set Rule group=$($DisableFWGroup) new enable=no"
	$result = invoke-expression $exe
	if ($result -notcontains "Ok.") {
		trace "Error -$result" -e
	}
	$indent--
}

#function to return firewall to original start state - no change directive given
function KeepFWOriginalStartState {
	$FromFunction = "KeepFWOriginalStartState"
	trace "Firewall Start State Unchanged - "
	$indent++
	trace "Returning Firewall Service to $($FWOriginalStartState)"
	Set-Service -name $FWService.Name -Startuptype $FWOriginalStartState
	$indent--
}

#resets firewall to windows default
function Reset {
	$FromFunction = "Reset"
	trace "Resetting firewall, RDP session may lose connection temporarily -"
	$indent++
	$result = netsh advfirewall reset
	if ($result -notcontains "Ok.") {
		trace "Error -$result" -e
	}
	trace "Enabling RDP rule - Remote Desktop (TCP-In)"
	$exe = "netsh advFirewall Firewall set Rule name=`"Remote Desktop (TCP-In)`" new enable=yes profile=any"
	$result = invoke-expression $exe
	if ($result -notcontains "Ok.") {
		trace "Error -$result" -e
	}
	$indent--
}
#end Region <Firewall Actions>

# Stop any current transcript and start a new one named after the script and the date/time
. {Trap {Continue}; Stop-Transcript | Out-Null}
$ProblemReport = @()
$logFile = ($MyInvocation.MyCommand.Name).Replace(".ps1","_$(Get-Date -Format ""yyyy-MM-dd_HH-mm"").log")
Start-Transcript $logFile -Force -ErrorAction SilentlyContinue
Trace "---- Start-PostMigration START ----"
Trace "Script Version $ScriptVersion"
$WebServer=$WebServer+"/windows/RWTools"
[System.Net.ServicePointManager]::ServerCertificateValidationCallback ={$true}
$ComputerName = $Computername
if ($Unmanaged -eq $True)
{
  Trace "'Unmanaged' flag was set.  Managed Server Software will not be removed." -WARN
  }
  
Trace "Checking for C:\Xfer\Migration folder..."
if (Test-Path -Path 'C:\Xfer\migration') {
	Trace "C:\Xfer\Migration folder found"
} else {
	Trace "C:\Xfer\Migration folder not found" -Warn
	Trace "Creating C:\Xfer\Migration directory"
	New-Item C:\Xfer\Migration -Type Directory | out-null
}

Trace "Retrieving list of installed software packages"
$installedSoftware = Get-WmiObject Win32_Product
Import-Module ServerManager

##region <Install SNMP features>
$FromFunction = "Install SNMP Features Region"
foreach ($feature in "SNMP-Service","SNMP-WMI-Provider") {
	$featureStatus = Get-WindowsFeature $feature
	if ($featureStatus.Installed -eq $true) {
		Trace "Feature '$feature' is installed"
	} else {
		Trace "Feature '$feature' is not installed"
		$indent++
		Trace "Installing '$feature'"
		$installResult = Add-WindowsFeature $feature
		if ($installResult.Success -eq $true) {
			Trace "Feature '$feature' has been successfully installed"
		} else {
			Trace "Feature '$feature' failed to install with exit code $($installResult.ExitCode)" -err
		}
		$indent--
	}
}
##endregion

##region <Remove domain users and groups>

Trace "Starting local group cleanup..."
if ($SkipGroupCleanup -eq $False)
{
Trace "Retrieving local groups and membership"
$computer = [ADSI]"WinNT://$($env:computername)"
$localGroups = $computer.PSBase.Children | Where-Object {$_.PSBase.SchemaClassName -eq 'group'}
$localDomains = "IIS APPPOOL","NT AUTHORITY","NT SERVICE",$env:computername
$found=$False
$indent++
foreach ($localGroup in $localGroups) 
      {
	$thisGroup = [ADSI]$localGroup.PSBase.Path
	$thisGroupName = $thisGroup.Properties.Name
	Trace "Found group: $($thisGroup.Properties.Name)"
	$group = [ADSI]"WinNT://./$($ThisgroupName)"
        $Members = @()
        Foreach($m in $group.members())
          {
             $u=""| Select Name,Domain
             $AdsPath=$m.GetType().InvokeMember("AdsPath",'GetProperty',$null,$m,$null)
             $ads=$AdsPath.split('/',[StringSplitOptions]::RemoveEmptyEntries)
             $name =$ads[-1]
             $domain=$ads[-2]
             
             if($name -like "S-1-5-*" -and $domain -eq  "WinNT:")
             {
                $domain = $domain.replace(":","").trim()
                $u.Name=$name
                $u.domain=""
                $Members+=$u
                $Found=$True
		        #Write-host $name " : " $domain
              }elseif($localDomains -notcontains $domain){
                $domain = $domain.replace(":","").trim()
                $u.Name="\"+$name
                $u.domain=$domain
                $Members+=$u   
              }    
	    }
          if ($members.count -ge 1)
            {
              $indent++
             foreach ($m in $members)
               {
                  Trace "Removing '$($m.domain)$($m.name)' from '$($Group.name)'"
                  $group.Remove("WinNT://$($m.domain)$($m.name)" )     
                }
			 $indent--	
             }      
           }
$indent--
}
else
{
 Trace "** The '-SkipGroupCleanup' flag was specified at runtime. As such, no local groups will be cleaned up on this server." -warn
 Trace "** If you would like to later clean those up, please re-run the script without the '-SkipGroupCleanup' command line paramater."
}

##endregion

##region <Unjoin from domain>
$cdomain = (gwmi Win32_ComputerSystem).domain
Trace "Removing computer from domain '$($CDomain)'"
$unjoinResults = invoke-expression "netdom remove $env:computername /domain:$($CDomain) /force"
Trace "Adding computer to workgroup WORKGROUP"
$wgJoinResults = Add-Computer -WorkGroupName WORKGROUP
Trace "--"
##endregion

##region <Rename computer>
$FromFunction = "Rename Computer Region"
Trace "Renaming computer from '$($env:computername)' to '$($Computername)'"
$CN = Get-WMIObject Win32_ComputerSystem
$RenameResult = $CN.Rename($ComputerName)
$Indent++
If ($RenameResult.ReturnValue -ne 0)
{
   Trace "Rename operation failed. This must be manually completed." -Err 
}
else
{
   Trace "Rename operation succeeded and will be reflected after the next reboot."
}
$Indent--
##endregion

##region <Enable Powershell Remoting>
$FromFunction = "Enable Powershell Remoting Region"
Trace "Enabling Powershell Remoting"
 
$PSR= Enable-PSRemoting -Force -ErrorAction silentlycontinue
if ($PSR -ne $NULL)
 {
   $PSR | ForEach-Object {Trace "> PSR: $($_)"}
   Trace "Setting WSMan Trusted Hosts..."
   Set-Item WSMan:\localhost\client\TrustedHosts * -Force
   }
else {Trace "Powershell Remoting enablement failed. Please remediate manually." -err }
##endregion

##region <Uninstall McAfee products>
$FromFunction = "Uninstall McAfee Productions Region"
if ($Unmanaged -eq $False){
	Trace "Uninstalling McAfee Products -"
	$indent++
	foreach ($product in $installedSoftware | Where-Object {$_.Name -match 'McAfee'}) {
		
	Trace "Uninstalling product '$($product.Name)'"
	$pTemp = $null
	
	$uninstallResult = $product.Uninstall()

	if ($uninstallResult.ReturnValue -eq 0) { 
		
		Trace "Uninstalled '$($product.Name)' successfully"
	
	} elseif ($product.Name -eq 'McAfee VirusScan Enterprise' -and $uninstallResult.ReturnValue -ne 0) {
		$attempt = 0
			
		do {
			if ($uninstallResult.ReturnValue -eq 0) {
				Trace "Uninstalled '$($product.Name)' successfully"
				break
			} else {
				$attempt += 1
				Trace "Attemping to uninstall 'McAfee VirusScan Enterprise'... Attempt#($attempt)"
				$uninstallResult = $product.Uninstall()
				sleep 30
			}
		} until ($attempt -eq 10)
	
		if ($uninstallResult.ReturnValue -ne 0) {Trace "Manual uninstallation of $($product.Name) required" -err}
		
	} else {
		Trace "Failed to uninstall '$($product.Name)' with return code $($uninstallResult.ReturnValue)" -Warn
	}
	
	if ($product.Name -eq 'McAfee Agent') {
	
		Trace "Attempting to force uninstall '$($product.Name)'"
		Trace "Looking for FrmInst.exe"
		
		if (Test-Path 'C:\Program Files\McAfee\Common Framework\FrmInst.exe') {
			$frminstPath = 'C:\Program Files\McAfee\Common Framework\FrmInst.exe'
		
		} elseIf (Test-Path 'C:\Program Files (x86)\McAfee\Common Framework\FrmInst.exe') {
			$frminstPath = 'C:\Program Files (x86)\McAfee\Common Framework\FrmInst.exe'
		
		} else {
			$frminstPath = ""
			Trace "Cannot find FrmInst.exe" -Err
		}
		
		if ($frminstPath -ne "") {
			Trace "Forcing uninstallation using $frminstPath"
			Invoke-Expression "& ""$frminstPath"" /forceuninstall /silent"
			$attempt = 0
			
			do {
				if ($pTemp=Get-WmiObject Win32_Product | Where-Object {$_.Name -eq $Product.name}) {
				$attempt += 1
				Trace "Sleeping 30 secs for uninstall to complete for $($Product.name)... Sleep#$($attempt)"
				sleep 30
		
				} else {
					Trace "Forced uninstallation of '$($product.name)' succeeded."; break		
				}
		
			} until ($attempt -eq 10)
		
		} else {
		Trace "Forced uninstallation of '$($product.name)' failed..`n    Manual uninstallation required." -err
		}
	}
}
$indent--
}
##endregion

##region <Uninstall Trend Micro Deep Security>
$FromFunction = "Uninstall Trend Micro Deep Security"
if ($Unmanaged -eq $False){
foreach ($product in ($installedSoftware | Where-Object {$_.Name -match 'Trend Micro Deep Security'}) ) {
Trace "Uninstalling product '$($product.Name)'"
Trace "*** This may cause RDP sessions to disconnect due to network driver changes ***" -WARN

	$indent++
	$uninstallResult = $product.Uninstall()
	if ($uninstallResult.ReturnValue -eq 0) {
		Trace "Uninstalled '$($product.Name)' successfully"
	} else {
		Trace "Failed to uninstall '$($product.Name)' with return code $($uninstallResult.ReturnValue)" -Warn
}
$indent--
}
}

##region <Uninstall HPSA products>
$FromFunction = "Uninstall HPSA Products Region"
if ($Unmanaged -eq $False){
if (test-path "<C:\Program Files\Common Files\Opsware\etc\agent\opswgw.args>" )
{
   out-file -inputobject "opswgw.gw_list: 127.0.0.1:3001`n" -FilePath "C:\Program Files\Common Files\Opsware\etc\agent\opswgw.args" -force -ErrorAction SilentlyContinue
}
else{
   trace "Configuration file 'opswgw.args' file doesn't exist"
   }
foreach ($product in ($installedSoftware | Where-Object {$_.Name -match 'Powershell Connector'}) ) {
Trace "Uninstalling product '$($product.Name)'"

	$indent++
	$uninstallResult = $product.Uninstall()
	if ($uninstallResult.ReturnValue -eq 0) {
		Trace "Uninstalled '$($product.Name)' successfully"
	} else {
		Trace "Failed to uninstall '$($product.Name)' with return code $($uninstallResult.ReturnValue)" -Warn
}
$indent--
}
Trace "Uninstalling HPSA Agent" ## MSI uninstall is flakey - better to use the scripts
if (test-path "C:\Program Files\Opsware\agent\pylibs\cog\uninstall\agent_uninstall.bat" )
{
	$results = Invoke-Expression "C:\""Program Files""\Opsware\agent\pylibs\cog\uninstall\agent_uninstall.bat --force"
	$results | ForEach-Object {Trace "> HPSA: $($_)"}
	Trace "Waiting for the processes to complete..."
	$HC=0
	$Indent++
	do{
	  Trace "Waiting 10 seconds..."
	  start-sleep -seconds 10
	  remove-item "C:\Program Files\Opsware\agent\pylibs\watchdog\watchdog.exe" -ErrorAction silentlycontinue
	  $Success=$?
	  $HC++
	}until(($Success -eq $True) -or ($HC -eq 12))
	$Indent--
	Trace "Removing HPSA Opsware folder"
	Remove-Item 'C:\Program Files\Opsware' -Confirm:$false -Force -Recurse
}
else 
{
  Trace "'C:\Program Files\Opsware\agent\pylibs\cog\uninstall\agent_uninstall.bat' is not found. Please remove manually." -Warn
  }
Trace "Removing HP SA Agent from Add/Remove Programs"
$indent++
foreach ($product in ($installedSoftware | Where-Object {$_.Name -match 'HP SA Agent'}) ) {
	Trace "Removing $($product.Name)"
	$GUID = $product.IdentifyingNumber
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$GUID" -Force -ErrorAction silentlycontinue
}
$indent--
}
##endregion


##region <Uninstall SIA>
$FromFunction = "Uninstall SIA Region"
if ($Unmanaged -eq $False){
Trace "Uninstalling SIA"
$indent++
$siaConfig = Get-ItemProperty -Path HKLM:\SOFTWARE\SAVVIS\SNMP_DLL\CurrentVersion -Name SiaConfig -ErrorAction SilentlyContinue
if ($siaConfig -eq $null) {
	$siaConfig = Get-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\SAVVIS\SNMP_DLL\CurrentVersion -Name SiaConfig -ErrorAction SilentlyContinue
}

if ($siaConfig -eq $null) {
	Trace "SIA does not appear to be installed"
} else {
	Trace "Found SIA installation"
	$siaConfig = $siaConfig.SiaConfig
	if ($siaConfig -notmatch ':') {$siaConfig = "C:$siaConfig"} # Add the drive letter missing from the configuration path
	$siaVersionFull = ([array](Get-Content $siaConfig | Select-String SIAVersion))[0].ToString().Split(':')[-1].Replace('$','').Replace('SIAWIN_','').Replace('_','.').Trim()
	$siaVersionSplit = $siaVersionFull.Split('.')
	if ($siaVersionSplit[1].Length -eq 1) {
		$siaVersion = [float]"$($siaVersionFull.Split('.')[0]).0$($siaVersionFull.Split('.')[1])"
	} else {
		$siaVersion = [float]"$($siaVersionFull.Split('.')[0]).$($siaVersionFull.Split('.')[1])"
	}
	$siaPath = $siaConfig.Replace('\etc\sia.cfg','')
	
	Trace "SIA version = $siaVersionFull"
	Trace "Backing up current gen_events.cfg to C:\Xfer\Migration\gen_events_$(Get-Date -Format 'yyyy-MM-dd').cfg"
	Copy-Item -Path "$($siaPath)\gen_events.cfg" -Destination "C:\Xfer\Migration\SIA_gen_events_$(Get-Date -Format 'yyyy-MM-dd').cfg" -Force
	
	Trace "Stopping SIA"
	$indent++
	Invoke-Expression -Command "C:\usr\local\monitor\monitor.cmd stop"
	$siaServices = "WOTS", "SIAScheduler", "SIACPD", "statsplus", "bdawatch", "srvwatch", "SNMP"
	foreach ($service in $siaServices) {
		if ($(Get-Service $service -ErrorAction SilentlyContinue)) {
			Trace "Attempting to stop service '$service'"
			Stop-Service $service -ErrorAction SilentlyContinue
		} else {
			Trace "Did not find service '$service'"
		}
	}
	$indent--
	
	if ($siaVersion -lt 3.08) {
		if (Test-Path 'C:\Xfer\SIA\RemoveSIA.cmd') {
			Trace "Found SIA uninstaller in default location"
			Push-Location -Path C:\Xfer\SIA
			Trace "Removing SIA"
			$indent++
			Invoke-Expression -Command "RemoveSIA.cmd" | ForEach-Object {Trace " >> $_"}
			$indent--
		} else {
			Trace "Cannot find C:\Xfer\SIA\RemoveSIA.cmd.  Please remove SIA by hand." -Err
		}
	} else {
		foreach ($package in $(Get-ChildItem "hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")) {
		    if ($package.GetValue("DisplayName") -eq "SIA") {
		    	Trace "Found SIA package in registry"
		        $UninstallCMD = ($package.GetValue("UninstallString").Replace("/I","/X `'")).Replace("}","}`' /quiet /qn /norestart /l 'C:\Xfer\Migration\Uninstall-SIA.log'")
		    }
		}
		Trace "Uninstalling SIA using MSIexec"
		Invoke-Expression -Command $UninstallCMD
		
		foreach ($package in $(Get-ChildItem "hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")) {
		    $displayName = $package.GetValue("DisplayName")
		    if ($displayName -match "^SIA") {
		    	Trace "Uninstalling $displayName"
		        $UninstallCMD = ($package.GetValue("UninstallString").Replace("/I","/X `'")).Replace("}","}`' /quiet /qn /norestart /l 'C:\Xfer\Migration\Uninstall-$($displayName).log'")
		        Invoke-Expression -Command $UninstallCMD
		    }
		}
	}
	
	Trace "Cleaning up SIA remaining files: Removing $siaPath"
	Remove-Item $siaPath -Recurse -Force
}
$indent--
}
##endregion

##region <Uninstall NetBackup>
$FromFunction = "Uninstall NetBackup"
if ($Unmanaged -eq $False){
foreach ($product in ($installedSoftware | Where-Object {$_.Name -match 'NetBackup'}) ) {
	Trace "Uninstalling product '$($product.Name)'"
	$indent++
	$uninstallResult = $product.Uninstall()
	if ($uninstallResult.ReturnValue -eq 0) {
		Trace "Uninstalled '$($product.Name)' successfully"
	} else {
		Trace "Failed to uninstall '$($product.Name)' with return code $($uninstallResult.ReturnValue)" -Err
	}
	$indent--
}
}
##endregion



##region <Delete HOSTS entries>
$FromFunction = "Delete HOSTS entries"
$defaultHosts = @"
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#         127.0.0.1     localhost
#         ::1           localhost
"@

Trace "Moving existing HOSTS file to Hosts.Migrated"
copy-Item C:\Windows\System32\Drivers\etc\hosts C:\Xfer\Migration\hosts.Migrated -Force

Trace "Writing out a default HOSTS file"
$defaultHosts | Out-File -FilePath C:\Windows\System32\Drivers\etc\hosts -Encoding ASCII -Force
##endregion

##region <Install Devcon>
$FromFunction = "Install devcon64.exe Region"
$Devcon = "devcon64.exe"
$destPath = "C:\Xfer\Migration\$($Devcon)"
     Trace "Checking for $($Devcon) executable..."
          if (Test-Path "C:\Xfer\Migration\$($Devcon)") 
		  { 
			Trace "Devcon file exists.  Proceeding to check for Ghosted NICs..." -Warn
          } 
          else 
		  {
			  $uri = "https://$($WebServer)/$($Devcon)"
			  Trace "Downloading Devcon"
			  $webClient = New-Object System.Net.WebClient
			  $webClient.DownloadFile($uri, $destPath)
          }

##end region <Install Devcon>

##region <Remove Ghosted NICS>
Remove-GhostedNICs
##end region

##region <Remove Errored NICs>
Remove-ErroredNICs
##end region

##region <AddCommunityName_Security>
AddCommunityName_Security
##end region

#Region <Firewall Actions>
	
#Firewall Profiles go here

	#BeginRackware
	if ($SetFWProgProf -eq "Rackware") {
	$SetFWPort = $SetFWPort + "","TCP:23131","TCP:80","UDP:161","ECHO"
	if ($SetFWRule -eq "") {$SetFWRule = "Rackware"}
	$DisableFWGroup = "`"File and Printer Sharing`""
}	#EndRackware
	
# end of Firewall Profiles
	
QueryFirewallStatus
QueryProfileStatus
if ($Reset) { Reset }
if ($SetFWProfile) { SetFWProfile }
if ($SetFWService) { SetFWService }
if ($SetFWPort) { SetFWPort }
if ($DisableFWGroup) { DisableFWGroup }
if ($SetFWState) { SetFWState }
if ($KeepFWOriginalStartState) { KeepFWOriginalStartState }
#Region <Firewall Actions>

##region <Set DNS resolvers on first available NIC>
$FromFunction = "Set DNS Resolvers on first available NIC Region"
Trace "Setting DNS resolvers on first available NIC"
$indent++
$SavvisNic = ([array](Get-WmiObject Win32_NetworkAdapter -Filter "AdapterType='Ethernet 802.3' AND PhysicalAdapter='TRUE'"))[0]
if ($SavvisNic -ne "") {
	Trace "Found NIC '$($SavvisNic.NetConnectionId)' with MAC address $($SavvisNic.MACaddress)"
	$SavvisNicConfig = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.MacAddress -eq $SavvisNic.MacAddress}
	$DG=$SavvisNicConfig.DefaultIPGateway
	$result = $savvisNicconfig.SetDNSServerSearchOrder($DNSServers)
	if ($result.ReturnValue -ne 0) {
		$eventMessage = "Failed to set DNS servers '$($DNSServers)' during post-migration with error $($result.ReturnValue).  Manually configure DNS server on this NIC."
		Trace $eventMessage -err
	} else {
		$eventMessage = "DNS servers '$($DNSServers)' were set during post-migration on NIC '$($SavvisNic.NetConnectionId)' with MAC address $($SavvisNic.MACaddress)"
		Trace $eventMessage
	}
} else {
	$eventMessage = "Failed to set DNS servers '$($DNSServers)'.  A suitable NIC was not found."
	Trace $eventMessage -err
}

$indent--
##endregion

##region <Delete static routes>
$FromFunction = "Delete Static Routes Region"
Trace "Removing static routes"
$indent++
foreach($route in (Get-WmiObject Win32_IP4PersistedRouteTable)){
   if ($route.Destination -ne '0.0.0.0' )
   {
     Trace "Removing persistent route: $($Route.Description)"
	$cmdResult = invoke-expression "ROUTE DELETE $([string]$Route.Destination)"
	
	Trace "$cmdResult"
   }
   elseif (($route.Destination -eq '0.0.0.0' -and $route.NextHop -ne $DG))
   {
      Trace "Removing superfluous GATEWAY route: $($Route.Description)"
	  Trace "This is usually caused by GHOST NICs." -Warn
     $cmdResult = invoke-expression "ROUTE DELETE 0.0.0.0 MASK 0.0.0.0 $($Route.NextHop)"
	
	Trace "$cmdResult"
   }
}   
$Indent--
##endregion

##region <Reconfigure KMS>
$FromFunction = "Reconfigure KMS"
Trace "Configuring KMS name for activation"
$KMSCMD = "CScript //NoLogo C:\Windows\System32\slmgr.vbs /skms $KMSServer"
$kmsCmdOutput = Invoke-Expression "$KMSCMD 2>&1"
$kmsCmdOutput | ForEach-Object {Trace " >> $($_)"}

Trace "Attempting to activate Windows"
$KMSCMD = "CScript //NoLogo C:\Windows\System32\slmgr.vbs /ato"
$kmsCmd2Output = Invoke-Expression "$KMSCMD 2>&1"
$kmsCmd2Output | ForEach-Object {Trace " >> $($_)"}
##endregion

##region <Reset WSUS config>
$FromFunction = "Reset WSUS Config"
Trace "Stopping WSUS service"
$indent++
Stop-Service wuauserv
Trace "Clearing WSUS Identity"
$wsusItems = "PingID", "AccountDomainSid", "SusClientId", "SusClientIdValidation"
foreach ($item in $wsusItems) {
	Trace "Removing '$item'"
	$indent++
	Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate -Name $item -ErrorAction SilentlyContinue
	if ($?) {
		Trace "Removed item successfully"
	} else {
		if ($error[0].Exception.Message -match 'does not exist at path') {
			Trace "Item did not exist"
		} else {
			Trace "Could not remove item '$item'" -Err
			Trace ">> $($error[0].Exception.Message)" -Err
		}
	}
	$indent--
}
Trace "Restarting WSUS service"
Start-Service wuauserv
Trace "Resetting WSUS authorization"

wuauclt.exe /resetauthorization /detectnow
$indent--
##endregion

##region <Setting local administrator flags and password>
$FromFunction = "Setting Local Administrator Flags and Password"
Trace "Setting Administrator Password..."

if ($AdminPassword -eq "") {
	$AdminPassword = New-Password -UrlSafe
	Trace "Stopping transcript so that password is not logged.."
    Stop-Transcript
	## Output password to screen, but keep out of the log by stopping and starting the transcript
	
	Write-Host "##### ---------------------------------------------------------------- #####" -Foreground Yellow -Background Black
	Write-Host "##### The password for Administrator will be set to:                   #####" -Foreground Yellow -Background Black
    Write-Host "#####                       $($AdminPassword)                             #####" -Foreground RED -Background BLACK
	Write-Host "#####          !!!  THIS WILL NOT BE RECORDED IN THE LOG !!!           #####" -Foreground Yellow -Background Black
	Write-Host "##### ---------------------------------------------------------------- #####" -Foreground Yellow -Background Black
	Start-Transcript $logFile -Append -ErrorAction SilentlyContinue
}
else
{
    Trace "Password was supplied from command line.  Setting to the provided value." -Warn
}

Set-LocalAdmin $AdminPassword
##endregion

#this section deprecated now that we have a firewall actions section.
##region <Verifying Windows Firewall status>
#Trace "Verifying firewall configuration"
#$indent++
#$firewallStatus = (Get-Service mpssvc).Status
#Trace "Windows Firewall service is $($firewallStatus)"
#if ($firewallStatus -ne 'Running') {
#	Trace "Setting Windows Firewall service to Automatic"
#	Set-Service -Name mpssvc -StartupType Automatic
#	Trace "Starting Windows Firewall service"
#	Start-Service -Name mpssvc
#}
#Trace "Checking if firewall is disabled for all profiles"
#[bool]$profileEnabled = $false
#$firewallProfileStatus = Invoke-Expression -Command "netsh advfirewall show allprofiles State"
#$profileStatus = $firewallProfileStatus | ForEach-Object {
#	if ($_ -match 'Profile settings') {
#		$profileName = $_.Split()[0]
#	} elseIf ($_ -match '^State') {
#		New-Object PsObject -Property @{Profile = $profileName;Status = $_.Split()[-1]}
#		if ($_.Split()[-1] -match 'ON') {$profileEnabled = $true}
#	}
#}

#if ($profileEnabled -eq $false) {
#	Trace "All profiles are disabled"
#} else {
#	Trace "One or more profiles are enabled" -warn
#	$indent++
#	$profileStatus | Where-Object {$_.Status -eq 'ON'} | ForEach-Object {
#		Trace "Profile $($_.Profile) is $($_.Status)" -Warn
#	}
#	$indent--
#	Trace "Disabling all Firewall profiles"
#	Invoke-Expression -Command "Netsh advfirewall set AllProfiles state off" | out-null
#}
#$indent--
##endregion


##region <Download SysAdmin-2K8.zip>
$FromFunction = "Download SysAdmin-2k8.zip Region"
  $destPath = "C:\Xfer\Migration\SysAdmin-2K8.zip"
  Trace "Checking for SysAdmin-2k8 package..."
if (Test-Path "C:\Xfer\Migration\SysAdmin-2K8.zip")
{ 
  Trace "Zip file exists.  Proceeding to extraction step..." -Warn
  }
else
{
	$uri = "https://$($WebServer)/Sysadmin-2K8.zip"
	
	Trace "Downloading SysAdmin-2K8.zip from '$uri'"
	$webClient = New-Object System.Net.WebClient
	$webClient.DownloadFile($uri, $destPath)
  }
Trace "Checking to see if C:\SysAdmin exists..."
if (Test-Path "C:\Sysadmin")
{
  $indent++
  Trace "Sysadmin Folder already exists. Renaming current folder to C:\SysAdmin_orig..." -warn
  $foldername = get-date -format "hh.mm.ss"
  rename-item "C:\Sysadmin" "C:\Sysadmin_$($foldername)" -Force
  $indent--
}
Trace "Extracting '$($destpath)' to 'C:\SysAdmin'..."
Expand-ZIPFile -File $destPath -Destination "C:\"

##endregion

##region <Install .NET Framework 4.5.2>
$FromFunction = "Install .NET Framework 4.5.2"
$dotNetPackage="NDP452-KB2901907-x86-x64-AllOS-ENU.exe"
$destPath = "C:\Xfer\Migration\$($dotNetPackage)"
 Trace "Checking for $($dotNetPackage) installer..."
if (Test-Path "C:\Xfer\Migration\$($DotNetPackage)")
{ 
  Trace "Installation file exists.  Proceeding to installation step..." -Warn
  }
else{

$uri = "https://$($WebServer)/$($dotNetPackage)"

Trace "Downloading .NET Framework 4.5.2 installer"
$webClient = New-Object System.Net.WebClient
$webClient.DownloadFile($uri, $destPath)
}
Trace "Installing .NET Framework 4.5.2"

Invoke-Expression "C:\Xfer\Migration\$($dotNetPackage) /q /log C:\Xfer\Migration\dotNET452.log /norestart"
$indent++
Do {
	Trace "Waiting 30 Seconds for .NET installer to complete"
	Start-Sleep -Seconds 30
	$results = Get-Process -name($dotNetPackage.split(".")[0]) -ErrorAction SilentlyContinue
} until ($results -eq $null)
$Indent--
Trace "Finished installing .NET 4.5.2"
##endregion

##region <Download and Install VMware Tools>
$FromFunction = "Download and Install VMWare Tools"
$destPath = "C:\Xfer\Migration\VMware-tools-9.4.10-2092844-x86_64.zip"
 Trace "Checking for '$($destPath)' ..."
if (Test-Path $DestPath)
{ 
  Trace "Zip file exists.  Proceeding to extraction step..." -Warn
  }
else{
	$uri = "https://$($WebServer)/$($VMwareTools)"
	Trace "Downloading VMware Tools from '$uri'"
	$webClient = New-Object System.Net.WebClient
	$webClient.DownloadFile($uri, $destPath)
}
Trace "Checking for 'C:\Xfer\Migration\VMware-tools-9.4.10-2092844-x86_64.exe'"

if (test-path "C:\Xfer\Migration\VMware-tools-9.4.10-2092844-x86_64.exe")
{
  Trace "Installation file exists.  Proceeding to installation step..." -Warn
}
else 
{
Trace "Extracting VMware Tools binary..."  
Expand-ZIPFile -File $destPath -Destination "C:\Xfer\Migration"
}

Trace "Installing VMware Tools"
Trace "*** This may cause RDP sessions to disconnect due to network driver updates ***" -WARN
$results = Invoke-Expression 'C:\Xfer\Migration\VMware-tools-9.4.10-2092844-x86_64.exe /S /v "/qn REBOOT=R /l*v ""C:\Xfer\Migration\VMware-Tools.log"""'
$indent++
Do {
	Trace "Waiting 10 Seconds for VMware Tools installer to complete"
	$TPVCGW=$Null
	Start-Sleep -Seconds 10
	$TPVCGW=get-process TPVCGateway -ErrorAction SilentlyContinue
	if($TPVCGW -ne $null)
	{
	  Trace "Found ThinPrint Gateway Process. Killing it due to known VMware bug." -Warn
	   $TPVCGW.Kill()
	   }
	$results = Get-Process VMware-tools-9.4.10-2092844-x86_64 -ErrorAction SilentlyContinue
} until ($results -eq $null)
$Indent--
##endregion


Trace "Cleaning up remaining installer packages"
Remove-Item C:\Xfer\wget-1.11.4-1-setup.exe -Force -ErrorAction SilentlyContinue
Remove-Item C:\Xfer\Migration\VMware-tools-9.4.10-2092844-x86_64.zip -Force -ErrorAction SilentlyContinue
Remove-Item C:\Xfer\Migration\VMware-tools-9.4.10-2092844-x86_64.exe -Force -ErrorAction SilentlyContinue
Remove-Item C:\Xfer\Migration\$($dotNetPackage) -Force -ErrorAction SilentlyContinue
Remove-Item C:\Xfer\Migration\SysAdmin-2K8.zip -Force -ErrorAction SilentlyContinue 

If ( $Reboot -eq $True){
  Trace "REBOOT flag was supplied"
  Trace "Rebooting computer..."
 
  }
  else
   {
   Trace "Please reboot this server to complete the 'Post Migration' steps..."
   
  }
#}

#Region <List Errors>
if ($IsError -ne $null) { 
	trace "The following handled errors were recorded:"
	trace $IsError
	trace "Number of handled errors recorded: $($IsError.count)"
	trace "Unhandled messages were the logged to the following c:\xfer\unhandledmsgs.log"
	$timestamp = (Get-Date).ToString()
	write-output ("-" * 80) $timestamp ("-" * 80) >> c:\xfer\unhandledmsgs.log
	write-output $error >> c:\xfer\unhandledmsgs.log
} else { 
	trace "No handled errors are being displayed." 
	trace "Unhandled messages were the logged to the following c:\xfer\unhandledmsgs.log"
	$timestamp = (Get-Date).ToString()
	write-output ("-" * 80) $timestamp ("-" * 80) >> c:\xfer\unhandledmsgs.log
	write-output $error >> c:\xfer\unhandledmsgs.log
}
#endregion

Stop-Transcript
Write-Host ("-" * 90) -Foreground RED -Background BLACK
Write-Host "Please record the following password for 'Administrator': $($AdminPassword)" -Foreground RED -Background Black
Write-Host ("-" * 90) -Foreground RED -Background BLACK
$Continue=Read-host "Press <ENTER> to continue..."

##region <reboot system>
$caption = "Choose Action"
$message = "Rebooting is required for all changes to take affect.  You may choose to reboot this computer at a later time, manually.  Would you like to reboot NOW?"
$yes = new-Object System.Management.Automation.Host.ChoiceDescription "&yes","reboot"
$no = new-Object System.Management.Automation.Host.ChoiceDescription "&no","no"

$choices = [System.Management.Automation.Host.ChoiceDescription[]]($yes,$no)
$answer = $host.ui.PromptForChoice($caption, $message, $choices, 0)

if($answer -eq 0) { Restart-Computer -Confirm:$true }
if($answer -eq 1) { Write-Host "You've chosen to reboot the computer manually at a later time" }


##endregion

<#
	.SYNOPSIS
		Cleans up a Windows 2008 R2 VPDC VM after migration to CLC

	.DESCRIPTION
		This script performs tasks necessary following the migration of a 
		Windows 2008 R2 VPDC VM to CLC.  The script performs the following tasks:
		
		* Installs the SNMP and SNMP-WMI features, if necessary
		* Removes existing domain-based users and groups from local groups
		* Removes the computer from the domain and joins WORKGROUP workgroup
		* Uninstalls the following software:
			- McAfee VirusScan
			- McAfee ePO Agent
			- NetBackup
			- HPSA Agent
			- SIA
		* Removes all static routes apart from the default gateway
		* Removes all HOSTS entries
		* Sets the DNS resolvers supplied on the first available NIC
		* Reconfigures and re-activates using the KMS server supplied
		* Removes any existing WSUS identity
		* Renames the BUILTIN administrator account to 'Administrator'
		* Resets the Administrator password to a randomly generated one
		* Verifies that Windows Firewall is running but disabled for all profiles
		* Downloads SysAdmin-2K8.zip from the RMM web server
		* Upgrades/Installs the .NET Framework to version 4.5.2
		* Upgrades/Installs VMware Tools to version 9.4.10-2092844
		* Removes the following installer packages:
			- Wget
			- VMware Tools
			- .NET Framework 4.5.2
		* Reboots the computer to complete the automated migration steps

	.EXAMPLE
		$example$
		
	.LINK
		https://confluence.savvis.net/x/o7Y5Bg
		
	.COMPONENT
		$List of required components, one per line$

	.NOTES
		#AUTHOR  : Russell Pitcher, CenturyLink, Cloud Product Engineering
		#DATE    : 2015-04-02
		#TAGS    : CLC, VPDC, Migration
		#VERSION : 01.01.00
		            |  |  +- Bug fix version
		            |  +---- Feature version
		            +------- Major version
#>