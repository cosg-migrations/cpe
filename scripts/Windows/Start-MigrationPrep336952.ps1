$ScriptVersion = "1.1"

[CmdletBinding(SupportsShouldProcess=$false)]
Param ()
if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("debug")) {$DebugPreference="Continue"}
New-Variable -Option 'AllScope' -Name 'indent' -Value (0 -as [int]) 
New-Variable -option 'AllScope' -Name 'logFile' -Value (($MyInvocation.MyCommand.Name).Replace(".ps1","_$(Get-Date -Format ""yyyy-MM-dd_HH-mm"").log") -as [string])
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
    if ($Err)  {$type = "ERROR";   if ($ForegroundColor -eq "") {$ForegroundColor = 'Red'}}
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

Function Test-ForVMwareTools
{
	$VMwareInstalled = $false
	$installedSoftware = Get-WmiObject Win32_Product
	trace "Checking to see if VMware Tools are installed."
	
	$installedSoftware | foreach-object {
		if ($_.name -match "VMware Tools") {
			$VMwareInstalled = $True
			$indent++
			trace "VMware Tools are installed, continuing with migration prep."
			$indent--
		}
	}

	if ($VMwareInstalled -eq $false) {
		$indent++
		trace "-------------------------------------------------------------------------" -e
		trace "|!!!!VMware Tools must be installed to continue Pre-Migration Script!!!!|" -e
		trace "|!!!!            The Pre-Migration Script is now stopping           !!!!|" -e
		trace "|!!!!    Install VMware Tools and run Pre-Migration Script again    !!!!|" -e
		trace "-------------------------------------------------------------------------" -e
		$indent--
		break
	}
}

Function Open-FirewallPort ($portNum, $Name)
{
	$FW=Get-WMIObject win32_service | where-object {$_.displayname -match "firewall"}
	if ($FW.State -eq "Running") 
		{
		  $port = New-Object -ComObject HNetCfg.FWOpenPort
		  $port.Port = $PortNum
		  $port.Name = $Name
		  $port.Enabled = $true

		  $fwMgr = New-Object -ComObject HNetCfg.FwMgr
		  $profile = $fwMgr.LocalPolicy.CurrentProfile
		  $profile.GloballyOpenPorts.Add($port)
		}  
		else
		{
		Trace " Firewall is not running, no rackware port created"
	}

}
 

Function Set-RemoteUAC
{
   Trace "Checking to see if UAC is enabled..."
   $UAC = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).EnableLUA
   If ($UAC -eq 1)
    {
	  $Indent++
	  Trace "UAC is currently enabled."
	  Trace "Disabling Remote UAC for migration discovery..."
	  $UACRemoteKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
	  $UACRemoteValue = "LocalAccountTokenFilterPolicy"
      $CurrentUACR = (Get-ItemProperty $UACRemoteKey).$UACRemoteValue
	  If ($CurrentUACR -eq $Null)
	    {
	       Trace "Remote UAC is ENABLED (by default setting)"
	     }
	  elseIf ($CurrentUACR -eq 0)
		{
		   Trace "Remote UAC is currently explicitly ENABLED."
		 }
	  else 
	    {
		   Trace "Remote UAC is currently explicitly DISABLED."
	     }
		
	  
	  $SetUACR = Set-ItemProperty -Path $UACRemoteKey -name $UACRemoteValue -value 1 -type dword
	  
	  $Indent--
	}
}

Function ResetUserFlag()
{Param ($userName)
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
	    $numb = "0123456789"
    $lett = "abcdefghijklmnopqrstuvwxyz"
    $punc = '!£$%^&*()_+-={}[]:@~;''"#<>?,./|\'
    if ($webSafe) {$punc = '!$*()_+-={}[]:./\'}
    if ($UrlSafe) {$punc = '!$*()_+-.'}
 
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
 }
function New-LocalAdminUser {
	Param(
		[string]$userName,
		[string]$userDesc = "Local Admin Account",
		[string]$strPass  = (New-Password -urlSafe)
	)
        Trace "Adding Admin User:"
	Trace "  User: $($userName)"
   $indent++
	# Check to see if user already exists and reset password if so
        Trace "Checking to see if '$($Username)' exists..."
        $u = [ADSI]"WinNT://$($env:computername)/$($username)"
        if ($U.name -eq $null) 
        {
	     $indent++
         Trace "User does not currently exist."
	     Trace "Creating user '$userName' with description '$userDesc'"
	     $computer = [ADSI]"WinNT://$($env:computername)"
	     $newUser = $computer.Create("User", $userName)
	     $newUser.SetPassword($strPass)
	     $newUser.SetInfo()
	     $newUser.Description = $userDesc
	     $newUser.SetInfo()
		 $indent--
          }
        else
         {
		    $Indent++
			Trace "User already exists. Resetting password..."
			$changeLAdminCMD = "net user $($Username) '$($strPass)'"
			$Result = Invoke-Expression $changeLAdminCMD

			if ($Result -Contains "The command completed successfully.") 
			{
				Trace "Password successfully set"
			} 
			else 
			{
				Trace "Password reset failed - please change by hand" -Err
			}
			Trace "Resetting account flags for '$($Username)'..."
			ResetUserFlag -Username $Username
		$Indent--
         }
	
	
	Trace "Stopping transcript so that password is not logged.."
	Stop-Transcript
	Write-Host "##### ---------------------------------------------------------------- #####" -Foreground Yellow -Background Black
	Write-Host "#####      The password for '$($Username)' will be:                        #####" -Foreground Yellow -Background Black
    Write-Host "#####                       $($strPass)                             #####" -Foreground RED -Background BLACK
	Write-Host "#####          !!!  THIS WILL NOT BE RECORDED IN THE LOG !!!           #####" -Foreground Yellow -Background Black
	Write-Host "#####  Save this password securely. It will be needed to login to the  #####" -Foreground Yellow -Background Black
	Write-Host "#####  server as part of the Post-Migration process.                   #####" -Foreground Yellow -Background Black
	Write-Host "##### ---------------------------------------------------------------- #####" -Foreground Yellow -Background Black
	Start-Transcript $logFile -Append -ErrorAction SilentlyContinue

	
        $adminGroup = [ADSI]"WinNT://$($env:computername)/Administrators,group"
trace "Attempting to add '$($username)' to the Local Administrators group"
	TRY{$AddGroup = $adminGroup.Add($newUser.Path)}catch{}
        $c=invoke-expression "net localgroup administrators | findstr ""$($username)"""
        if ($c -eq $username)
{
           trace "User '$($Username)' is currently a member of the 'Administrators' group"
}
else
{
 trace "User '$($Username)' failed to be added to 'Administrators' group.  Manually add user to this group" -Err
}
	$indent--
}


# Stop any current transcript and start a new one named after the script and the date/time
. {Trap {Continue}; Stop-Transcript | Out-Null}
#$logFile = ($MyInvocation.MyCommand.Name).Replace(".ps1","_$(Get-Date -Format ""yyyy-MM-dd_HH-mm"").log")
Start-Transcript $logFile -Force -ErrorAction SilentlyContinue

Trace "---- Migration prep script STARTED ----"
Trace "Script Version $ScriptVersion"
Trace "Checking for C:\Xfer folder..."
if (Test-Path -Path 'C:\Xfer') {
	Trace "C:\Xfer folder found"
} else {
	Trace "C:\Xfer folder not found" -Warn
	Trace "Creating C:\Xfer directory"
	New-Item C:\Xfer -Type Directory
}
Trace "Checking for C:\Xfer\Migration folder..."
if (Test-Path -Path 'C:\Xfer\migration') {
	Trace "C:\Xfer\Migration folder found"
} else {
	Trace "C:\Xfer\Migration folder not found" -Warn
	Trace "Creating C:\Xfer\Migration directory"
	New-Item C:\Xfer\Migration -Type Directory | out-null
}

#region <Test-ForVMwareTools>
Test-ForVMwareTools
#endregion

##region <Download and install wget>
$destPath = "C:\Xfer\wget-1.11.4-1-setup.exe"

#Check to make sure file was downloaded before continuing
$WGetInstalled = $False
Trace "Checking for 'wget.exe' ..."
if (Test-Path 'C:\Program Files (x86)\GnuWin32\bin\wget.exe') {
	$WGetInstalled = $True
} elseif (Test-Path 'C:\Program Files\GnuWin32\bin\wget.exe') {
	$WGetInstalled = $True
} else {
	$WGetInstalled = $False
}

If ($WgetInstalled -eq $False)
{
Trace "Installing wget from $destPath"
#if (Test-path $destpath )
#{
Invoke-Expression "$($destPath) /VERYSILENT /NORESTART /LOG /SUPPRESSMSGBOXES"
$indent++
Trace "Sleeping 30 seconds for installation to complete..."
Start-sleep -seconds 30

if (Test-Path 'C:\Program Files (x86)\GnuWin32\bin\wget.exe') {
	Trace "wget.exe found.  Installed successfully"
} elseif (Test-Path 'C:\Program Files\GnuWin32\bin\wget.exe') {
	Trace "wget.exe found.  Installed successfully"
} else {
	Trace "wget.exe not found. Installation failed" -Err
}
}
else
{
  $Indent++
  Trace "The 'wget' package is already installed. Continuing.."
   $Indent--
   }
$indent--
##endregion

##region <Create an administrator account for migration>
 New-LocalAdminUser  -userName 'rackware' -userDesc 'Rackware Migration Admin Account'
#New-LocalAdminUser  -userName 'Migration_admin' -userDesc 'Migration Admin Account'
##endregion

##region <Reset Remote UAC Setting for discovery>
 Set-RemoteUAC
##endregion
##region <Open Migration agent firewall port>
Trace "Opening the RMM Capture Agent port on the Windows Firewall..."
$FWRuleName = "RMM Capture Agent Port"
Open-FirewallPort -Name $FWRuleName -PortNum 23131
##endregion

##region <Set services to automatic and start>
# WinExeSvc Service will likely not be installed already. This service is needed to perform
#    execution of commands from automation via shell.
Trace "Configuring Services"
$servicesToStart = "MSiSCSI", "VSS",  "WinExeSvc"  
foreach ($service in $servicesToStart) {
	$indent++
	$thisService = Get-Service $service -ErrorAction SilentlyContinue
	if ($?) {
		Trace "Setting $($thisService.DisplayName) service to Automatic"
		$thisService | Set-Service -StartupType Automatic
		Trace "Starting $($thisService.DisplayName) service"
		$thisService | Start-Service
	} else {
	    if($Service -eq "WinExeSvc")
		 {
		  Trace $error[0].Exception -Warn
		 }
		 else
		 {
		  Trace $error[0].Exception -Err
		  }
	}
	$indent--
}
##endregion

##region <Record persistent routes>
Trace "Saving persistent routes"
Get-WmiObject Win32_IP4PersistedRouteTable | Export-Clixml -Path C:\Xfer\Migration\PersistentRoutes.xml
##endregion	

##region <Generate RMM command stings>
#Commenting this code... to be worked later.
#$myIpAddress = ((Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IpAddress -ne $null}) | Select-Object -First 1).IPAddress[0].ToString()
#Trace "RMM commands:"
#$indent++
#TODO: Not happy that these RMM commands are correct.  Need to read the doc more thoroughly and check with someone who knows...
#Trace "Discovery  : # rw h d $myIpAddress -n $BillingSiteId_$VPDCFriendlyName_discovered  –s $BillingSiteId_$VPDCFriendlyName_discovered  -–winuser [YOUR_USERNAME]  --winpass '[YOUR_PASSWORD]'"
#Trace "Capture    : # rw h ca $myIpAddress --clonename  $BillingSiteId_$VPDCFriendlyName_captured"
#Trace "Provis-Man : # rw h ca $myIpAddress --clonename $BillingSiteId_$VPDCFriendlyName_captured"
#Trace "Provis-Auto: # rw h ca $myIpAddress --clonename $CLCName"
#Trace "Add        : # rw system add $myIpAddress -s $BillingSiteId_$VPDCFriendlyName_target -–winuser [YOUR_USERNAME]  --winpass '[YOUR_PASSWORD]'"
#Trace "Assign-Man : # rw image assign $BillingSiteId_$VPDCFriendlyName_captured -s $BillingSiteId_$VPDCFriendlyName_target -n $BillingSiteId_$VPDCFriendlyName_assigned  --inherit-system-nics"
#Trace "Assign-Auto: # rw image assign $CLCName --clouduser [cloud_user] --autoprovision --autogen-conf"
#Trace "Sync Stage1: # rw image sync $BillingSiteId_$VPDCFriendlyName_discovered  --image $BillingSiteId_$VPDCFriendlyName_captured --allow-direct-fscopy"
#Trace "Sync Stage2: # rw image sync $BillingSiteId_$VPDCFriendlyName_captured --image $BillingSiteId_$VPDCFriendlyName_assigned"
#$indent--
##endregion

Trace "---- Migration prep script FINISHED ----"
Stop-Transcript

<#
.SYNOPSIS
	Prepares a Windows 2008 R2 VPDC VM for migration to CLC

.DESCRIPTION
	This script performs tasks necessary for the migration of a VPDC VM to
	CenturyLink Cloud.  The script performs the following tasks:
	
	* Creates the C:\Xfer directory if it does not already exist
	* Installs wget tool (to be copied to c:\Xfer manually)
	* Creates a new user and adds it to the Administrators group
	* Ensures that the iSCSI initiator service is running and set to Automatic
	* Ensures that the Volume Shadow Copy service is running and set to Automatic
	* Ensures that the WinExecSvc service is running and set to Automatic
	* Records any existing persistent routes to C:\Xfer\Migration\PersistentRoutes.xml 

.EXAMPLE
	$example$
	
.LINK
	https://confluence.savvis.net/x/p8MyB
	
.COMPONENT
	$List of required components, one per line$

.NOTES
	#AUTHOR  : Russell Pitcher, CenturyLink, Cloud Product Engineering
	#DATE    : 2015-04-02
	#TAGS    : VPDC,CLC,Migration
	#VERSION : 01.00.01
	            |  |  +- Bug fix version
	            |  +---- Feature version
	            +------- Major version
#>
