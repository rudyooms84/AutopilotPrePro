
<#PSScriptInfo
 
.VERSION 0.1
 
.GUID 715a6707-796c-445f-9e8a-8a0fffd778a5
 
.AUTHOR Rudy Ooms
 
.COMPANYNAME
 
.COPYRIGHT
 
.TAGS Windows, AutoPilot, Powershell
 
.LICENSEURI
 
.PROJECTURI https://www.github.com
 
.ICONURI
 
.EXTERNALMODULEDEPENDENCIES
 
.REQUIREDSCRIPTS
 
.RELEASENOTES
 
Version 0.1: Initial Release.
 
.PRIVATEDATA
 
#>
<#
 
.DESCRIPTION

.SYNOPSIS
GUI to import Device to Autopilot.
 
MIT LICENSE
Copyright (c) 2022 Rudy Ooms
     
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
     
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
     
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 
.DESCRIPTION
The goal of this script is to help with the troubleshooting of Attestation issues when enrolling your device with Autopilot for Pre-Provisioned deployments

.EXAMPLE
Blog post with examples and explanations @call4cloud.nl
 
.LINK
Online version: https://call4cloud.nl
#>

# Making sure the script is run as admin

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$runasadmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if($runasadmin -eq $false){
write-host "Script is not run as admin!" -ForegroundColor red
exit (0)
}

# Test Internet Connection

function Test-WebConnection {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $True)]
        [string]$Uri = 'google.com'
    )
    begin {}
        process {
        $Params = @{
            Method = 'Head'
            Uri = $Uri
            UseBasicParsing = $True
        }

        try {
            Write-Verbose "Test-WebConnection OK: $Uri"
            Invoke-WebRequest @Params | Out-Null
            $true
        }
        catch {
            Write-Verbose "Test-WebConnection FAIL: $Uri"
            $false
        }
        finally {
            $Error.Clear()
        }
    }
    
    end {}
}






$testinternernet = test-webconnection www.google.com

 If($testinternernet -eq "False"){
       write-host "Internet Connection Available!" -ForegroundColor Green
       Write-Host @ErrorIcon
    } else {
      
  write-host "No Internet Connection Available, Please check your internet connection before trying again!" -ForegroundColor Red
      Write-Host @ErrorIcon
      exit 1
      }



if($internetmsg -eq "Internet Connection Available!"){
write-host "Making sure the correct Time is configured !" -ForegroundColor yellow
    cmd /c "pushd %SystemRoot%\system32" | out-null
    cmd /c "net stop w32time" | out-null
    cmd /c "w32tm /unregister" | out-null
    cmd /c "w32tm /register" | out-null
    cmd /c "sc config w32time type= own" | out-null
    cmd /c "net start w32time" | out-null
    cmd /c "w32tm /config /update /manualpeerlist:0.pool.ntp.org,1.pool.ntp.org,2.pool.ntp.org,3.pool.ntp.org,0x8 /syncfromflags:MANUAL /reliable:yes" | out-null
    cmd /c "w32tm /resync" | out-null
    cmd /c "popd" | out-null
    
    
    # Apparaat Info
    $SerialNoRaw = wmic bios get serialnumber
    $SerialNo = $SerialNoRaw[2]
    
    $ManufacturerRaw = wmic computersystem get manufacturer
    $Manufacturer = $ManufacturerRaw[2]
    
    $ModelNoRaw = wmic computersystem get model
    $ModelNo = $ModelNoRaw[2]
    
    Write-Host "Computer Serialnumber: `t $SerialNo" -ForegroundColor Yellow
    Write-Host "Computer Supplier: `t $Manufacturer" -ForegroundColor Yellow
    Write-Host "Computer Model: `t $ModelNo" -ForegroundColor Yellow
    
    

}

 Write-Host "Starting Connectivity test to Intel, Qualcomm and AMD" -ForegroundColor Yellow


    $TPM_Intel = (Test-NetConnection ekop.intel.com -Port 443).TcpTestSucceeded
    If($TPM_Intel -eq "True"){
        Write-Host -NoNewline -ForegroundColor Green "TPM_Intel - Success "
        Write-Host @ErrorIcon  
    } else {
        Write-Host -NoNewline -ForegroundColor Red "TPM_Intel - Error "
        Write-Host @ErrorIcon   
    }
    $TPM_Qualcomm = (Test-NetConnection ekcert.spserv.microsoft.com -Port 443).TcpTestSucceeded
    If($TPM_Qualcomm -eq "True"){
        Write-Host -NoNewline -ForegroundColor Green "Qualcomm - Success "
        Write-Host @ErrorIcon
    } else {
        Write-Host -NoNewline -ForegroundColor Red "Qualcomm - Error "
        Write-Host @ErrorIcon
    }
    $TPM_AMD = (Test-NetConnection ftpm.amd.com -Port 443).TcpTestSucceeded
    If($TPM_AMD -eq "True"){
        Write-Host -NoNewline -ForegroundColor Green "AMD - Success "
       Write-Host @ErrorIcon
    } else {
        Write-Host -NoNewline -ForegroundColor Red "AMD - Error "
     Write-Host @ErrorIcon
    }
    $TPM_Azure = (Test-NetConnection azure.net -Port 443).TcpTestSucceeded 
    If($TPM_Azure -eq "True"){
        Write-Host -NoNewline -ForegroundColor Green "Azure - Success "
      Write-Host @ErrorIcon
    } else {
        Write-Host -NoNewline -ForegroundColor Red "Azure - Error "
      Write-Host @ErrorIcon
    }




# Test Windows 10 license
$WindowsProductKey =  (Get-WmiObject -query "select * from SoftwareLicensingService").OA3xOriginalProductKey
$WindowsProductType = (Get-WmiObject -query "select * from SoftwareLicensingService").OA3xOriginalProductKeyDescription


Write-Host "[BIOS] Windows Product Key: $WindowsProductKey" -ForegroundColor Yellow
Write-Host "[BIOS] Windows Product Type: $WindowsProductType" -ForegroundColor Yellow


If($WindowsProductType -like "*Professional*" -or $WindowsProductType -eq "Windows 10 Pro" ){
    Write-Host "BIOS Windows licentie is suited for MS365 enrollment" -ForegroundColor Green
}
else{
    Write-Host "BIOS Windows licentie is not suited for MS365 enrollment" -ForegroundColor red
    $WindowsProductType = get-computerinfo | select WindowsProductName
    $WindowsProductType = $WindowsProductType.WindowsProductName
    
    Write-Host "[SOFTWARE] Windows Product Key: $WindowsProductKey" -ForegroundColor Yellow
    Write-Host "[SOFTWARE] Windows Product Type: $WindowsProductType" -ForegroundColor Yellow
    
    If($WindowsProductType -like "*Professional*" -or $WindowsProductType -eq "Windows 10 Pro" ){
        Write-Host "SOFTWARE Windows licentie is valid for MS365 enrollment" -ForegroundColor Green
    }
    else{
    Write-Host "SOFTWARE Windows licentie is not valid for MS365 Enrollment" -ForegroundColor red
    exit(0)
    }
}


Write-Host "Determining if the Infineon TPM has vulnerable Firmware" -ForegroundColor Yellow

$IfxManufacturerIdInt = 0x49465800 # 'IFX'
		function IsInfineonFirmwareVersionAffected ($FirmwareVersion)
		{
			$FirmwareMajor = $FirmwareVersion[0]
			$FirmwareMinor = $FirmwareVersion[1]
			switch ($FirmwareMajor)
			{
				4 { return $FirmwareMinor -le 33 -or ($FirmwareMinor -ge 40 -and $FirmwareMinor -le 42) }
				5 { return $FirmwareMinor -le 61 }
				6 { return $FirmwareMinor -le 42 }
				7 { return $FirmwareMinor -le 61 }
				133 { return $FirmwareMinor -le 32 }
				default { return $False }
			}
		}
		function IsInfineonFirmwareVersionSusceptible ($FirmwareMajor)
		{
			switch ($FirmwareMajor)
			{
				4 { return $True }
				5 { return $True }
				6 { return $True }
				7 { return $True }
				133 { return $True }
				default { return $False }
			}
		}
		$Tpm = Get-Tpm
		$ManufacturerIdInt = $Tpm.ManufacturerId
		$FirmwareVersion = $Tpm.ManufacturerVersion -split "\."
		$FirmwareVersionAtLastProvision = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TPM\WMI" -Name "FirmwareVersionAtLastProvision" -ErrorAction SilentlyContinue).FirmwareVersionAtLastProvision
		if (!$Tpm)
		{
			Write-Host "No TPM found on this system, so the issue does not apply here."
		}
		else
		{
			if ($ManufacturerIdInt -ne $IfxManufacturerIdInt)
			{
				Write-Host "This non-Infineon TPM is not affected by the issue."
			}
			else
			{
				if ($FirmwareVersion.Length -lt 2)
				{
					Write-Error "Could not get TPM firmware version from this TPM."
				}
				else
				{
					if (IsInfineonFirmwareVersionSusceptible($FirmwareVersion[0]))
					{
						if (IsInfineonFirmwareVersionAffected($FirmwareVersion))
						{
							Write-Host ("This Infineon firmware version {0}.{1} TPM is not safe. Please update your firmware." -f [int]$FirmwareVersion[0], [int]$FirmwareVersion[1]) -ForegroundColor red
						}
						else
						{
							Write-Host ("This Infineon firmware version {0}.{1} TPM is safe." -f [int]$FirmwareVersion[0], [int]$FirmwareVersion[1]) -ForegroundColor green

							if (!$FirmwareVersionAtLastProvision)
							{
								Write-Host ("We cannot determine what the firmware version was when the TPM was last cleared. Please clear your TPM now that the firmware is safe.") -ForegroundColor red
							}
							elseif ($FirmwareVersion -ne $FirmwareVersionAtLastProvision)
							{
								Write-Host ("The firmware version when the TPM was last cleared was different from the current firmware version. Please clear your TPM now that the firmware is safe.") -ForegroundColor red
							}
						}
					}
					else
					{
						Write-Host ("This Infineon firmware version {0}.{1} TPM is safe." -f [int]$FirmwareVersion[0], [int]$FirmwareVersion[1]) -ForegroundColor green
					}
				}
			}
		}

# Test TPM Attestation #

$IntegrityServicesRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\IntegrityServices"
$WBCL = "WBCL"
$TaskStatesRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\TPM\WMI\taskStates"
$EkCertificatePresent = "EkCertificatePresent"
$OOBERegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\OOBE"
$SetupDisplayedEula = "SetupDisplayedEula"


$tpmtool = "https://call4cloud.nl/wp-content/uploads/2022/08/TpmDiagnostics.zip"
$path = "C:\windows\system32"
Invoke-WebRequest $tpmtool -OutFile "$path\ZippedFile.zip"
Expand-Archive -LiteralPath "$path\ZippedFile.zip" -DestinationPath "$path" -force



$attestation = Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -ClassName 'Win32_TPM' | Invoke-CimMethod -MethodName 'Isreadyinformation'
$attestationerror = $attestation.information
$keyattestation = Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -ClassName 'Win32_TPM' | Invoke-CimMethod -MethodName 'IsKeyAttestationCapable'
$keyattestationerror = $keyattestation.testresult

    if($attestationerror -eq "0")
    {
    write-host "TPM seems Ready For Attestation.. Let's Continue and test the Attestation itself!" -ForegroundColor Green 
    }if(!(Get-Tpm | Select-Object tpmowned).TpmOwned -eq $true)
    {
        Write-Host "Reason: TpmOwned is FALSE (Get-Tpm)" -ForegroundColor Red
    }If(!(Get-ItemProperty -Path $IntegrityServicesRegPath -Name $WBCL -ErrorAction Ignore))
    {
        Write-Host "Reason: Registervalue HKLM:\SYSTEM\CurrentControlSet\Control\IntegrityServices\WBCL does not exist! Measured boot logs are missing. Make sure your reboot your device!" -ForegroundColor Red
    }if((Get-ItemProperty -Path $TaskStatesRegPath).EkCertificatePresent -ne 1 ) 
    {
        Write-Host "Reason: Registervalue HKLM:\SYSTEM\CurrentControlSet\Services\TPM\WMI\taskStates\EkCertificatePresent missing!! Launching TPM-Maintenance Task!" -ForegroundColor Red
        Start-ScheduledTask -TaskPath "\Microsoft\Windows\TPM\" -TaskName "Tpm-Maintenance" -erroraction 'silentlycontinue'
        sleep 5

        $taskinfo = Get-ScheduledTaskInfo -TaskName "\Microsoft\Windows\TPM\Tpm-Maintenance" -ErrorAction Ignore
        $tasklastruntime = $taskinfo.LastTaskResult  

    If($tasklastruntime -ne 0)
    {
    Write-Host "Reason: TPM-Maintenance Task could not be run! Checking and Configuring the EULA Key!" -ForegroundColor Red
    }
  
    If((!(Get-ItemProperty -Path $OOBERegPath -Name $SetupDisplayedEula -ErrorAction Ignore)) -or ((Get-ItemProperty -Path $OOBERegPath -Name $SetupDisplayedEula -ErrorAction Ignore).SetupDisplayedEula -ne 1)) 
    {
        Write-Host "Reason: Registervalue HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\OOBE\SetupDisplayedEula does not exist! EULA is not accepted!" -ForegroundColor Red
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\OOBE\' -Name  'SetupDisplayedEula' -Value '1' -PropertyType 'DWORD' –Force| Out-null
        Write-Host "SetupDisplayedEula registry key configured, rerunning the TPM-Maintanence Task" -ForegroundColor Yellow
        Start-ScheduledTask -TaskPath "\Microsoft\Windows\TPM\" -TaskName "Tpm-Maintenance" -erroraction 'silentlycontinue'  
    }
    sleep 5
    $taskinfo = Get-ScheduledTaskInfo -TaskName "\Microsoft\Windows\TPM\Tpm-Maintenance" -ErrorAction Ignore
    $tasklastruntime = $taskinfo.LastTaskResult  
   
    If($tasklastruntime -ne 0)
    {
    Write-Host "TPM-Maintenance task could not be run succesfully despite the EULA key being set! Exiting now!" -ForegroundColor Red
    exit (0)
    }

    If($tasklastruntime -eq 0){
    Write-Host "EULA Key is set and TPM-Maintenance Task has been run succesfully!" -ForegroundColor Green
    }

    }if(!(test-path -path HKLM:\SYSTEM\CurrentControlSet\Services\Tpm\WMI\Endorsement\EKCertStore\Certificates\*))
    {
        Write-Host "Reason:EKCert seems to be missing in HKLM:\SYSTEM\CurrentControlSet\Services\Tpm\WMI\Endorsement\EKCertStore\Certificates\ - Launching TPM-Maintenance Task!" -ForegroundColor Red
        Start-ScheduledTask -TaskPath "\Microsoft\Windows\TPM\" -TaskName "Tpm-Maintenance" -erroraction 'silentlycontinue' 
        sleep 5
        Write-Host "Going hardcore! Installing that damn EkCert on our own!!" -ForegroundColor yellow

        tpmdiagnostics installekcertfromnvr | out-null
        tpmdiagnostics installekcertfromweb | out-null
        tpmdiagnostics installekcertThroughCoreProv | out-null
        sleep 5
        $endorsementkey = get-tpmendorsementkeyinfo          
    }if($endorsementkey.IsPresent -ne $true)
    {
    Write-Host "Endorsementkey still not present!!" -ForegroundColor Red
    }else{
     Write-Host "Endorsementkey reporting for duty!" -ForegroundColor green
    }   

             

    

#geting AIK Test CertEnroll error


$attestation = Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -ClassName 'Win32_TPM' | Invoke-CimMethod -MethodName 'Isreadyinformation'
$attestationerror = $attestation.information


if($attestationerror -eq "0")
    {
   write-host "Retrieving AIK Certificate....." -ForegroundColor Green

$errorcert = 1
    for($num = 1 ; $errorcert -ne -1 ; $num++)
      {
        Write-Host "Fetching test-AIK cert - attempt $num"
        $certcmd = (cmd.exe /c "certreq -q -enrollaik -config """)

        $errorcode = 

        $startcert  = [array]::indexof($certcmd,"-----BEGIN CERTIFICATE-----")
        $endcert    = [array]::indexof($certcmd,"-----END CERTIFICATE-----")
        $errorcert  = [array]::indexof($certcmd,'{"Message":"Failed to parse SCEP request."}')
       
       $certlength = $endcert - $startcert
        If($certlength -gt 1){
            write-host "Found Test AIK Certificate" -ForegroundColor Green
            $cert = $certcmd[$startcert..$endcert]
            write-host $cert -ForegroundColor DarkGreen
            write-host "AIK Test AIK Enrollment succeeded" -ForegroundColor Green
      }
        else{
            write-host "AIK TEST Certificaat could not be retrieved" -ForegroundColor Red
            if($num -eq 10)
        {
                write-host "Retried 10 times, killing process" -ForegroundColor Red
                exit (0)
        }
        }
    }

#fetching AIkCertEnrollError
Write-Host "Running another test, to determine if the TPM is capable for key attestation... just for fun!!" -ForegroundColor Yellow

$attestationcapable = Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -ClassName 'Win32_TPM' | Invoke-CimMethod -MethodName 'IsKeyAttestationCapable'
$attestationcapable = $attestationcapable.testresult

If ($attestationcapable -ne 0){
 Write-Host "Reason: TPM doesn't seems capable for Attestation!" -ForegroundColor Red
 tpmtool getdeviceinformation
 }else{
 Write-Host "We can almost start celebrating! TPM is capable for attestation! "-ForegroundColor green
 }
   
   


Write-Host "Launching the real AikCertEnroll task!" -ForegroundColor Yellow

Start-ScheduledTask -TaskPath "\Microsoft\Windows\CertificateServicesClient\" -TaskName "AikCertEnrollTask"
sleep 5
$AIKError = "HKLM:\SYSTEM\CurrentControlSet\Services\TPM\WMI\"
If ((Get-ItemProperty -Path $AIKError -Name "AIKEnrollmentErrorCode" -ErrorAction Ignore).AikEnrollmenterrorcode -ne 0){
 Write-Host "Reason: AIK Cert Enroll Failed!" -ForegroundColor Red
 tpmtool getdeviceinformation
 }else{
 Write-Host "AIK Cert Enroll Task Succeeded, Looks like the device is 100% ready for attestation!You can start the Autopilot Pre-Provioning! "-ForegroundColor green
 }
   

}else{
    write-host "TPM is still NOT suited for Autopilot Pre-Provisioning,  please re-run the test again" -ForegroundColor RED
    tpmtool getdeviceinformation
    exit (0)
   }
   




