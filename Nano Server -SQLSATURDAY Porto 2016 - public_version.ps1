<# 

SQLSaturday #546 - Oporto 2016 (http://www.sqlsaturday.com/546) - 2016-10-01

What is Windows Nano Servers ?
By Ricardo Cabral @rramoscabral

What you need:
  - 1 virtual machine (Azure / On-premise) with Windows Server 2016
  - 1 virtual machine (Azure / On-premise) that will have the Windows Server Nano image
  - ISO Windows Server 2016
  - Windows Sysinternals Suite [https://technet.microsoft.com/en-us/sysinternals/bb842062.aspx] 
 
 
#>


<# Roles and features available im RTM edition:

Hyper-V role (including NetQoS)                 -Compute
Shielded VM                                     -Packages Microsoft-NanoServer-ShieldedVM-Package (Only available at datacenter editon)
Failover Clustering                             -Clustering
Basic drivers                                   -Microsoft-NanoServer-OEM-Drivers-Package
File Server role and other storage components	-Storage
Windows Defender Antimalware                    -Defender
DNS Server role	                                -Packages Microsoft-NanoServer
                                                -DNS-Package
Desired State Configuration (DSC)	            -Packages Microsoft-NanoServer-DSC-Package [https://msdn.microsoft.com/powershell/dsc/nanodsc?f=255&MSPPError=-2147217396]
Internet Information Server (IIS)	            -Packages Microsoft-NanoServer-IIS-Package [https://technet.microsoft.com/en-us/windows-server-docs/compute/nano-server/iis-on-nano-server]
Host support for Windows Containers	            -Containers
System Center Virtual Machine Manager agent	    -Packages Microsoft-NanoServer-SCVMM-Package
                                                -Packages Microsoft-NanoServer-SCVMM-Compute-Package
Network Performance Diagnostics Service (NPDS) 	-Packages Microsoft-NanoServer-NPDS-Package
Data Center Bridging (including DCBQoS	        -Packages Microsoft-NanoServer-DCB-Package
Deploying on a virtual machine	Microsoft       -NanoServer-Guest-Package
Deploying on a physical machine	Microsoft       -NanoServer-Host-Package
Secure Startup	                                -Packages Microsoft-NanoServer
                                                -SecureStartup-Packag

Location: [DVD|ISO]\NanoServer\Packages\

#>


<# Demo Setup replaces the values in the variables for your demo environment

#Virtual Machine Windows Server 2016
$ISO = "e:"
$WS2016PublicIP = "13.69.253.164"
$WS2016Name = "WS2016"
$WS2016AdminUserName = "itpro"
$MediaPath = "C:\NanoServer\"

#Virtual Machine  Nano Server
$NanoServerPublicIP = "52.169.185.207"
$NanoServerName = "NanoServer"
$NanoServerAdminUserName = "itpro"

#>

# ---Importing Server's Nano generator --

#Windows Server 2015 TP5 [https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-technical-preview]
mkdir c:\temp
Invoke-WebRequest http://care.dlservice.microsoft.com/dl/download/8/9/2/89284B3B-BA51-49C8-90F8-59C0A58D0E70/14300.1000.160324-1723.RS1_RELEASE_SVC_SERVER_OEMRET_X64FRE_EN-US.ISO -OutFile c:\temp\WS2016TP5.iso
Mount-DiskImage –ImagePath c:\temp\WS2016TP5.iso
# Get-DiskImage –ImagePath c:\temp\WS2016TP5.iso
#Dismount-DiskImage c:\temp\WS2016TP5.iso

#Windows Server 2015 RTM (RTM Version is not available in Azure only TP5) [https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-technical-preview]
mkdir c:\temp
Invoke-WebRequest http://xxxx.ISO -OutFile c:\temp\WS2016RTM.iso
Mount-DiskImage –ImagePath c:\temp\WS2016RTM.iso
#Dismount-DiskImage –ImagePath c:\temp\WS2016RTM.iso

# Verify  the dvd/iso
$ISO = "e:"
dir $ISO\NanoServer


# --- For use the local disk Copy the folder NanoServer + Source to root C:\NanoServer
$ISO = "e:"
$MediaPath = "C:\NanoServer\"
Copy-Item -Path $ISO\NanoServer\ -Destination $MediaPath\NanoServer -Recurse
Copy-Item -Path $ISO\Sources\ -Destination $MediaPath\Sources -Recurse
dir $MediaPath
Import-Module $MediaPath\NanoServer\NanoServerImageGenerator -Verbose


#--- For use the dvd/iso
$ISO ="e:"
Import-Module $ISO\NanoServer\NanoServerImageGenerator -Verbose

# --- Powershell cmdlets for Nano Server ---
# Work with Windows 10 for create c# projects
Install-Module Microsoft.PowerShell.NanoServer.SDK

# --- Install Powershell roles and features for Nano Server ---
Install-PackageProvider NanoServerPackage
Import-PackageProvider NanoServerPackage


<# --- Create a new VHD --- 
Command: New-NanoServerImage -Edition Standard -DeploymentType Host 
                             -MediaPath [Location ISO] - is the root of the DVD/ISO or folder containing Windows Server 2016 
                             -BasePath  [Location VHD created] - will contain a copy of the Nano Server binaries, so you can use New-NanoServerImage -BasePath without having to specify -MediaPath in future runs. 
                             -TargetPath [Filename vhd or Localtion + Filename vhd] - will contain the resulting .wim file containing the roles & features you selected. Make sure to specify the .wim extension. 
                             -ComputerName [Nano Server name] 
#>

#Create demos directory
mkdir c:\NanoServerDemos

#Demo: Nano server + Guest Package using MediaPath (Local Disk)
$MediaPath = "C:\NanoServer\"
$BasePath = "c:\NanoServerDemos\"
$TargetPath ="NanoDemoEmpty.vhd"
$NanoServerName = "NanoServer"
New-NanoServerImage -Edition Standard -DeploymentType Guest -MediaPath $MediaPath -BasePath $BasePath -TargetPath $TargetPath -ComputerName $NanoServerName

#Demo: Nano server + + Guest Package and OEM Drivers Package without BasePath (Local Disk)
$MediaPath = "C:\NanoServer\"
$TargetPath ="C:\NanoServerDemos\NanoDemoOEM.vhd"
$NanoServerName = "NanoDrivers"
$Package = "Microsoft-NanoServer-OEM-Drivers-Package"
New-NanoServerImage -Edition Standard -DeploymentType Guest -MediaPath $MediaPath  -TargetPath $TargetPath  -ComputerName $NanoServerName -Package $Package

#Demo: Nano Server + Guest Package and IIS without BasePath (Local Disk)
$MediaPath = "C:\NanoServer\"
$TargetPath ="C:\NanoServerDemos\NanoDemoISS.vhd"
$NanoServerName = "NanoISS"
$Package = "Microsoft-NanoServer-IIS-Package"
New-NanoServerImage -Edition Standard -DeploymentType Guest -MediaPath $MediaPath -TargetPath $TargetPath -ComputerName $NanoServerName -Packages $Package 

#Demo: Set Administrator password (DVD/ISO)
#Don't forget to change the import-module NanoServerImageGenerator
$ISO ="e:"
$MediaPath = $ISO
$BasePath = "c:\NanoServerDemos\"
$TargetPath ="NanoServerPWS.vhd"
$NanoServerName = "NanoServerPWS"
$Package = "Microsoft-NanoServer-OEM-Drivers-Package"
New-NanoServerImage –MediaPath $ISO
    -MediaPath $MediaPath
    -BasePath $BasePath
    -TargetPath $TargetPath
    –ComputerName $NanoServerName
    -Guestdrivers
    -Ipv4Address 192.168.0.41
    -Ipv4SubnetMask 255.255.255.0
    -Ipv4Gateway 192.168.0.1
    -Package $Package
    -Language en-us
    -AdministratorPassword (ConvertTo-SecureString -String ‘P@ssw0rd’ -AsPlainText -Force)

	
#Demo: Cmdlet to create new Nano Server using GUI (Windows Server 2016 TP4 & TP5)
New-NanoServerImage
	

#Demo: Cmdlet to Edit Nano Server based install to add new roles & features 
Edit-NanoServerImage

# --- Network ---
# -InterfaceNameOrIndex Ethernet -Ipv4Address [IP Address] -Ipv4SubnetMask [Subnet] -Ipv4Gateway [IP Address Gateway] -Ipv4Dns [IP Address DNS]


# --- Maximum size --- 
# -MaxSize [Quantity]
$ISO ="e:"
$MediaPath = $ISO
New-NanoServerImage -DeploymentType Host -Edition Standard -MediaPath $MediaPath -BasePath c:\temp\ -TargetPath NanoServer.vhd -MaxSize 20GB


# --- Nano Server join AD
# -DomainName [domain]
$ISO ="e:"
$MediaPath = $ISO
$NanoServerName "NS007-AD"
New-NanoServerImage -Edition Standard -DeploymentType Host -MediaPath $MediaPath -BasePath c:\temp\ -TargetPath NanoServerAD.vhdx -ComputerName $NanoServerName -DomainName msft.local

<# --- Remote access using WinRM ---

Before connect to Nano Server you need to open firewall ports On Azure is 'Network security group'.~
https://msdn.microsoft.com/en-us/library/aa384372(v=vs.85).aspx
WINRM 2.0 : 5985 [TCP] warning deprecated 
WINRM quickconfig : 5986 [TCP]


$ip = "[IP Address Nano Server]"
Set-Item WSMan:\localhost\Client\TrustedHosts $ip
Enter-PSSession -ComputerName $ip -Credential $ip\Administrator
#>


# Azure
$NanoServerName = "NanoServer"
$NanoServerAdminUserName = "itpro"
Set-Item WSMan:\localhost\Client\TrustedHosts NanoServer
Enter-PSSession -ComputerName $NanoServerName -Credential $NanoServerName\$NanoServerAdminUserName

# On-premise
$NanoServerVIP = "52.169.185.207"
$NanoServerAdminUserName = "itpro"
Set-Item WSMan:\localhost\Client\TrustedHosts $NanoServerVIP
Enter-PSSession -ComputerName $NanoServerVIP -Credential $NanoServerName\$NanoServerAdminUserName

# --- WinRM + DNS + AD --- 

# --- Add the local DNS server Nano Server registration --- 
Add-DnsServerResourceRecordA -ComputerName WS2012R2 -Name NanoServer -ZoneName "Mcsesolution.local" -IPv4Address "192.168.0.41" -PassThru

# --- Create a remote session --- 
#Add to the list of trusted Hosts that can be remotely managed.
Set-Item -Path WSMan:\localhost\client\TrustedHosts -Value NanoServer -Force

#--- Create and perform a remote session ---

# create a new a remote session 
$NanoServerName = "NanoServer"
$NanoServerAdminUserName = "itpro"
$s = New-PSSession -ComputerName $NanoServerName -Credential $NanoServerName\$NanoServerAdminUserName

# Perform a remote session 
Enter-PSSession -Session $s
Exit-PSSession


# --- Add DNS (WinRM) ---
$placaderede = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
$placaderede | Set-DnsClientServerAddress -ServerAddresses "192.168.0.200"

# --- COPY FEATURES With The PS (WinRM) ---
#Copiar Item
$NanoServerName ="NanoServer" 
Copy-Item -ToSession $s -Path C:\WebServer\*.* -Destination c:\inetpub\wwwroot
Copy-Item -ToSession $s -Path c:\$NanoServerName\[odjblob] -Destination c:\temp

# --- Add Nano server in the domain (WinRM) ---
djoin.exe /provision /domain mcsesolution.local /machine NanoServer /savefile .\odjblob
djoin /requestodj /loadfile c:\Temp\odjblob /windowspath c:\windows /localos
shutdown /r /t 3
Exit-PSSession


#--- Updates ---
Get-WindowsPackage -Online 
Get-WindowsPackage -Online | Where-Object {$_.PackageName -like "*Fix*"}
Add-WindowsPackage

#--- Packages ---

<# 
Packages with several culture (Powershell cmdlet)
First you need install and import NanoServerPackage 

Install-PackageProvider NanoServerPackage
Import-PackageProvider NanoServerPackage

#>
Find-NanoServerPackage


#Import-PackageProvider 


#Get-NanoServerPackages 


#Source 
Get-PackageSource
Get-PackageProvider
Get-PackageProvider -ListAvailable


#Install Containers Package
Install-PackageProvider Microsoft-NanoServer-Containers-Package

# Nano Server TP5 NuGet has Version installed 2.8.5.205
Install-PackageProvider -Name NuGet -RequiredVersion 2.8.5.201
Import-PackageProvider -Name  NuGet –RequiredVersion 2.8.5.201

#Find and Install
Find-Package –AllVersions 
Find-Package –AllVersions -Name *IIS*
Install-Package -Name Microsoft-NanoServer-IIS-Package 

# --- Command line history --- 
Get-History

<#
Warning: Not all PowerShell cmdlet/commands work with Nano Server.
#>

<# SysInternals Nano Server 

First we need to download and install SysInternals in Nano Server

Who to install SysInternals tools
Info: There is no Invoke-WebRequest, System.Net.WebClient, Start-BitsTransfer, bitsadmin.
TP4/TP5/RTM: Not all cmdlets are available yet

Trick: https://docs.asp.net/en/latest/tutorials/nano-server.html#installing-the-asp-net-core-module-ancm

Or you can use 'Copy-Item' lets you copy files or folders from one Windows PowerShell session to another.

#>

# Trick. Execute in Nano Server
$SourcePath = "https://download.sysinternals.com/files/SysinternalsSuite-Nano.zip"
$DestinationPath = "C:\SysInternals\"

$EditionId = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'EditionID').EditionId

if (($EditionId -eq "ServerStandardNano") -or
    ($EditionId -eq "ServerDataCenterNano") -or
    ($EditionId -eq "NanoServer") -or
    ($EditionId -eq "ServerTuva")) {

    $TempPath = [System.IO.Path]::GetTempFileName()
    if (($SourcePath -as [System.URI]).AbsoluteURI -ne $null)
    {
        $handler = New-Object System.Net.Http.HttpClientHandler
        $client = New-Object System.Net.Http.HttpClient($handler)
        $client.Timeout = New-Object System.TimeSpan(0, 30, 0)
        $cancelTokenSource = [System.Threading.CancellationTokenSource]::new()
        $responseMsg = $client.GetAsync([System.Uri]::new($SourcePath), $cancelTokenSource.Token)
        $responseMsg.Wait()
        if (!$responseMsg.IsCanceled)
        {
            $response = $responseMsg.Result
            if ($response.IsSuccessStatusCode)
            {
                $downloadedFileStream = [System.IO.FileStream]::new($TempPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
                $copyStreamOp = $response.Content.CopyToAsync($downloadedFileStream)
                $copyStreamOp.Wait()
                $downloadedFileStream.Close()
                if ($copyStreamOp.Exception -ne $null)
                {
                    throw $copyStreamOp.Exception
                }
            }
        }
    }
    else
    {
        throw "Cannot copy from $SourcePath"
    }
    [System.IO.Compression.ZipFile]::ExtractToDirectory($TempPath, $DestinationPath)
    Remove-Item $TempPath
}


#Copy-Item (don't use both). Execute On-premise/Azure VM
$NanoServerName = "NanoServer"
$NanoServerAdminUserName = "itpro"
$UriSysinternalNS = 'https://download.sysinternals.com/files/SysinternalsSuite-Nano.zip'
$session = New-PSSession -ComputerName $NanoServerName -Credential $NanoServerName\$NanoServerAdminUserName 
Invoke-WebRequest -Uri $UriSysinternalNS -OutFile c:\SysinternalsSuite-Nano.zip
Expand-Archive -Path c:\SysinternalsSuite-Nano.zip -DestinationPath C:\SysinternalsSuite-Nano
Get-ChildItem -Path C:\SysinternalsSuite-Nano | Copy-Item -ToSession $session -Destination C:\Sysinternals
Remove-Item -Path c:\SysinternalsSuite-Nano.zip
Remove-Item -Path c:\SysinternalsSuite-Nano -Recurse



# --- conection with SysInternals tools ---
$NanoServerName = "NanoServer"
$NanoServerAdminUserName = "itpro"
$NS1 = new-pssession -ComputerName $NanoServerName -Credential $NanoServerName\$NanoServerAdminUserName
Enter-PSSession $NS1 


<# --- Demos inside Nano Server ---
Sysinternals Suite Nano must be installed at the Nano Server
#> 
dir c:\Sysinternals

#Enter directory
cd  c:\Sysinternals

#Tool: PsInfor
.\PsInfo64.exe -accepteula

#Tool: du64
.\du64 -accepteula


#Tool: psping64
.\psping64.exe -accepteula 
.\psping64.exe -4 -f -s NanoServer x1:5000

#Tool: handle64
.\handle64.exe -accepteula -s

#Tool: Listdlls64
.\Listdlls64.exe -accepteula


#Tool: PsExec64.exe (execute On-premise/Azure VM)
$NanoServerName ="NanoServer"
$NanoServerAdminUserName = "itpro"
.\PsExec64.exe -accepteula
.\PsExec64.exe \\NanoServerps -u $NanoServerName\$NanoServerAdminUserName  hostname
echo "Hello SQLSartuday Porto" 

#Tool: logonsessions
.\logonsessions64.exe -accepteula

#Tool: PsLoggedon
.\PsLoggedon64.exe -accepteula

# --- Database ---
<#MySQL 
https://blogs.technet.microsoft.com/nanoserver/2016/06/13/mysql-on-nano-server
http://social.technet.microsoft.com/wiki/contents/articles/34655.nano-server-deploying-mysql-database-server.aspx
#>
