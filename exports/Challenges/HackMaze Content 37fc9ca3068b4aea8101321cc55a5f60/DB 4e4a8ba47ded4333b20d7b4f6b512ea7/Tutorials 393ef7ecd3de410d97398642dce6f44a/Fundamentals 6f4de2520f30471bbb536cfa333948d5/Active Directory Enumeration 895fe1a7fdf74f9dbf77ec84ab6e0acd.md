# Active Directory Enumeration

---

# Identifying Hosts

## Capturing Traffic (Stealthy)

- A very stealthy way to identify hosts is to use wireshark or tcpdump to listen to any ARP requests and replies

```bash
sudo tcpdump -i ens224
```

```bash
sudo responder -I ens224 -A
```

## ping sweep

```bash
fping -asgq $network_ip
```

---

# Enumerating Domain

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

---

# Enumerating Users

## **Kerbrute - Internal AD Username Enumeration**

[Kerbrute](https://github.com/ropnop/kerbrute) can be a stealthier option for domain account enumeration. It takes advantage of the fact that Kerberos pre-authentication failures often will not trigger logs or alerts. We will use Kerbrute in conjunction with the `jsmith.txt` or `jsmith2.txt` user lists from [Insidetrust](https://github.com/insidetrust/statistically-likely-usernames). This repository contains many different user lists that can be extremely useful when attempting to enumerate users when starting from an unauthenticated perspective. We can point Kerbrute at the DC we found earlier and feed it a wordlist. The tool is quick, and we will be provided with results letting us know if the accounts found are valid or not, which is a great starting point for launching attacks such as password spraying, which we will cover in-depth later in this module.

To get started with Kerbrute, we can download [precompiled binaries](https://github.com/ropnop/kerbrute/releases/latest) for the tool for testing from Linux, Windows, and Mac, or we can compile it ourselves. This is generally the best practice for any tool we introduce into a client environment. 

```bash
kerbrute userenum -d INLANEFREIGHT.LOCAL --dc $dc_ip $usernames_wordlist -o valid_ad_users
```

## `net` command (domain joined)

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

---

# Enumerating Groups & members

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

---

# LLMNR & NBT-NS **Poisoning**

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

```powershell
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

---

# Enumerating Logged in Users

- we can  use **`NetWkstaUserEnum` and `NetSessionEnum`**
    - `NetWkstaUserEnum` requires Administrative Permissions and returns a list of **all users**
    - `NetSessionEnum` does not require  Administrative Permissions and returns a list of current **logged in users**
- we will use PowerView to ease the process, import Powerview first
    - **`Get-NetLoggedon [-ComputerName name]`   invokes**  `NetWkstaUserEnum`
    - **`Get-NetSession [-ComputerName name]`      invokes** `NetSessionEnum`

---

# Enumerating SPNs

- **`Get-UserSPNs` (enumerate services instead of performing port scanning)**

localsystem, localservice, networkservice

---

# **Tools of the Trade**

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