# Windows Security Basics

- Prerequisites
    
    [Windows Basics](https://www.notion.so/Windows-Basics-92e2d4a4698848a88b84cc737a4ae237?pvs=21)
    
- Table Of Contents

---

## Windows Securable Objects

- Files
- Folders
- Services
- Registry Keys
- Named Pipes

---

# Security IDentifier ( **SID** )

Each of the security principals on the system has a unique security identifier (SID). The system automatically generates SIDs. This means that even if, for example, we have two identical users on the system, Windows can distinguish the two and their rights based on their SIDs. SIDs are string values with different lengths, which are stored in the security database. These SIDs are added to the user's access token to identify all actions that the user is authorized to take.

A SID consists of the Identifier Authority and the Relative ID (RID). In an Active Directory (AD) domain environment, the SID also includes the domain SID.

![Untitled](../Network%20Penetration%20Testing%207bc0c24ad8fe484d8df2696d10985222/Windows%20Security%20Basics%20a3be49509de34546b4bd04074f780f95/Untitled.png)

![Untitled](../Network%20Penetration%20Testing%207bc0c24ad8fe484d8df2696d10985222/Windows%20Security%20Basics%20a3be49509de34546b4bd04074f780f95/Untitled%201.png)

The SID is broken down into this pattern.

```
(SID)-(revision level)-(identifier-authority)-(subauthority1)-(subauthority2)-(etc)
```

Let's break down the SID piece by piece.

`S-1-5-21-674899381-4069889467-2080702030-1002`

| Number | Meaning | Description |
| --- | --- | --- |
| S | SID | Identifies the string as a SID. |
| 1 | Revision Level | To date, this has never changed and has always been 1. |
| 5 | Identifier-authority | A 48-bit string that identifies the authority (the computer or network) that created the SID. |
| 21 | Subauthority1 | This is a variable number that identifies the user's relation or group described by the SID to the authority that created it. It tells us in what order this authority created the user's account. |
| 674899381-4069889467-2080702030 | Subauthority2 | Tells us which computer (or domain) created the number |
| 1002 | Subauthority3 | The RID that distinguishes one account from another. Tells us whether this user is a normal user, a guest, an administrator, or part of some other group |

---

# ACL & ACEs

- **ACE: Access Control Entry**
- **ACL: Access Control List**

![Untitled](../Network%20Penetration%20Testing%207bc0c24ad8fe484d8df2696d10985222/Windows%20Security%20Basics%20a3be49509de34546b4bd04074f780f95/Untitled%202.png)

- ACL is a list of ACE — a list of everyone who has access to this file
- You can’t spoof the  SID because Windows use [access tokens](https://www.notion.so/Windows-Security-Basics-a3be49509de34546b4bd04074f780f95?pvs=21)
- An ACL can be one of two specific varieties: a Discretionary Access Control List (DACL) or a System Access Control List (SACL). **The DACL is primarily used for controlling access to an object, whereas a SACL is primarily used for logging access attempts to an object**.

### → **Discretionary Access Control List (DACL)**

DACLs define which security principles are granted or denied access to an object; it contain a list of ACEs. When a process tries to access a securable object, the system checks the ACEs in the object's DACL to determine whether or not to grant access. **If an object does NOT have a DACL, then the system will grant full access to everyone**, **but if the DACL has no ACE entries, the system will deny all access attempts**. ACEs in the DACL are checked in sequence until a match is found that allows the requested rights or until access is denied.

### → **System Access Control Lists (SACL)**

Allows for administrators to log access attempts that are made to secured objects. ACEs specify the types of access attempts that cause the system to generate a record in the security event log.

---

# **Windows Authentication Process**

The [Windows client authentication process](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication)
 can oftentimes be more complicated than with Linux systems and consists of many different modules that perform the entire logon, retrieval, and verification processes. In addition, there are many different and complex authentication procedures on the Windows system, such as Kerberos authentication. The [Local Security Authority](https://ldapwiki.com/wiki/Local%20Security%20Authority) (`LSA`) is a protected subsystem that authenticates users and logs them into the local computer. In addition, the LSA maintains information about all aspects of local security on a computer. It also provides various services for translating between names and security IDs (`SIDs`).

The security subsystem keeps track of the security policies and accounts that reside on a computer system. In the case of a Domain Controller, these policies and accounts apply to the domain where the Domain Controller is located. These policies and accounts are stored in Active Directory. In addition, the LSA subsystem provides services for checking access to objects, checking user permissions, and generating monitoring messages.

## ⇒ **Windows Authentication Process Diagram**

![Untitled](Windows%20Security%20Basics%20eff40492461c4c44ad842d8af7cbe503/Untitled.png)

- LSA (Local Security Authority) and LSASS (Local Security Authority Subsystem Service) are not the same thing, although they are related.
    - LSA is a security component in Windows systems that is responsible for enforcing security policies and authentication. It is essentially a database of security-related information that is used by various components of the operating system, including LSASS.
    - LSASS, on the other hand, is a system process that provides various security-related functions, including handling user logins and authentication, enforcing security policies, and managing security tokens. LSASS uses the information stored in the LSA database to perform these functions.
- In summary, LSA is a database of security-related information, while LSASS is a system process that uses that information to perform various security-related functions.
- The key difference between LSA and LSASS is that LSA is a database that contains security-related information, while LSASS is a system process that provides various security-related functions by using that information.

Local interactive logon is performed by the interaction between the logon process ([WinLogon](https://www.microsoftpressstore.com/articles/article.aspx?p=2228450&seqNum=8)), the logon user interface process (`LogonUI`), the `credential providers`, `LSASS`, one or more `authentication packages`, and `SAM` or `Active Directory`. Authentication packages, in this case, are the Dynamic-Link Libraries (`DLLs`) that perform authentication checks. For example, for non-domain joined and interactive logins, the authentication package `Msv1_0.dll` is used.

`Winlogon` is a trusted process responsible for managing security-related user interactions. These include:

- Launching LogonUI to enter passwords at login
- Changing passwords
- Locking and unlocking the workstation

It relies on credential providers installed on the system to obtain a user's account name or password. Credential providers are `COM` objects that are located in DLLs.

Winlogon is the only process that intercepts login requests from the keyboard sent via an RPC message from Win32k.sys. Winlogon immediately launches the LogonUI application at logon to display the user interface for logon. After Winlogon obtains a user name and password from the credential providers, it calls LSASS to authenticate the user attempting to log in.

### → **LSASS**

- Upon initial logon, LSASS will:
    - Cache credentials locally in memory
    - Create [access tokens](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
    - Enforce security policies
    - Write to Windows [security log](https://docs.microsoft.com/en-us/windows/win32/eventlog/event-logging-security)

[Local Security Authority Subsystem Service](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service) (`LSASS`) is a collection of many modules and has access to all authentication processes that can be found in `%SystemRoot%\System32\Lsass.exe`. This service is responsible for the local system security policy, user authentication, and sending security audit logs to the `Event log`. In other words, it is the vault for Windows-based operating systems, and we can find a more detailed illustration of the LSASS architecture [here](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc961760(v=technet.10)?redirectedfrom=MSDN).

| Authentication Packages | Description |
| --- | --- |
| Lsasrv.dll | The LSA Server service both enforces security policies and acts as the security package manager for the LSA. The LSA contains the Negotiate function, which selects either the NTLM or Kerberos protocol after determining which protocol is to be successful. |
| Msv1_0.dll | Authentication package for local machine logons that don't require custom authentication. |
| Samsrv.dll | The Security Accounts Manager (SAM) stores local security accounts, enforces locally stored policies, and supports APIs. |
| Kerberos.dll | Security package loaded by the LSA for Kerberos-based authentication on a machine. |
| Netlogon.dll | Network-based logon service. |
| Ntdsa.dll | This library is used to create new records and folders in the Windows registry. |

Source: [Microsoft Docs](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication).

Each interactive logon session creates a separate instance of the Winlogon service. The [Graphical Identification and Authentication](https://docs.microsoft.com/en-us/windows/win32/secauthn/gina) (`GINA`) architecture is loaded into the process area used by Winlogon, receives and processes the credentials, and invokes the authentication interfaces via the [LSALogonUser](https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsalogonuser) function.

### → **SAM Database**

The [Security Account Manager](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc756748(v=ws.10)?redirectedfrom=MSDN) (`SAM`) is a database file in Windows operating system that stores users' passwords. It can be used to authenticate local and remote users. SAM uses cryptographic measures to prevent unauthenticated users from accessing the system. User passwords are stored in a hash format in a registry structure as either an `LM` hash or an `NTLM` hash. This file is located in `%SystemRoot%/system32/config/SAM` and is mounted on HKLM/SAM. SYSTEM level permissions are required to view it.

SAM grants rights to a network to execute specific processes. The access rights themselves are managed by Access Control Entries (ACE) in Access Control Lists (ACL)

Windows systems can be assigned to either a workgroup or domain during setup. If the system has been assigned to a workgroup, it handles the SAM database locally and stores all existing users locally in this database. However, if the system has been joined to a domain, the Domain Controller (`DC`) must validate the credentials from the Active Directory database (`ntds.dit`), which is stored in `%SystemRoot%\ntds.dit`.

Microsoft introduced a security feature in Windows NT 4.0 to help improve the security of the SAM database against offline software cracking. This is the `SYSKEY` (`syskey.exe`) feature, which, when enabled, partially encrypts the hard disk copy of the SAM file so that the password hash values for all local accounts stored in the SAM are encrypted with a key.

### → **Credential Manager**

![https://academy.hackthebox.com/storage/modules/147/authn_credman_credprov.png](https://academy.hackthebox.com/storage/modules/147/authn_credman_credprov.png)

Source: [Microsoft Docs](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication).

Credential Manager is a feature built-in to all Windows operating systems that allows users to save the credentials they use to access various network resources and websites. Saved credentials are stored based on user profiles in each user's `Credential Locker`. Credentials are encrypted and stored at the following location:

Credential Manager

```
PS C:\Users\[Username]\AppData\Local\Microsoft\[Vault/Credentials]
```

There are various methods to decrypt credentials saved using Credential Manager. We will practice hands-on with some of these methods in this module.

### → **NTDS**

The NTDS.DIT file can be considered the heart of Active Directory. It is stored on a Domain Controller at `%systemroot%\NTDS` means`C:\Windows\NTDS\` on the domain controllers in a [forest](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/using-the-organizational-domain-forest-model). The `.dit` stands for [directory information tree](https://docs.oracle.com/cd/E19901-01/817-7607/dit.html).
 is enabled, then the NTDS.DIT will also store the clear-text passwords for all users created or who changed their password after this policy was set. While rare, some organizations may enable this setting if they use applications or protocols that need to use a user's existing password (and not Kerberos) for authentication.

It is very common to come across network environments where Windows systems are joined to a Windows domain. This is common because it makes it easier for admins to manage all the systems owned by their respective organizations (centralized management). In these cases, the Windows systems will send all login requests to Domain Controllers that belong to the same Active Directory forest. Each Domain Controller hosts a file called `NTDS.dit` that is kept synchronized across all Domain Controllers with the exception of [Read-Only Domain Controllers](https://docs.microsoft.com/en-us/windows/win32/ad/rodc-and-active-directory-schema). NTDS.dit is a database file that stores the data in Active Directory, including but not limited to:

- User accounts (username & password hash)
- Group accounts
- Computer accounts
- Group policy objects

We will practice methods that allow us to extract credentials from the NTDS.dit file later in this module.

Now that we have gone through a primer on credential storage concepts, let's study the various attacks we can perform to extract credentials to further our access during assessments.

---

# LM (Lan Manager)

`LAN Manager` (LM or LANMAN) hashes are the oldest password storage mechanism used by the Windows operating system. LM debuted in 1987 on the OS/2 operating system. If in use, they are stored in the SAM database on a Windows host and the NTDS.DIT database on a Domain Controller. Due to significant security weaknesses in the hashing algorithm used for LM hashes, it has been turned off by default since Windows Vista/Server 2008. However, it is still common to encounter, especially in large environments where older systems are still used. Passwords using LM are limited to a maximum of `14` characters. Passwords are not case sensitive and are converted to uppercase before generating the hashed value, limiting the keyspace to a total of 69 characters making it relatively easy to crack these hashes using a tool such as Hashcat.

Before hashing, a 14 character password is first split into two seven-character chunks. If the password is less than fourteen characters, it will be padded with NULL characters to reach the correct value. Two DES keys are created from each chunk. These chunks are then encrypted using the string `KGS!@#$%`, creating two 8-byte ciphertext values. These two values are then concatenated together, resulting in an LM hash. This hashing algorithm means that an attacker only needs to brute force seven characters twice instead of the entire fourteen characters, making it fast to crack LM hashes on a system with one or more GPUs. If a password is seven characters or less, the second half of the LM hash will always be the same value and could even be determined visually without even needed tools such as Hashcat. The use of LM hashes can be disallowed using [Group Policy](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-do-not-store-lan-manager-hash-value-on-next-password-change). An LM hash takes the form of `299bd128c1101fd6`.

---

# NTLM hash

NTLM is a single sign-on (SSO) solution that uses a challenge-response protocol to verify the user's identity without having them provide a password. With NTLM, passwords stored on the server and domain controller are not "salted," which means that an adversary with a password hash can authenticate a session without knowing the original password. We call this a `Pass the Hash (PtH) Attack`. they are considerably stronger than LM hashes (supporting the entire Unicode character set of 65,536 characters), they can still be brute-forced offline relatively quickly using a tool such as Hashcat. GPU attacks have shown that the entire NTLM 8 character keyspace can be brute-forced in under `3 hours`. Longer NTLM hashes can be more challenging to crack depending on the password chosen, and even long passwords (15+ characters) can be cracked using an offline dictionary attack combined with rules. NTLM is also vulnerable to the pass-the-hash attack, which means an attacker can use just the NTLM hash (after obtaining via another successful attack) to authenticate to target systems where the user is a local admin without needing to know the clear-text value of the password.

An NT hash takes the form of `b4b9b02e6f09a9bd760f388b67351e2b`, which is the second half of the full NTLM hash. An NTLM hash looks like this:

```
Rachel:500:aad3c435b514a4eeaad3b935b51304fe:e46b9e548fa0d122de7f59fb6d48eaa2:::
```

Looking at the hash above, we can break the NTLM hash down into its individual parts:

- `Rachel` is the username
- `500` is the Relative Identifier (RID). 500 is the known RID for the `administrator` account
- `aad3c435b514a4eeaad3b935b51304fe` is the LM hash and, if LM hashes are disabled on the system, can not be used for anything
- `e46b9e548fa0d122de7f59fb6d48eaa2` is the NT hash. This hash can either be cracked offline to reveal the clear-text value (depending on the length/strength of the password) or used for a pass-the-hash attack.

---

# UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is a security feature in Windows to prevent malware from running or manipulating processes that could damage the computer or its contents. There is the Admin Approval Mode in UAC, which is designed to prevent unwanted software from being installed without the administrator's knowledge or to prevent system-wide changes from being made. Surely you have already seen the consent prompt if you have installed a specific software, and your system has asked for confirmation if you want to have it installed. Since the installation requires administrator rights, a window pops up, asking you if you want to confirm the installation. With a standard user who has no rights for the installation, execution will be denied, or you will be asked for the administrator password. This consent prompt interrupts the execution of scripts or binaries that malware or attackers try to execute until the user enters the password or confirms execution. To understand how UAC works, we need to know how it is structured and how it works, and what triggers the consent prompt. The following diagram, adapted from the source [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), illustrates how UAC works.

![Untitled](Windows%20Security%20Basics%20eff40492461c4c44ad842d8af7cbe503/Untitled%201.png)

---

# Access Token

- Windows uses tokens to ensure that accounts have the right privileges to carry out particular actions. Account tokens are assigned to an account when users log in or are authenticated. This is usually done by LSASS.exe(**Local Security Authority Subsystem Service**).
- contains the security context of that entity (**the entity could be a user, group, or process**) such as:
    - user SIDs (Security IDentifier)
    - group SIDs
    - privileges
- There are two types of access tokens:
    - **primary access tokens**: those associated with a user account that is generated on log-on
    - **impersonation tokens**: these allow a particular process(or thread in a process) to gain access to resources using the token of another (user/client) process
- For an impersonation token, there are different levels:
    - **`SecurityAnonymous`**: current user/client cannot impersonate another user/client
    - **`SecurityIdentification`**: current user/client can get the identity and privileges of a client, but cannot impersonate the client
    - **`SecurityImpersonation`**: current user/client can impersonate the client's security context on the local system
    - **`SecurityDelegation`**: current user/client can impersonate the client's security context on a remote system
- The privileges of an account(which are either given to the account when created or inherited from a group) allow a user to carry out particular actions. Here are the most commonly abused privileges:
    - **`SeImpersonatePrivilege`**
    - **`SeAssignPrimaryPrivilege`**
    - **`SeTcbPrivilege`**
    - **`SeBackupPrivilege`**
    - **`SeRestorePrivilege`**
    - **`SeCreateTokenPrivilege`**
    - **`SeLoadDriverPrivilege`**
    - **`SeTakeOwnershipPrivilege`**
    - **`SeDebugPrivilege`**
- Tied to process or thread

![Untitled](Windows%20Security%20Basics%20eff40492461c4c44ad842d8af7cbe503/Untitled%202.png)

- it’s not a simple process to spoof an access token, because **Access Token uses technologies like Digital Signature to ensure that it’s not modified**
- any change in user groups will recreate the access token so the user should log off and log in again
- Even though you have a higher privileged token you may not have the permissions of a privileged user (this is due to the way Windows handles permissions - it uses the Primary Token of the process and not the impersonated token to determine what the process can or cannot do). Ensure that you migrate to a process with correct permissions. The safest process to pick is the **`services.exe`** process. First, use the **`ps`** command to view processes and find the PID of the `services.exe` process. Migrate to this process using the command **`migrate PID-OF-PROCESS`**

---

- right-click + properties + security to show the ACL
    
    ![Untitled](Windows%20Security%20Basics%20eff40492461c4c44ad842d8af7cbe503/Untitled%203.png)
    
    ![Untitled](Windows%20Security%20Basics%20eff40492461c4c44ad842d8af7cbe503/Untitled%204.png)
    
    - There are special identities in the ACL like **SYSTEM** and **Authenticated Users**, they are special Local users that are the same on every installation of windows
    - the computer stores the SID, not the name, this computer has no access to the domain controller (offline) so you can notice the last 2 are SID if it’s connected to the network these SIDs will be names
        - so you can rename a user or a group without affecting the security
    
    ![Untitled](Windows%20Security%20Basics%20eff40492461c4c44ad842d8af7cbe503/Untitled%205.png)
    
    - the last two entries in the local group administrators and the local group Users

---

![Untitled](Windows%20Security%20Basics%20eff40492461c4c44ad842d8af7cbe503/Untitled%206.png)

![Untitled](Windows%20Security%20Basics%20eff40492461c4c44ad842d8af7cbe503/Untitled%207.png)

![Untitled](Windows%20Security%20Basics%20eff40492461c4c44ad842d8af7cbe503/Untitled%208.png)

![Untitled](Windows%20Security%20Basics%20eff40492461c4c44ad842d8af7cbe503/Untitled%209.png)

![Untitled](Windows%20Security%20Basics%20eff40492461c4c44ad842d8af7cbe503/Untitled%2010.png)

---

# Windows Integrity Levels

![Untitled](Windows%20Security%20Basics%20eff40492461c4c44ad842d8af7cbe503/Untitled%2011.png)

![Untitled](Windows%20Security%20Basics%20eff40492461c4c44ad842d8af7cbe503/Untitled%2012.png)

![Untitled](Windows%20Security%20Basics%20eff40492461c4c44ad842d8af7cbe503/Untitled%2013.png)

---

![Untitled](Windows%20Security%20Basics%20eff40492461c4c44ad842d8af7cbe503/Untitled%2014.png)

# Windows Users

Windows systems mainly have two kinds of users. Depending on their access levels, we can categorize a user in one of the following groups:

[User Types ](Windows%20Security%20Basics%20eff40492461c4c44ad842d8af7cbe503/User%20Types%200457b06891a24594aa46fc873a255e8f.csv)

[Build-in Users ](Windows%20Security%20Basics%20eff40492461c4c44ad842d8af7cbe503/Build-in%20Users%20bcec1a71f2b64a04b1a038aadeecbdc9.csv)

- **The account NT AUTHORITY\System is a Local System account.. It is a powerful account that has unrestricted access to all local system resources**

---

# Service Permissions

The first step in realizing the importance of service permissions is simply understanding that they exist and being mindful of them. On server operating systems, critical network services like DHCP and Active Directory Domain Services commonly get installed using the account assigned to the admin performing the install. Part of the install process includes assigning a specific service to run using the credentials and privileges of a designated user, which by default is set within the currently logged-on user context.

We should also be mindful of service permissions and the permissions of the directories they execute from because it is possible to replace the path to an executable with a malicious DLL or executable file.

Most services run with LocalSystem privileges by default which is the highest level of access allowed on an individual Windows OS. Not all applications need Local System account-level permissions, so it is beneficial to perform research on a case-by-case basis when considering installing new applications in a Windows environment. It is a good practice to identify applications that can run with the least privileges possible to align with the principle of least privilege. [Here is one breakdown of the principle of least privilege](https://www.cloudflare.com/learning/access-management/principle-of-least-privilege/)

Notable built-in service accounts in Windows:

- **`LocalService`**
- **`NetworkService`**
- **`LocalSystem`**

## ⇒ Browsing Services

### →Services app (GUI)

![Untitled](Windows%20Security%20Basics%20eff40492461c4c44ad842d8af7cbe503/Untitled%2015.png)

![Untitled](Windows%20Security%20Basics%20eff40492461c4c44ad842d8af7cbe503/Untitled%2016.png)

### → `sc`: Service Control

- enumerate all active services

```powershell
sc query 
```

```powershell
sc qc $ServiceName
```

If we wanted to query a service on a device over the network, we could specify the hostname or IP address immediately after `sc`

```powershell
sc //$ipOrHostname qc $ServiceName
```

```powershell
sc config $ServiceName binPath=C:\$path
```

```powershell
sc stop $ServiceName
```

Another helpful way we can examine service permissions using `sc` is through the `sdshow` (Security Descriptor Show)command.

```bash
C:\WINDOWS\system32> sc sdshow $ServiceName

D:(A;;CCLCSWRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)S:(AU;FA;CCDCLCSWRPWPDTLOSDRCWDWO;;;WD)
```

At an initial glance, the output looks crazy. It almost seems that we have done something wrong in our command, but there is a meaning to this madness. Every named object in Windows is a [securable object](https://docs.microsoft.com/en-us/windows/win32/secauthz/securable-objects), and even some unnamed objects are securable. If it's securable in a Windows OS, it will have a [security descriptor](https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptors). Security descriptors identify the object’s owner and a primary group containing a `Discretionary Access Control List` (`DACL`) and a `System Access Control List` (`SACL`).

Generally, a DACL is used for controlling access to an object, and a SACL is used to account for and log access attempts. This section will examine the DACL, but the same concepts would apply to a SACL.

```
D:(A;;CCLCSWRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)
```

This amalgamation of characters crunched together and delimited by opened and closed parentheses is in a format known as the `Security Descriptor Definition Language` (`SDDL`).

We may be tempted to read from left to right because that is how the English language is typically written, but it can be much different when interacting with computers. Read the entire security descriptor for the `Windows Update` (`wuauserv`) service in this order starting with the first letter and set of parentheses:

`D: (A;;CCLCSWRPLORC;;;AU)`

1. D: - the proceeding characters are DACL permissions
2. AU: - defines the security principal Authenticated Users
3. A;; - access is allowed
4. CC - SERVICE_QUERY_CONFIG is the full name, and it is a query to the service control manager (SCM) for the service configuration
5. LC - SERVICE_QUERY_STATUS is the full name, and it is a query to the service control manager (SCM) for the current status of the service
6. SW - SERVICE_ENUMERATE_DEPENDENTS is the full name, and it will enumerate a list of dependent services
7. RP - SERVICE_START is the full name, and it will start the service
8. LO - SERVICE_INTERROGATE is the full name, and it will query the service for its current status
9. RC - READ_CONTROL is the full name, and it will query the security descriptor of the service

As we read the security descriptor, it can be easy to get lost in the seemingly random order of characters, but recall that we are essentially viewing access control entries in an access control list. Each set of 2 characters in between the semi-colons represents actions allowed to be performed by a specific user or group.

`;;CCLCSWRPLORC;;;`

After the last set of semi-colons, the characters specify the security principal (User and/or Group) that is permitted to perform those actions.

`;;;AU`

The character immediately after the opening parentheses and before the first set of semi-colons defines whether the actions are Allowed or Denied.

`A;;`

This entire security descriptor associated with the `Windows Update` (`wuauserv`) service has three sets of access control entries because there are three different security principals. Each security principal has specific permissions applied.

### → PowerShell

```powershell
Get-ACL -Path HKLM:\System\CurrentControlSet\Services\$ServiceName | Format-List
```

---

# **Windows Management Instrumentation (WMI)**

WMI is a subsystem of PowerShell that provides system administrators with powerful tools for system monitoring. The goal of WMI is to consolidate device and application management across corporate networks. WMI is a core part of the Windows operating system and has come pre-installed since Windows 2000. It is made up of the following components:

| Component Name | Description |
| --- | --- |
| WMI service | The Windows Management Instrumentation process, which runs automatically at boot and acts as an intermediary between WMI providers, the WMI repository, and managing applications. |
| Managed objects | Any logical or physical components that can be managed by WMI. |
| WMI providers | Objects that monitor events/data related to a specific object. |
| Classes | These are used by the WMI providers to pass data to the WMI service. |
| Methods | These are attached to classes and allow actions to be performed. For example, methods can be used to start/stop processes on remote machines. |
| WMI repository | A database that stores all static data related to WMI. |
| CMI Object Manager | The system that requests data from WMI providers and returns it to the application requesting it. |
| WMI API | Enables applications to access the WMI infrastructure. |
| WMI Consumer | Sends queries to objects via the CMI Object Manager. |

Some of the uses for WMI are:

- Status information for local/remote systems
- Configuring security settings on remote machines/applications
- Setting and changing user and group permissions
- Setting/modifying system properties
- Code execution
- Scheduling processes
- Setting up logging

The following command example lists information about the operating system.

```
C:\htb> wmic os list brief

BuildNumber  Organization  RegisteredUser  SerialNumber             SystemDirectory      Version
19041                      Owner           00123-00123-00123-AAOEM  C:\Windows\system32  10.0.19041

```

WMIC uses aliases and associated verbs, adverbs, and switches. The above command example uses `LIST` to show data and the adverb `BRIEF` to provide just the core set of properties. An in-depth listing of verbs, switches, and adverbs is available [here](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmic). WMI can be used with PowerShell by using the `Get-WmiObject` [module](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1). This module is used to get instances of WMI classes or information about available classes. This module can be used against local or remote machines.

Here we can get information about the operating system.

```powershell
Get-WmiObject -Class Win32_OperatingSystem | select SystemDirectory,BuildNumber,SerialNumber,Version | ft
```

We can also use the `Invoke-WmiMethod` [module](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/invoke-wmimethod?view=powershell-5.1), which is used to call the methods of WMI objects. A simple example is renaming a file. We can see that the command completed properly because the `ReturnValue` is set to 0.

```powershell
Invoke-WmiMethod -Path "CIM_DataFile.Name='C:\users\public\spns.csv'" -Name Rename -ArgumentList "C:\Users\Public\kerberoasted_users.csv"
```

This section provides a brief overview of `WMI`, `WMIC`, and combining `WMIC` and `PowerShell`. `WMI` has a wide variety of uses for both blue team and red team operators. Later sections of this course will show some ways that `WMI` can be leveraged offensively for both enumeration and lateral movement.

---

# **AppLocker**

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview) is Microsoft's application whitelisting solution and was first introduced in Windows 7. AppLocker gives system administrators control over which applications and files users can run. It gives granular control over executables, scripts, Windows installer files, DLLs, packaged apps, and packed app installers.

It allows for creating rules based on file attributes such as the publisher's name (which can be derived from the digital signature), product name, file name, and version. Rules can also be set up based on file paths and hashes. Rules can be applied to either security groups or individual users, based on the business need. AppLocker can be deployed in audit mode first to test the impact before enforcing all of the rules.

---

# Local Group Policy

Group Policy allows administrators to set, configure, and adjust a variety of settings. In a domain environment, group policies are pushed down from a Domain Controller onto all domain-joined machines that Group Policy objects (GPOs) are linked to. These settings can also be defined on individual machines using Local Group Policy.

Group Policy can be configured locally, in both domain environments and non-domain environments. Local Group Policy can be used to tweak certain graphical and network settings that are otherwise not accessible via the Control Panel. It can also be used to lock down an individual computer policy with stringent security settings, such as only allowing certain programs to be installed/run or enforcing strict user account password requirements.

We can open the Local Group Policy Editor by opening the Start menu and typing `gpedit.msc`. The editor is split into two categories under Local Computer Policy - `Computer Configuration` and `User Configuration`.

![https://academy.hackthebox.com/storage/modules/49/Local_GP.png](https://academy.hackthebox.com/storage/modules/49/Local_GP.png)

For example, we can open the Local Computer Policy to enable Credential Guard by enabling the setting `Turn On Virtualization Based Security`. Credential Guard is a feature in Windows 10 that protects against credential theft attacks by isolating the operating system's LSA process.

![https://academy.hackthebox.com/storage/modules/49/credguard.png](https://academy.hackthebox.com/storage/modules/49/credguard.png)

We can also enable fine-tuned account auditing and configure AppLocker from the Local Group Policy Editor. It is worth exploring Local Group Policy and learning about the wide variety of ways it can be used to lock down a Windows system.

- We can use the PowerShell cmdlet `Get-MpComputerStatus` to check which protection settings are enabled.

```powershell
Get-MpComputerStatus
```

---

# Next Step: Links

[*Windows Command line*](https://www.notion.so/Windows-Command-line-d66d5731cdd642c88249ba31adc99f18?pvs=21)

[Active Directory Basics](https://www.notion.so/Active-Directory-Basics-b9ab0c3f116b490ea6f935f852a9e380?pvs=21)

[Windows Privilege Escalation](https://www.notion.so/Windows-Privilege-Escalation-035f0b2030e3444e92aebd694e84d9a8?pvs=21)