# Windows Basics

- Table Of Contents

---

# File System

- Windows file system structure is:
    - Logical drives (Ex: Local Disk `C:\\`)
    - Folders (these are the folders that come by default. Ex: Documents, Downloads, Music)
    - Files
- `C:` Drive:
    
    
    | Directory | Function |
    | --- | --- |
    | Perflogs | Can hold Windows performance logs, issues and other reports regarding performance but is empty by default. |
    | Program Files | On 32-bit systems, all 16-bit and 32-bit programs are installed here. On 64-bit systems, only 64-bit programs are installed here. |
    | Program Files (x86) | 32-bit and 16-bit programs are installed here on 64-bit editions of Windows. |
    | ProgramData | This is a hidden folder that contains data that is essential for certain installed programs to run. This data is accessible by the program no matter what user is running it. |
    | Users | This folder contains user profiles for each user that logs onto the system and contains the two folders Public and Default. |
    | Default | This is the default user profile template for all created users. Whenever a new user is added to the system, their profile is based on the Default profile. |
    | Public | This folder is intended for computer users to share files and is accessible to all users by default. This folder is shared over the network by default but requires a valid network account to access. |
    | AppData | Per user application data and settings are stored in a hidden user subfolder (i.e., username\AppData). Each of these folders contains three subfolders. 
    → The Roaming folder contains machine-independent data that should follow the user's profile, such as custom dictionaries. 
    → The Local folder is specific to the computer itself and is never synchronized across the network. 
    → LocalLow is similar to the Local folder, but it has a lower data integrity level. Therefore it can be used, for example, by a web browser set to protected or safe mode. |
    | Windows | The majority of the files required for the Windows operating system are contained here. |
    | System,
    System32,
    SysWOW64 | Contains all DLLs required for the core features of Windows and the Windows API. The operating system searches these folders any time a program asks to load a DLL without specifying an absolute path. |
    | WinSxS | The Windows Component Store contains a copy of all Windows components, updates, and service packs. |

---

# Permissions

## **Share permissions**

| Permission | Description |
| --- | --- |
| Full Control | Users are permitted to perform all actions given by Change and Read permissions as well as change permissions for NTFS files and subfolders |
| Change | Users are permitted to read, edit, delete and add files and subfolders |
| Read | Users are allowed to view file & subfolder contents |

## NTFS Basic Permissions:

- Full control - allows the user/users/group/groups to set the ownership of the folder, **set permission** for others, **modify**, **read**, **write**, and **execute** files.
- Modify - allows the user/users/group/groups to **modify**, **read**, **write**, and **execute** files. **(No set permission)**
- Read & execute - allows the user/users/group/groups to **read** and **execute** files.
- List folder contents - allows the user/users/group/groups to list the contents (files, subfolders, etc) of a folder.
- Read - only allows the user/users/group/groups to read files.
- Write - allows the user/users/group/groups to write data to the specified folder (automatically set when "Modify" right is checked).

![Untitled](Windows%20Basics%2070b83146fec141688f4fe739dcf61ebd/Untitled.png)

## **NTFS special permissions**

| Permission | Description |
| --- | --- |
| Full control | Users are permitted or denied permissions to add, edit, move, delete files & folders as well as change NTFS permissions that apply to all permitted folders |
| Traverse folder / execute file | Users are permitted or denied permissions to access a subfolder within a directory structure even if the user is denied access to contents at the parent folder level. Users may also be permitted or denied permissions to execute programs |
| List folder/read data | Users are permitted or denied permissions to view files and folders contained in the parent folder. Users can also be permitted to open and view files |
| Read attributes | Users are permitted or denied permissions to view basic attributes of a file or folder. Examples of basic attributes: system, archive, read-only, and hidden |
| Read extended attributes | Users are permitted or denied permissions to view extended attributes of a file or folder. Attributes differ depending on the program |
| Create files/write data | Users are permitted or denied permissions to create files within a folder and make changes to a file |
| Create folders/append data | Users are permitted or denied permissions to create subfolders within a folder. Data can be added to files but pre-existing content cannot be overwritten |
| Write attributes | Users are permitted or denied to change file attributes. This permission does not grant access to creating files or folders |
| Write extended attributes | Users are permitted or denied permissions to change extended attributes on a file or folder. Attributes differ depending on the program |
| Delete subfolders and files | Users are permitted or denied permissions to delete subfolders and files. Parent folders will not be deleted |
| Delete | Users are permitted or denied permissions to delete parent folders, subfolders and files. |
| Read permissions | Users are permitted or denied permissions to read permissions of a folder |
| Change permissions | Users are permitted or denied permissions to change permissions of a file or folder |
| Take ownership | Users are permitted or denied permission to take ownership of a file or folder. The owner of a file has full permissions to change any permissions |

## How to Check Permissions

### `icacls`: Integrity Control Access Control List

```powershell
icacls $FileName
```

- `ICACLS`: Integrity Control Access Control List

![Untitled](Windows%20Basics%2070b83146fec141688f4fe739dcf61ebd/Untitled%201.png)

- The possible inheritance settings are:
    - `(CI)`: container inherit
    - `(OI)`: object inherit
    - `(IO)`: inherit only
    - `(NP)`: do not propagate inherit
    - `(I)`: permission inherited from parent container
- Basic access permissions are as follows:
    - `F` : full access
    - `D` : delete access
    - `N` : no access
    - `M` : modify access
    - `RX` : read and execute access
    - `R` : read-only access
    - `AD` - append data (add subdirectories)
    - `WD` - write data and add files
    - `W` : write-only access
- icacls cheatsheet

[iCacls - Modify Access Control List - Windows CMD - SS64.com](https://ss64.com/nt/icacls.html)

### `accesschk`

```powershell
accesschk.exe $FileName
```

- icalcs installed by default in window, but accesschk isn’t  ([accesschk documentation](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk))

---

<aside>
💡 Alternate Data Streams (ADS) is a file attribute specific to Windows NTFS (New Technology File System).

Every file has at least one data stream (**`$DATA`**), and ADS allows files to contain more than one stream of data. Natively [Window Explorer](https://support.microsoft.com/en-us/windows/what-s-changed-in-file-explorer-ef370130-1cca-9dc5-e0df-2f7416fe1cb1) doesn't display ADS to the user. There are 3rd party executables that can be used to view this data, but [Powershell](https://docs.microsoft.com/en-us/powershell/scripting/overview?view=powershell-7.1) gives you the ability to view ADS for files.

Not all its uses are malicious. For example, when you download a file from the Internet, there are identifiers written to ADS to identify that the file was downloaded from the Internet.

</aside>

---

# System Configuration

- You can manage the start-up apps using the task manager `taskmgr` but you can’t with System Configuration

![Untitled](Windows%20Basics%2070b83146fec141688f4fe739dcf61ebd/Untitled%202.png)

Notice the **Selected command** section. The information in this textbox will change per tool.

The reason Event Viewer is important is that it can be used to forward the events to a SIEM (Security Information and Event Manager) which helps the IT team of a company determine possible malicious activities

---

# Local Security Policy

- Local Security Policy is a group of settings you can configure to strengthen the computer's security. Even though most policy settings in Windows are fine, there are a few that need adjusting for enhanced security. You can set the minimum password length, the password complexity level, you can disable guest & local administrator accounts, and many more.
- **Note: If the computer is not integrated into an Active Directory environment disabling the local administrator account is a bad idea.**

---

# Registry

- The Windows registry database stores many important operating system settings. For example, it contains entries with information about what should happen when double-clicking a particular file type or how wide the taskbar should be. Built-in and inserted hardware also store information in the registry when the driver is installed; this driver is called up every time the system is booted up.
- To access the Registry Editor you can either search it or use **Windows Key + R** and type **RegEdit**.
- The entire system registry is stored in several files on the operating system. You can find these under `C:\Windows\System32\Config\`.
- The user-specific registry hive (HKCU) is stored in the user folder (i.e., `C:\Windows\Users\<USERNAME>\Ntuser.dat`).
- Registries Structure
    - **`HKEY_CLASSES_ROOT`**
    - **`HKEY_CURRENT_USER`**
    - **`HKEY_LOCAL_MACHINE`**
    - **`HKEY_USERS`**
    - **`HKEY_CURRENT_CONFIG`**

The tree-structure consists of main folders (root keys) in which subfolders (subkeys) with their entries/files (values) are located. There are 11 different types of values that can be entered in a subkey.

| Value | Type |
| --- | --- |
| REG_BINARY | Binary data in any form. |
| REG_DWORD | A 32-bit number. |
| REG_DWORD_LITTLE_ENDIAN | A 32-bit number in little-endian format. Windows is designed to run on little-endian computer architectures. Therefore, this value is defined as REG_DWORD in the Windows header files. |
| REG_DWORD_BIG_ENDIAN | A 32-bit number in big-endian format. Some UNIX systems support big-endian architectures. |
| REG_EXPAND_SZ | A null-terminated string that contains unexpanded references to environment variables (for example, "%PATH%"). It will be a Unicode or ANSI string depending on whether you use the Unicode or ANSI functions. To expand the environment variable references, use the https://docs.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-expandenvironmentstringsa function. |
| REG_LINK | A null-terminated Unicode string containing the target path of a symbolic link created by calling the https://docs.microsoft.com/en-us/windows/desktop/api/Winreg/nf-winreg-regcreatekeyexa function with REG_OPTION_CREATE_LINK. |
| REG_MULTI_SZ | A sequence of null-terminated strings, terminated by an empty string (\0). The following is an example: String1\0String2\0String3\0LastString\0\0 The first \0 terminates the first string, the second to the last \0 terminates the last string, and the final \0 terminates the sequence. Note that the final terminator must be factored into the length of the string. |
| REG_NONE | No defined value type. |
| REG_QWORD | A 64-bit number. |
| REG_QWORD_LITTLE_ENDIAN | A 64-bit number in little-endian format. Windows is designed to run on little-endian computer architectures. Therefore, this value is defined as REG_QWORD in the Windows header files. |
| REG_SZ | A null-terminated string. This will be either a Unicode or an ANSI string, depending on whether you use the Unicode or ANSI functions. |

## **Run and RunOnce Registry Keys**

There are also so-called registry hives, which contain a logical group of keys, subkeys, and values to support software and files loaded into memory when the operating system is started or a user logs in. These hives are useful for maintaining access to the system. These are called [Run and RunOnce registry keys](https://docs.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys).

Use `Run` or `RunOnce` registry keys to make a program run when a user logs on. The `Run` key makes the program run every time the user logs on, while the `RunOnce` key makes the program run one time, and then the key is deleted. These keys can be set for the user or the machine.

The Windows registry includes the following four keys:

```
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

Here is an example of the `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run` key while logged in to a system.

```
PS C:\htb> reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
    SecurityHealth    REG_EXPAND_SZ    %windir%\system32\SecurityHealthSystray.exe
    RTHDVCPL    REG_SZ    "C:\Program Files\Realtek\Audio\HDA\RtkNGUI64.exe" -s
    Greenshot    REG_SZ    C:\Program Files\Greenshot\Greenshot.exe
```

Here is an example of the `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` showing applications running under the current user while logged in to a system.

```
PS C:\htb> reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run

HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    OneDrive    REG_SZ    "C:\Users\bob\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background
    OPENVPN-GUI    REG_SZ    C:\Program Files\OpenVPN\bin\openvpn-gui.exe
    Docker Desktop    REG_SZ    C:\Program Files\Docker\Docker\Docker Desktop.exe
```

---

# Windows Services

- Windows services are managed via the Service Control Manager (SCM) system, accessible via the `services.msc` MMC add-in.
- Windows has three categories of services: Local Services, Network Services, and System Services. Services can usually only be created, modified, and deleted by users with administrative privileges. Misconfigurations around service permissions are a common privilege escalation vector on Windows systems.

In Windows, we have some [critical system services](https://docs.microsoft.com/en-us/windows/win32/rstmgr/critical-system-services) that cannot be stopped and restarted without a system restart. If we update any file or resource in use by one of these services, we must restart the system.

| Service | Description |
| --- | --- |
| smss.exe | Session Manager SubSystem. Responsible for handling sessions on the system. |
| csrss.exe | Client Server Runtime Process. The user-mode portion of the Windows subsystem. |
| wininit.exe | Starts the Wininit file .ini file that lists all of the changes to be made to Windows when the computer is restarted after installing a program. |
| logonui.exe | Used for facilitating user login into a PC |
| lsass.exe | The Local Security Authentication Server verifies the validity of user logons to a PC or server. It generates the process responsible for authenticating users for the Winlogon service. |
| services.exe | Manages the operation of starting and stopping services. |
| winlogon.exe | Responsible for handling the secure attention sequence, loading a user profile on logon, and locking the computer when a screensaver is running. |
| System | A background system process that runs the Windows kernel. |
| svchost.exe with RPCSS | Manages system services that run from dynamic-link libraries (files with the extension .dll) such as "Automatic Updates," "Windows Firewall," and "Plug and Play." Uses the Remote Procedure Call (RPC) Service (RPCSS). |
| svchost.exe with Dcom/PnP | Manages system services that run from dynamic-link libraries (files with the extension .dll) such as "Automatic Updates," "Windows Firewall," and "Plug and Play." Uses the Distributed Component Object Model (DCOM) and Plug and Play (PnP) services. |

This [link](https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_components#Services) has a list of Windows components, including key services.

---

# [Service Permissions](https://www.notion.so/Service-Permissions-57e56b597a984edf9baea0d68bdd009d?pvs=21) Service Permissions

---

# **Local Security Authority Subsystem Service (LSASS)**

`lsass.exe` is the process that is responsible for enforcing the security policy on Windows systems. When a user attempts to log on to the system, this process verifies their log on attempt and creates access tokens based on the user's permission levels. LSASS is also responsible for user account password changes. All events associated with this process (logon/logoff attempts, etc.) are logged within the Windows Security Log. LSASS is an extremely high-value target as several tools exist to extract both cleartext and hashed credentials stored in memory by this process.

---

# **Sysinternals Tools**

The [SysInternals Tools suite](https://docs.microsoft.com/en-us/sysinternals) is a set of portable Windows applications that can be used to administer Windows systems (for the most part without requiring installation). The tools can be either downloaded from the Microsoft website or by loading them directly from an internet-accessible file share by typing `\\live.sysinternals.com\tools` into a Windows Explorer window.

For example, we can run procdump.exe directly from this share without downloading it directly to disk.

```powershell
C:\htb> \\live.sysinternals.com\tools\procdump.exe -accepteula
```

The suite includes tools such as `Process Explorer`, an enhanced version of `Task Manager`, and `Process Monitor`, which can be used to monitor file system, registry, and network activity related to any process running on the system. Some additional tools are TCPView, which is used to monitor internet activity, and PSExec, which can be used to manage/connect to systems via the SMB protocol remotely.

---

# **Windows Sessions**

## **Interactive**

An interactive, or local logon session, is initiated by a user authenticating to a local or domain system by entering their credentials. An interactive logon can be initiated by logging directly into the system, by requesting a secondary logon session using the `runas` command via the command line, or through a Remote Desktop connection.

## **Non-interactive**

Non-interactive accounts in Windows differ from standard user accounts as they do not require login credentials. There are 3 types of non-interactive accounts: the Local System Account, Local Service Account, and the Network Service Account. Non-interactive accounts are generally used by the Windows operating system to automatically start services and applications without requiring user interaction. These accounts have no password associated with them and are usually used to start services when the system boots or to run scheduled tasks.

There are differences between the three types of accounts:

| Account | Description |
| --- | --- |
| Local System Account | Also known as the NT AUTHORITY\SYSTEM account, this is the most powerful account in Windows systems. It is used for a variety of OS-related tasks, such as starting Windows services. This account is more powerful than accounts in the local administrators group. |
| Local Service Account | Known as the NT AUTHORITY\LocalService account, this is a less privileged version of the SYSTEM account and has similar privileges to a local user account. It is granted limited functionality and can start some services. |
| Network Service Account | This is known as the NT AUTHORITY\NetworkService account and is similar to a standard domain user account. It has similar privileges to the Local Service Account on the local machine. It can establish authenticated sessions for certain network services. |

---

# Types of servers

Servers can be used for a variety of actions or things. The most common ones are:

- Domain Controller
- File server
- Web server
- FTP Server
- Mail Server
- Database Server
- Proxy Server
- Application Server

![Untitled](Windows%20Basics%2070b83146fec141688f4fe739dcf61ebd/Untitled%203.png)

- **Domain Controller** - This might be one of the most important servers because in an AD or AAD infrastructure we can control users, and groups, restrict actions, improve security, and many more of other computers and servers.
    
    **The easiest way to remember the difference between both is that Active Directory handles your identity and security access and Domain Controllers authenticate your authority
    In other words, it can be said as the Active Directory Domain Service runs the [domain controller](https://www.varonis.com/blog/domain-controller/).** 
    
- **Web Server-** It serves static or dynamic content to a Web browser by loading a file from a disk and serving it across the network to a user’s Web browser.
- **File Server -** File servers provide a great way to share files across devices on a network.
- **FTP Server -** Makes it possible to move one or more files securely between computers while providing file security and organization as well as transfer control.
    
    > **File servers essentially act as a local shared hard drive for offices, and they’re only accessible within the business’ internal network. With [FTP servers](https://offers.ftptoday.com/ftp-comparison-guide-offer)
     on the other hand, you store files on a remote server, uploaded via the internet.**
    > 
- **Mail Server -** Mail servers move and store mail over corporate networks (via LANs and WANs) and across the Internet.
- **Database Server -** A database server is a computer system that provides other computers with services related to accessing and retrieving data from one or multiple databases.
- **Proxy Server -** This server usually sits between a client program and an external server to filter requests, improve performance, and share connections.
- **Application Server -** They're usually used to connect the database servers and the users.

---

---

# Next Step: Links

[Windows Security Basics](https://www.notion.so/Windows-Security-Basics-a3be49509de34546b4bd04074f780f95?pvs=21)

[*Windows Command line*](https://www.notion.so/Windows-Command-line-d66d5731cdd642c88249ba31adc99f18?pvs=21)

[Active Directory Basics](https://www.notion.so/Active-Directory-Basics-b9ab0c3f116b490ea6f935f852a9e380?pvs=21)

[Windows Privilege Escalation](https://www.notion.so/Windows-Privilege-Escalation-035f0b2030e3444e92aebd694e84d9a8?pvs=21)