# Windows Forensics

# Introduction

Among all the used operating system in the world  Windows is the most used OS as it’s easy to use and efficient. It’s used basically in most of organizations   

One of the most important in the forensic investigation is understanding what is File System. Think of a file system as the librarian of your computer's storage drives. It's like an organized catalog that manages all the files and folders, ensuring everything is neatly arranged and easily accessible. 

There is 2 main types of file systems in windows:

1. **File Allocation Table (FAT)**, a basic but sturdy file system, was created back in 1977 for floppy disks. It's one of Microsoft's earliest choices for file management in MS-DOS. FAT gets its name from its simple method of using an index table to keep track of files on disks. The FAT file system has different types***:***
    1. FAT12
    2. FAT16
    3. FAT32
    4. Extended File Allocation Table (exFAT)
    
    **Q: what about those numbers we saw in the different types (12, 16, and 32)?**
    
    A: These refer to the number of bits used for clusters addressing. Which means a **12 bit FAT** can have a cluster size of **212**
    
2. **New Technology File System (NTFS),** is a modern file system developed by Microsoft to replace the aging FAT file system. NTFS provided Features Like:

1. Journaling
2. Scalability
3. Hard links
4. Alternate Data Streams (ADS)
5. File compression
6. Sparse files
7. Volume shadow copy

 

1. Transactions
2. Security
3. Encryption
4. Quotas
5. Reparse points
6. Resizing 

Basically we will focus on NTFS as that is the most commonly used now and we will explore together how can windows know everything about you

# NTFS Structure

### Master File Table (MFT)

NTFS relies on several metadata files to construct its file system's data structures. The cornerstone among these files is the Master File Table (MFT), denoted as $MFT. Visualize the MFT as an array of records, where each file in the NTFS system, including the MFT itself, possesses one or more records. The quantity of records allocated to a file hinges on its size.

The $MFT is the first record in the volume. The Volume Boot Record (VBR) points to the cluster where it is located. $MFT stores information about the clusters where all other objects present on the volume are located. This file contains a directory of all the files present on the volume.

To avert fragmentation of the MFT—ensuring its contiguous placement on the disk—NTFS sets aside space, typically about 12.5% of the total disk capacity, known as the MFT Zone. Alternative settings allocate 25%, 37.5%, or 50% of disk space for this purpose.

**Note:** Sometimes you might have noticed that when you formatted your hard disk drive, and let’s assume it has a 100GB of capacity. You will find that around 12.5GB are already gone from the disk space. In other words, you cannot use them, because they are already reserved for the NTFS file system. This is for your own system’s benefit, don’t worry, not that Microsoft wants to consume your disk space for nothing.

| System File | File Name | MFT Record # | Purpose |
| --- | --- | --- | --- |
| Master file table | $MFT
 | 0 | File holding a record for each file and directory on the volume |
| Master file table mirror | $MFTMirror
 | 1
 | For recovery in case MFT failure |
| Log file | $LogFile
 | 2 | Holds information for file system metadata changes, and helps with recovery |
| Volume | $Volume
 | 3 | Information about the volume and its label |
| Attribute definition | $AttrDef
 | 4 | Holds info about all attributes used within the file system |
| Root file name index |  | 5 | The rood directory |
| Cluster bitmap | $Bitmap
 | 6 | Track free unused clusters within the volume |
| Boot sector | $Boot
 | 7 | Mount the volume and other bootstrap code when the volume is bootable |
| Bad cluster file | $BadClus | 8 | Track bad clusters within the volume
Security file |
| Security file | $Secure | 9 | Stores the security descriptors for all files in the volume |
| Upcase table | $Upcas | 10 | Convert lowercase chars to the matching Unicode uppercase chars |
| NTFS extension directory | $Extended | 11 | Holds optional and extended features such as quotas, reparse points, etc |

### MFT Explorer

MFT Explorer is one of Eric Zimmerman's tools used to explore MFT files. It is available in both command line and GUI versions. We will be using the CLI version for this task. This tool will help you parse and explore MFT record

```bash
MFTECmd.exe -f $MFT_file --csv path-to-save-results-in-csv
```

```bash
MFTECmd.exe -f C:\\\\Path\\\\$MFT --csv .
```

## Journaling

***what does that mean?***
It means the file system uses a log file ($LogFile) to store all metadata changes that happen to the volume. This feature was not found in previous file system used, and it helps the file system to heal itself in case of any uncommitted changes to the appropriate data structures.

### $UsnJrnl

The Update Sequence Number (USN) Journal, found within the $Extend record, serves as a comprehensive log of all file system modifications, along with the reasons behind each change. This journal, alternatively known as the change journal, meticulously documents alterations made to files within the file system.

Q: What is MFT?

A: Master file table

Q: Which file Stores the security descriptors for all files in the volume?

A: $Secure

Q: What is the feature that traces the changes in files?

A: Journaling

# System Registry

Windows Registry is a hierarchical database that stores configuration settings and options on Microsoft Windows operating systems. It serves as a centralized repository for system and application settings, user preferences, hardware configurations, and other critical information needed for the proper functioning of the operating system and installed software.

Imagine the registry as a filing cabinet with labeled folders and subfolders. Each folder (key) holds settings (values) or even more folders (subkeys) for further organization. The cabinet itself is divided into different drawers (hives) that group related settings together. This way, Windows and programs can easily find the specific information they need to run smoothly.

### Location and importance:

Registry hives are  located at `C:\\Windows\\System32\\Config` which contains all the configuration about your PC:

1. **DEFAULT** mounted on `HKEY_USERS\\DEFAULT` → This hive contains default user settings and configurations. It serves as a template for new user profiles created on the system.
2. **SAM** mounted on `HKEY_LOCAL_MACHINE\SAM` → hive stores user account information, including user names and their corresponding security identifiers (SIDs). It is crucial for user authentication and security on the system.
3. **SECURITY** mounted on `HKEY_LOCAL_MACHINE\\Security` → The Security hive contains security-related configuration settings and policies for the Windows operating system. It includes information about user rights, permissions, and security settings.
4. **SOFTWARE** mounted on `HKEY_LOCAL_MACHINE\\Software` → This hive stores configuration data and settings for installed software applications on the system. It includes information about installed programs, their settings, and preferences.
5. **SYSTEM** mounted on `HKEY_LOCAL_MACHINE\\System` → The System hive contains essential configuration data related to the hardware, drivers, and system settings of the Windows operating system. It includes information needed for the system to boot and function properly.

When you open **Registry Editor,** Which is the built-in tool for windows, you will see all the previous hives

![Untitled](Windows%20Forensics%20f1d88d533a8a4f2fb4f8aef5d4f091f1/Untitled.png)

***Why Examine the Registry?***
It could have a great effect on the examination: 

1.  Maintains system configurations and functionality settings
2.  Whether the system is to clear the page file on shutdown
3. Recycle Bin settings and whether to bypass it or not
4. Settings related to enable/disable Windows Firewall
5. User preferences and historical activity such as opening files, and recently used stuff
6. We can also find what programs will automatically start when the Windows starts (Autostarts)

### Registry Artifacts

1. Time Zone: **`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\TimeZoneInformation`**
2. Windows Computer Name: **`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`**
3. services: **`SYSTEM\ControlSet00#\Service\`**
4. Windows DHCP Config: **`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`**
5. Legal Notice & Text : check the legal notices that appear to the user at the logon screen. **`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\`**
6. NTFS Last Accessed: **`SYSTEM \ControlSet###\Control\FileSystem`**
7. Autoruns it contains  auto-starting programs, services, drivers, scheduled tasks, and more on Windows systems.: 
    - **`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`**
    - **`HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run bzw.\RunOnce`**
    - `SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\Run`
8. Installed Applications
    - **`HKLM\SOFTWARE\Microsoft\Windows\C.V.\App Paths`**
    - **`HKLM\SOFTWARE\Microsoft\Windows\C.V.\Uninstall`**
9. Windows Firewall: determine the state of the Windows Firewall. 
    - Private (standard): **`SYSTEM\ControlSet###\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\EnableFirewall`**
    - Public: **`SYSTEM\ControlSet###\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\EnableFirewall`**
    - Domain: **`SYSTEM\ControlSet###\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\EnableFirewall`**
10. Remote Desktop: **`SYSTEM\ControlSet###\Control\TerminalServer\fDenyTSConnections`**
11. Network History: **`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache`**
12. Managed networks location refers to one where the computer is part of a domain: **`HKLM\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\NetworkList\Signatures\Managed\`**
13. Unmanaged network location is, by default and logically, the one where a computer is not part of a domain. 

**`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\NetworkList\Signatures\Unmanaged`**

1. Network Types **`HKLM\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\NetworkList\Profiles`**
2. Shutdown Details: **`HKLM\SYSTEM\ControlSet001\Control\Windows`**
3. AppInit_DLLs: is a value that contains a list of DLLs that will be automatically loaded whenever any usermode application that is linked to user32.dll is launched. **`HKLM\Software\Microsoft\WindowsNT\CurrentVersion\Windows\AppInit_DLLs` , `HKLM\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\Windows\LoadAppInit_DLLs`**

Q: Where is the login information stored in registry?

A: SAM

Q: Where is the IP address stored in registry?

A: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces

# User Hives

User hives are sections of the Windows Registry that contain configuration settings and preferences specific to individual user profiles on a Windows system. Each user account on a Windows system has its own user hive, which stores personalized settings and configurations unique to that user. These settings include desktop customization, application preferences, file associations, and more.

### Location and Importance

1. **NTUSER.DAT** mounted on `HKEY_CURRENT_USER` when a user logs in →  stores the registry settings specific to each user profile when they log into the system.
2. **USRCLASS.DAT** mounted on `HKEY_CURRENT_USER\\Software\\CLASSES` The USRCLASS.DAT hive is located in the directory `C:\\Users\\<username>\\AppData\\Local\\Microsoft\\Windows`  → contains user-specific settings related to file associations and MIME types.
3. **AmCache.hve** this hive is located in `C:\\Windows\\AppCompat\\Programs\\Amcache.hve` → Windows creates this hive to save information on programs that were recently run on the system.

### Artifacts

1. **Autostart Programs (Autoruns):**
    - **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`**
    - **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`**
2. **Windows Recycle Bin**: The properties of the Windows recycle bin have been consistent since Vista. User’s can send (move) files to the Recycle Bin or completely bypass it (similar to Shift + Delete command). **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\BitBucket\Volume\{GUID}\NukeOnDelete`**  The settings are:1 = bypass Recycle Bin, 0 = move to Recycle Bin
3. **User Sessions: `SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData\<#>\LastLoggedOnSamUser`**this value is DELETED once the machine is powered off!
4. **Local Users... Login Tile: `SAM\SAM\Domains\Account\Users\<32-bit hexvalue>\UserTile`**
5. **User Account Control (UAC): `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`**
6. **User Assist Keys: `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`**
7. **What Key was Viewed: `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit\LastKey`**
8. **Most Recently Used and Opened: `HKEY_USERS\{SID}\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenPidlMRU`  ,** 

**`HKEY_USERS\{SID}\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPid`**

1. **Start Menu Run MRUs: `HKEY_USERS\{SID}\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`**
2. **RecentDocs MRUs:** Another registry key that contains a list of recently opened files  **`HKEY_USERS\{SID}\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`  NOTE**  Values within this key mirror the link (LNK) files tracked within **`C:\Documents and Settings\%USERNAME%\Recent\`**
3. **Remote Desktop MRU: `HKEY_USERS\{SID}\Software\Microsoft\Terminal ServerClient\Default\` , `HKEY_USERS\{SID}\Software\Microsoft\Terminal ServerClient\Servers\Terminal Server Client\Default\`**   contains the most recently accessed IP address or host name.
4. **Most Recently Opened:** applications and files that have been opened **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32`**  

We can find a series of subkeys: LastVisitedPidlMRU: Applications , OpenSavePidlMRU: Files

1. **IE Browser Settings: `NTUSER.DAT\Software\Microsoft\InternetExplorer\Main`**

### Tools

there are many tools for exploring registry one of the most powerful ones are

- registry explorer by Eric Zimmerman
- Registry Editor
- Registry Manager

# Application compatibility cache

**ShimCache** (aka Application Compatibility Cache), allows Windows to track executable files and scripts that may require special compatibility settings to properly run. It is maintained within kernel memory and serialized to the registry upon system shutdown or restart.

### Location & Importance

Decoded contents of this key vary by version of Windows, and can include the following data:

- The executable or script file names and full paths
- The standard information last modified date
- The size of the binary
- Finally, whether the file actually ran on the system (just browsed through explorer.exe)
- By analyzing the entries, we can identify whether an executable was run on a system. In addition to the local drive, executables on removable media and UNC paths are also stored in ShimCache.

**Remember**

- Prefetch files are specify the file being executed on the system and they are disabled by default on Windows Servers! So, ShimCache are a great alternative!
- Windows also processes and adds executable files to the cache upon changes to file metadata and path, regardless of whether the file has executed. This means that it could provide evidence of executable files that never actually ran on a system.
- while both Shimcache and Amcache store information about executed programs, the Amcache is a more advanced and evolved version introduced in later Windows versions for improved functionality and data structure.

They are found in:

Windows XP: **`HKLM\SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatibility\AppCompatCache`**

Windows Vista/7/8, etc: **`HKLM\SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache`**

Starting with Windows 8, it is now replaced with a registry HIVE called **amcache.hve** which can be found: **`%SYSTEMROOT%\AppCompat\Programs`**

### Tools

- Load the **`%SYSTEMROOT%\AppCompat\Progr**ams\amcache.hve` into registry explorer
- **AppCompatCachPareser.exe** from Eric Zimmerman tools

```bash
AppCompatCachPareser.exe -f /config/SYSTEM --csv Path/to/dir 
```

![Untitled](Windows%20Forensics%20f1d88d533a8a4f2fb4f8aef5d4f091f1/Untitled%201.png)

Q: Which is the more advanced part of windows that contains information about executed programs?

A: Amcache 

Q: What is the location of amcache.hve

A: %SYSTEMROOT%\AppCompat\Programs

# Prefetch Files

When a program is run in Windows, it stores its information for future use. This stored information is used to load the program quickly in case of frequent use. The windows cache manager is a component of the memory management system that monitors the data and code that running processes load from files on disk. It tracks the first 2 minutes of boot processes and the first 10 seconds of all other applications startup. Then, the cache manager working with the task scheduler writes these results of traces to prefetch files.

The naming schema of these files consists of adding the executable name in capital letters, followed by ( **`-`**), and then an eight character hash derived from the location the application was started from.

***Important Note:*** If same executable ran from two different paths (locations), then you will find two different prefetch files.

**Prefetch Directory holds the following files:**

- [Ntosboot-b00dfaad.pf](http://ntosboot-b00dfaad.pf/) which is the system boot prefetch. This file will always have the same name. On windows servers, this is the only prefetch file that will exist by default. monitoring accessed files through the first two minutes of the boot process.
- Layout.Ini, this file contains data used by the disk defragmenter.

**Superfetch**

Additional files that are found and follow the naming convention **ag*.db**, such as:

- Agapplaunch.Db these are files that were generated by the **Superfetch system mechanism** is another performance optimization mechanism that can run concurrently with prefetch. The format of these files is undocumented.

### location:

1. **`C:\Windows\Prefetch`**
2. Registry Keys: **`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\MemoryManagement\PrefetchParameters`**
    - 0: This means that prefetching is disabled.
    - 1: This means enable applications prefetching only.
    - 2: This means enable boot prefetching only.
    
    ### Tools
    
    - Winprefetchview, NirSoft
    - Prefetch-parser, TZWorks
    - prefetch-parser, Redwolf Forensics
    - PECmd, Eric Zimmerman (highly recommended)
    - [PrefetchDump.py](http://prefetchdump.py/) script
    

# ShellBags

ShellBags are a set of Windows Registry keys located in NTUser.dat and USRClass.dat registry hives that maintain view, icon, position, and size of folders when using Windows Explorer. Each ShellBag contains binary data (seen in hexadecimal) that defines what the ShellBag represents. Some ShellBags contain strings (both ANSI and Unicode) representing things such as directory names or UNC paths.

### Location & Importance

- May point to evidence that existed at one point in time.
- May assist the examiner in looking at the broader picture when only a piece is known.
- Information persists even when the original directories, files, and physical devices have been removed from the system.
- Can serve as a “history” into data that was previously on a system but may have since been removed.
- Can be the Desktop item, a Control Panel Category, a Control Panel item, a drive letter, or a directory, etc.
- Could be used to track a cyber intruder's actions on a host system after compromise if the actor uses for example:
    - RDP or other Remote Connection controls.
    - Windows Explorer to drop binaries onto the system.
    - Access network resources.
    - Browse compressed archives.

Shellbags are found in:

- **`HKCU\Software\Microsoft\Windows\Shell\Bags`**
- **`HKCU\Software\Microsoft\Windows\Shell\BagMRU (ntuser.dat)`**
- **`HKCU\Software\Microsoft\Windows\ShellNoRoam\Bags`**
- **Under NTUSER.DAT:**
    - **`HKCU\Software\Microsoft\Windows\ShellNoRoam\ BagMRU`**
- **Under USRCLASS.DAT:**
    - **`HKCU\Software\Classes\LocalSettings\Software\Microsoft\Windows\Shell\BagMRU`**
    - **`HKCU\Software\Classes\LocalSettings\Software\Microsoft\Windows\Shell\Bags`**

### Tools

Some tools used to view ShellBags:

- RegEdit
- RegRipper
- ShellBags Explorer (The best option)

# Jump lists

Is a new feature released with Microsoft Windows 7. Provides the user with a graphical interface associated with each installed application which lists files that have been previously accessed by that application. The default setting is to show the **10 most recently** accessed files per application. It is possible to adjust to a **maximum of 60 entries**.

***Jump lists could contain:***

- Tasks
- Links to recent files
- Frequently used files
- Links to pinned files

### Location and Dest Files

- The common location that JumpLists are found in is:
    - **`%USERPROFILE%\AppData\Roaming\Microsoftg\Windows\Recent\`**
    - **`%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent Items`**
- items pinned to the Taskbar are stored in a directory:
    - **`%userprofile%\AppData\Roaming\Microsoft\InternetExplorer\Quick Launch\User Pinned\TaskBar`**
    - OR in registry: **`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband`  ,**
    - **`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_JumpListItems`**
- **When the application performs certain actions, two types of files are generated, as seen to the right:**
    
    **AutomaticDestinations-ms (autodest) files**: These are files that are created by the operating systems. They can be found: **`%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations`**
    
    **CustomDestinations-ms (customdest) files:** are created when the user pins a file to an application via taskbar. They can be found: **`%USERPROFILE%\AppData\Microsoft\Windows\Recent\CustomDestinations`**
    
    ***NOTE:*** Every application has an id known as AppID. It is formed of 16 hexadecimal digits. Every file is named with AppID, followed by the file extension **automaticDestinations-ms.** 
    

# Link Files (.lnk)

According to Microsoft, it is "a data object that contains information that can be used to access another data object." They are commonly called as Shortcuts. Lnk files are **metadata** files specific for the Microsoft Windows platform and are interpreted by the Windows Shell. specific signature, **`0x4C (4C 00 00 00)`** at offset **`0`** within the file.

### Location & Importance

- Path of target
- Creation time
- MAC address of the host computer (not always)
- The size of the target when it was last accessed
- Serial number of the volume where the target was stored

- Network volume share name
- Modification time
- Different attributes: Readonly, hidden, system, volume label, encryption, sparse, compressed, etc
- Distributed link tracking information

**NOTE**:

- Absolute Path is not stored in the lnk file! At the time a target file is opened the MAC timestamps of the target file are read and stored within the associated link file itself. The **FILETIME** format using **8 bytes** is used to record the date of these files.
- if both timestamps are the same (timestamps found in file and on filesystem) this indicates that the file was opened only once from ShortCut.
- A special case and important exception is when a new file has been created from an application and then saved from inside it, and supposedly a link file has been created for it. Then, the link file will not contain any embedded dates relating to the target file!

**common locations**

1. **`\%USERPROFILE%\Recent`**
2. **`\%USERPROFILE%\Application Data\Microsoft\Office\Recent`**

### **Tools**

- Exiftool
- Windows LNK Parsing Utility from TZWorks
- LECmd.exe, by Eric Zimmerman
- Any Hex Editor, as long as you know the structure

# ThumbCache

Thumbnails are small, reduced-size versions of images or videos used to give viewers a preview or quick reference without having to load the full-size file. For example When the user uses the Thumbnails or Filmstrip views from the Windows folder viewing options, a small thumbnail version of the pictures will be created and stored in a single file (basic form of database).

### Location & Importance

Before Windows Vista/7, thumbnail files were located within the same directory the pictures are stored in and has the name Thumbs.db. This file stores a thumbnail version of the existing and also deleted pictures.

If the user has deleted the pictures but **hasn't delete the thumbs.db** file, it will be possible to recover the thumbnail version of the pictures deleted from that directory, which provides a good clue about the pictures contents that used to be there.

**Thumbnails are found in:**

- **`%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer`**
- **`C:\ProgramData\Microsoft\Search\Data\Applications\Windows.edb`**

### Tools

1. Thumbcache Viewer 
2. Esentutil.exe (run on windows.edb)

# Analysis of Recycler

***When a file is placed into the Recycle Bin, Windows renames it using the following convention***

- **C** is a fixed character and will always be present.
- **<DriveLetter>** refers to the volume from which the file was deleted.
- **<Index#>** references index of file in recycle bin
- **<FileExtension>** matches the original extension of the file.

EX ⇒ **C:\hacking\ipaddresses.txt**

 In recycle bin ⇒ **C:\Recycler\[John’s SID]\DC1.txt**

- C refers to the source volume name.
- 1 refers to the index.
- .txt refers to the file’s original extension.

Now each time a new file is added to the Recycle Bin, its associated metadata is stored in a hidden file named **`\Recycler\<SID>\INFO2`**.

The INFO2 file is used to track the following information for each file sent to the recycle bin: The physical file size (not logical), The date and time of deletion (stored in UTC), The original file name and path

Analysis of \$Recycle.Bin\

- **`\$Recycle.Bin\<SID>\$I<ID_STRING>.<FileExtension>` (**$I file replaces the usage INFO2 file as the source of accompanying metadata, **I** from information **)**
- **`\$Recycle.Bin\<SID>\$R<ID_STRING>.<FileExtension>`** ($R file is a renamed copy of the “deleted” , **R** contains the RAW content of the file.)

### Tools

- rifiuti2, it is an excellent open source utility capable of parsing Recycle Bin INFO2 and $I files alike.
- Recbin.exe, Harlan Carvey.
- EnCase and FTK
- Autopsy
- Finally, a simple Python script [RecycleDump.py](http://recycledump.py/).

# Internet Explorer (IE) forensics

### Artifacts Created by Browsers

***artifacts*** 

- **History**:
    - Date and time for visited websites (URLs).
    - Convenient to revisit a site recently visited.
- **Cache**:
    - Store local copies of data that is retrieved.
    - Used to speed up the browsing process.
- **Cookies:**
    - Small bits of info. that a site may instruct a browser to store.
    - Commonly used to save site preferences and maintain session information.

### Data Format and Locations

Stores data in a combination of files and registry keys.

- **Stored in the Windows Registry**
    - Autocomplete
    - Typed URLs
    - Preferences
- **Stored in the File System**
    - Cache
    - Bookmarks
    - Cookies

**Autocomplete** “form data” saves inputs that a user has provided in a form. Data is stored in one of two registry keys because the autocomplete data may contain sensitive information.

- **`HKCU\Software\Microsoft\InternetExplorer\IntelliForms\Storage1Autocomplete`**
- **`HKCU\Software\Microsoft\InternetExplorer\IntelliForms\Storage2Typed URLs`**

### Artifact Locations

- **Cache**:  **`\%USERPROFILE%\AppData\Local\Microsoft\Windows\Temporary\Internet Files\`**
- **Bookmarks**: **`\%USERPROFILE%\Favorites`**
- **Cookies:**
    - **`\%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Cookies`**
    - **`\%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Cookies\Low`**
    
    **IE History Files…
    ****• IE <= Versions 9 store history in proprietary database files named index.dat.
    • A number of index.dat files will exist per user, for different time ranges of the user’s browsing history.
    • As of IE version 10, Microsoft has dropped the index.dat files and uses the Extensible Storage Engine (ESE) database format.
    
    **IE behavior :** 
    
    - The “**automatic**” setting is done by the browser to determine the frequency of visits and number of changes a page has between visits
    before it checks for new content.
    - User can **manually** clear the cache or set the browser to clear the cache on exit.
    - Cache will be **maintained** for a number of days (configurable).
    - Settings also **limit** the amount of disk space to use.
    - These actions will delete files from the Temporary Internet location.
    
    ### Tools
    
    - Cache Viewer: [www.nirsoft.net/utils/ie_cache_viewer.html](http://www.nirsoft.net/utils/ie_cache_viewer.html)
    - History Viewer for IE 4-9: [www.nirsoft.net/utils/iehv.html](http://www.nirsoft.net/utils/iehv.html)
    - Cookie Viewer for IE 4-9: [www.nirsoft.net/utils/iecookies.html](http://www.nirsoft.net/utils/iecookies.html)
    - History and Cookie Viewer for IE 10+: [www.nirsoft.net/utils/ese_database_view.html](http://www.nirsoft.net/utils/ese_database_view.html)
    - AutoComplete for IE4-9: [www.nirsoft.net/utils/pspv.html](http://www.nirsoft.net/utils/pspv.html)
    - AutoComplete for IE10+: [www.nirsoft.net/utils/internet_explorer_password.html](http://www.nirsoft.net/utils/internet_explorer_password.html)

# USB Forensics

### Locations of USB Device Evidence

### Via File System

1. Specific System Log Files: Files under C:\Windows\
    1. **setupact.log:** holds setup actions done during installation
    2. **setup.err.log:** holds error message to actions that happened
2. To locate where the device is mounted, we need to check the MountedDevices registry key. This key is located at: **`HKLM\SYSTEM\MountedDevices`**

## Via Registry

- Windows Registry: **`HKLM\SYSTEM\ControlSet00?\Enum\USBSTOR`**
- serial number here is **5639311262174133917&0**
- further, then navigate to the 'Properties' key. From there, expand the key that begins with ‘xxxxxxxx-xxxx-xxxx-xxxxxxxxx’ This subkey will contain additional subkeys with more information on of them contain **timestamp**
- if the service type was disk which confirmed whether it was a mini USB or an **external drive attached** via a USB port.

## Via Event Logs

Open the event viewer and go to: “Application and Services Logs” -> Microsoft -> Windows.

- **Partition → diagnostic** We are interested in event ID **1006**
- **Kernel-PnP → Device Configuration** We are interested in Event IDs **400** and **410**
- **NTFS  → operational** event log and filter for event ID **142**.

## Via Shellbags

Shellbags are stored in the registry at the following locations:

- **`NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU`**
- **`NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags`**
- **`USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags`**
- **`USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`**

load the userclass.dat or ntuser.dat in **shellbags explorer** 

## **Via Jumplists**

check jumplists data with shellbag explorer

## Via third party tool

use USB Detective