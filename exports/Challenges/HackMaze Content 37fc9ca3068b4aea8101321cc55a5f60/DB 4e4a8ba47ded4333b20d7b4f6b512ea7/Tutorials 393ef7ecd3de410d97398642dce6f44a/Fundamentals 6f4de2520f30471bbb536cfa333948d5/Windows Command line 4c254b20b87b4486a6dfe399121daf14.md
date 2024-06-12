# Windows Command line

---

# **Case Study: Windows Recovery**

In the event of a user lockout or some technical issue preventing/ inhibiting regular use of the machine, booting from a Windows installation disc gives us the option to boot to `Repair Mode`. From here, the user is provided access to a Command Prompt, allowing for command-line-based troubleshooting of the device.

![https://academy.hackthebox.com/storage/modules/167/RecoveryMode.gif](https://academy.hackthebox.com/storage/modules/167/RecoveryMode.gif)

While useful, this also poses a potential risk. For example, on this Windows 7 machine, we can use the recovery Command Prompt to tamper with the filesystem. Specifically, replacing the `Sticky Keys` (`sethc.exe`) binary with another copy of `cmd.exe`

Once the machine is rebooted, we can press `Shift` five times on the Windows login screen to invoke `Sticky Keys`. Since the executable has been overwritten, what we get instead is another Command Prompt - this time with `NT AUTHORITY\SYSTEM` permissions. We have bypassed any authentication and now have access to the machine as the super user.

---

# Getting Help

## `help` command

```bash
help
```

```bash
help command
```

## Microsoft Documentation

[Microsoft Documentation](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands) has a complete listing of the commands that can be issued within the command-lin interpreter as well as detailed descriptions of how to use them. Think of it as an online version of the Man pages.

## ss64

[ss64](https://ss64.com/nt/) Is a handy quick reference for anything command-line related, including cmd, PowerShell, Bash, and more.

This is a partial list of resources; however, these should provide a good baseline for working with the Command Prompt.

---

# **Basic Tips & Tricks**

## History

```bash
doskey /history
```

- doskey shows the current session history only
- cmd.exe history location `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\CommandPrompt0.txt`

## **Useful Keys & Commands for Terminal History**

It would be helpful to have some way of remembering some of the key functionality provided by our terminal history. With this in mind, the table below shows a list of some of the most valuable functions and commands that can be run to interact with our session history. This list is not exhaustive. For example, the function keys F1 - F9 all serve a purpose when working with history.

| Key/Command | Description |
| --- | --- |
| doskey /history | doskey /history will print the session's command history to the terminal or output it to a file when specified. |
| page up | Places the first command in our session history to the prompt. |
| page down | Places the last command in history to the prompt. |
| ⇧ | Allows us to scroll up through our command history to view previously run commands. |
| ⇩ | Allows us to scroll down to our most recent commands run. |
| ⇨ | Types the previous command to prompt one character at a time. |
| ⇦ | N/A |
| F3 | Will retype the entire previous entry to our prompt. |
| F5 | Pressing F5 multiple times will allow you to cycle through previous commands. |
| F7 | Opens an interactive list of previous commands. |
| F9 | Enters a command to our prompt based on the number specified. The number corresponds to the commands place in our history. |

---

# **Interesting Directories**

As promised, we have nearly reached the end of this section. With our current skill set, navigating the system should be much more approachable now than initially seemed. Let us take a minute to discuss some directories that can come in handy from an attacker's perspective on a system. Below is a table of common directories that an attacker can abuse to drop files to disk, perform reconnaissance, and help facilitate attack surface mapping on a target host.

| Name: | Location: | Description: |
| --- | --- | --- |
| %SYSTEMROOT%\Temp | C:\Windows\Temp | Global directory containing temporary system files accessible to all users on the system. All users, regardless of authority, are provided full read, write, and execute permissions in this directory. Useful for dropping files as a low-privilege user on the system. |
| %TEMP% | C:\Users\<user>\AppData\Local\Temp | Local directory containing a user's temporary files accessible only to the user account that it is attached to. Provides full ownership to the user that owns this folder. Useful when the attacker gains control of a local/domain joined user account. |
| %PUBLIC% | C:\Users\Public | Publicly accessible directory allowing any interactive logon account full access to read, write, modify, execute, etc., files and subfolders within the directory. Alternative to the global Windows Temp Directory as it's less likely to be monitored for suspicious activity. |
| %ProgramFiles% | C:\Program Files | folder containing all 64-bit applications installed on the system. Useful for seeing what kind of applications are installed on the target system. |
| %ProgramFiles(x86)% | C:\Program Files (x86) | Folder containing all 32-bit applications installed on the system. Useful for seeing what kind of applications are installed on the target system. |

---

# Working with Files and Directories

- `mkdir DirectoryName`  or `md DirecotryName` Make Directory
- `rmdir DirectoryName`  or `rd DirecotryName` Make Directory
- `move DirectoryName NewLocation`

## `Xcopy`

We will take a minute to look at `xcopy` since it still exists in current Windows operating systems, but it is essential to know that it has been deprecated for `robocopy`. **Where xcopy shines is that it can remove the Read-only bit from files when moving them**. The syntax for `xcopy` is `xcopy` `source` `destination` `options`. As it was with move, we can use wildcards for source files, not destination files.

```bash
xcopy $FileName $DestPath /E
```

Xcopy prompts us during the process and displays the result. In our case, the directory and any files within were copied to the Desktop. Utilizing the `/E` switch, we told Xcopy to copy any files and subdirectories to include empty directories. Keep in mind this will not delete the copy in the previous directory. When performing the duplication, xcopy will reset any attributes the file had. If you wish to retain the file's attributes ( such as read-only or hidden ), you can use the `/K`
 switch.

## Robocopy

`Robocopy` is xcopy's predecessor built with much more capability. We can think of Robocopy as merging the best parts of copy, xcopy, and move spiced up with a few extra capabilities. Robocopy can copy and move files locally, to different drives, and even across a network while retaining the file data and attributes to include timestamps, ownership, ACLs, and any flags set like hidden or read-only. We need to be aware that Robocopy was made for large directories and drive syncing, so it does not like to copy or move singular files by default. That is not to say it is incapable, however. We will cover a bit of that down below.

```bash
robocopy $FileName $DestPath
```

Robocopy can also work with system, read-only, and hidden files. As a user, this can be problematic if we do not have the `SeBackupPrivilege` and `auditing privilege` attributes. This could stop us from duplicating or moving files and directories. There is a bit of a workaround, however. We can utilize the `/MIR` switch to permit ourselves to copy the files we need temporarily.

Utilizing the /MIR switch will complete the task for us. Be aware that it will mark the files as a system backup and hide them from view. We can clear the additional attributes if we add the `/A-:SH` switch to our command. Be careful of the `/MIR` switch, as it will mirror the destination directory to the source**. Any file that exists within the destination will be removed**. Ensure you place the new copy in a cleared folder. Above, we also used the `/L` switch. This is a what-if command. It will process the command you issue but not execute it; it just shows you the potential result. Let us give it a try below.

```bash
robocopy /E /MIR /A-:SH $DirName $DestPath
```

---

# Finding Files and Directories

## Where

- search for file

```bash
where $FileName
```

- `where` will search in folders in `PATH env` only we can use `/R` to make it recursive and in search in all directories

```bash
where /R $path $FileName
```

- Example:
    
    ```bash
    where /R c:\ *.ext
    ```
    

## Find

```bash
find $SearchKey $FileName
```

- `/I`  Ignore case sensitivity
- `/N`  show line number
- `/V`  all lines not contain `$SearchKey`

## findstr

`findstr` is close to `grep`

```bash
findstr $SearchKey $FileName
```

```bash
type $FileName | findstr $SearchKey
```

---

# Evaluating and Sorting Files

## compare

### `comp`

```bash
comp $FileName $FileName2
```

### `fc`

```bash
fc $FileName $FileName2
```

## sort

```bash
sort $FileName /O $OutputName
```

```bash
sort $FileName /O $OutputName /unique
```

---

# **Environment Variables**

environment variables are `not` case sensitive and can have spaces and numbers in the name, but they cannot have a name that starts with a number or include an equal sign.

## **Variable Scope**

In this context, `Scope` is a programming concept that refers to where variables can be accessed or referenced. 'Scope' can be broadly separated into two categories:

- **Global:**
    - Global variables are accessible `globally`. In this context, the global scope lets us know that we can access and reference the data stored inside the variable from anywhere within a program.
- **Local:**
    - Local variables are only accessible within a `local` context. `Local` means that the data stored within these variables can only be accessed and referenced within the function or context in which it has been declared.

| Scope | Description | Permissions Required to Access | Registry Location |
| --- | --- | --- | --- |
| System (Machine) | The System scope contains environment variables defined by the Operating System (OS) and are accessible globally by all users and accounts that log on to the system. The OS requires these variables to function properly and are loaded upon runtime. | Local Administrator or Domain Administrator | HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment |
| User | The User scope contains environment variables defined by the currently active user and are only accessible to them, not other users who can log on to the same system. | Current Active User, Local Administrator, or Domain Administrator | HKEY_CURRENT_USER\Environment |
| Process | The Process scope contains environment variables that are defined and accessible in the context of the currently running process. Due to their transient nature, their lifetime only lasts for the currently running process in which they were initially defined. They also inherit variables from the System/User Scopes and the parent process that spawns it (only if it is a child process). | Current Child Process, Parent Process, or Current Active User | None (Stored in Process Memory) |

## show all Environment Variables

```bash
set
```

## print variable

```bash
echo %$VarName%
```

## Managing Environment Variables

### `set` vs `setx`

- The `set` utility only manipulates environment variables in the current command line session. This means that once we close our current session, any additions, removals, or changes will not be reflected the next time we open a command prompt. Suppose we need to make permanent changes to environment variables. In that case, we can use `setx` to make the appropriate changes to the registry, which will exist upon restart of our current command prompt session.
- Using `setx`, we also have some additional functionality added in, such as being able to create and tweak variables across computers in the domain as well as our local machine.

## `set`

```bash
set DCIP=172.16.5.2
```

### `setx`

```bash
setx DCIP 172.16.5.2
```

- don’t add `=`

```bash
setx username "Juba :)"
```

### remove variable

```bash
setx username
```

```bash
C:\htb> set DCIP
Environment variable DCIP not defined

C:\htb> echo %DCIP%
%DCIP%
```

- Using both `set` and `echo`, we can verify that the `%DCIP%` variable is no longer set and is not defined in our environment anymore.

## **Important Environment Variables**

Now that we are comfortable creating, editing, and removing our own environment variables, let us discuss some crucial variables we should be aware of when performing enumeration on a host's environment. Remember that all information found here is provided to us in clear text due to the nature of environment variables. As an attacker, this can provide us with a wealth of information about the current system and the user account accessing it.

| Variable Name | Description |
| --- | --- |
| %PATH% | Specifies a set of directories(locations) where executable programs are located. |
| %OS% | The current operating system on the user's workstation. |
| %SYSTEMROOT% | Expands to C:\Windows. A system-defined read-only variable containing the Windows system folder. Anything Windows considers important to its core functionality is found here, including important data, core system binaries, and configuration files. |
| %LOGONSERVER% | Provides us with the login server for the currently active user followed by the machine's hostname. We can use this information to know if a machine is joined to a domain or workgroup. |
| %USERPROFILE% | Provides us with the location of the currently active user's home directory. Expands to C:\Users\{username}. |
| %ProgramFiles% | Equivalent of C:\Program Files. This location is where all the programs are installed on an x64 based system. |
| %ProgramFiles(x86)% | Equivalent of C:\Program Files (x86). This location is where all 32-bit programs running under WOW64 are installed. Note that this variable is only accessible on a 64-bit host. It can be used to indicate what kind of host we are interacting with. (x86 vs. x64 architecture) |

Provided here is only a tiny fraction of the information we can learn through enumerating the environment variables on a system. However, the abovementioned ones will often appear when performing enumeration on an engagement. For a complete list, we can visit the following [link](https://ss64.com/nt/syntax-variables.html). Using this information as a guide, we can start gathering any required information from these variables to help us learn about our host and its target environment inside and out.

---

# Managing Services

## check Service permissions in [Service Permissions](https://www.notion.so/Service-Permissions-57e56b597a984edf9baea0d68bdd009d?pvs=21)

## `sc`: Service Controller

### state

```bash
sc query state= inactive
```

 اوعي تغير مكان المسافة  not → sc query state = inactive query is a service 

### start and stop

```bash
*sc start $ServiceName*
```

- service name  not display name
- attempting to stop an elevated service like this is not the best way of testing permissions, as this will likely lead to us getting caught due to the traffic that will be kicked up from running a command like this.

### config

```bash
sc config $ServiceName start= disabled
```

- All changes made with this command are reflected in the Windows registry as well as the database for Service Control Manager (`SCM`).
- Remember that all changes to existing services will only fully update after restarting the service.

## query

```bash
sc query $ServiceName
```

```bash
sc queryex $ServiceName
```

- Displays extended status for the eventlog service

## `tasklist`

- [Tasklist](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tasklist) is a command line tool that gives us a list of currently running processes on a local or remote host. However, we can utilize the `/svc` parameter to provide a list of services running under each process on the system. Let's look at some of the output this can provide.

```bash
tasklist /svc
```

## `net start`

- [Net start](https://ss64.com/nt/net-service.html) is a very simple command that will allow us to quickly list all of the current running services on a system. In addition to `net start`, there is also `net stop`, `net pause`, and `net continue`. These will behave very similarly to `sc` as we can provide the name of the service afterward and be able to perform the actions specified in the command against the service that we provide.

```bash
net stat
```

## WMIC

- Windows Management Instrumentation Command (`WMIC`) allows us to retrieve a vast range of information from our local host or host(s) across the network. The versatility of this command is wide in that it allows for pulling such a wide arrangement of information.
- To list all services existing on our system and information on them, we can issue the following command: `wmic service list brief`.

```bash
wmic service list brief
```

> **Note:** It is important to be aware that the `WMIC` command-line utility is currently deprecated as of the current Windows version. As such, it is advised against relying upon using the utility in most situations. You can find further information regarding this change by following this [link](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmic).
> 

---

# Various Commands

- **`dir /r`  to list the ADS (alternate data stream)**
- **`dir /ah`  list with *only*   the  hidden files ⇒ `ls -a` in Linux**
- `dir /A:R` List files with Read-only Attribute

```bash
fsutil file createNew $FileName 222
```

- `ren FileName NewName`
- `find /i "see" < test.txt`
- **`attrib file +h`  to hide the file ⇒ `mv .file`**
- **`attrib file -h`  to show the file x⇒ `mv file`**
- `del FileName`  or `erase FileName`  Delete file
    - Let us say we want to get rid of a read-only or hidden file. We can do that with the `/A:` switch. /A can delete files based on a specific attribute. Let us look at the help for del quickly and see what those attributes are.
- **`tasklist` ⇒ `top` in Linux**
- **`taskkill ID` ⇒ `kill ID`**
- **`ipconfig` network configuration ⇒ `ifconfig, iwconfig`**
- **`netstat`**
- **`tree`**
- **`tracert`  = `traceroute` in Linux**
- **`net user username /add` (user or users in any command) 
`net user username password /add || net user username * /add`**
- **`net user username /delete`**
- **`net user username /active:no` or `yes`**
- **`net localgroup`   shows all the groups**
- **`net localgroup group_name` to show the members of group_name**
- **`net localgroup group_name /add`  or  `/del`**
- **`net localgroup group_name new_user /add`  or  `/del`**
- **`runas /user:<username> <command>` like cmd.exe, GUI ⇒ shift and right click you will find run as a different user**
    - **`/netonly` credentials are for remote access only**

![Windows%20Command%20line%204c254b20b87b4486a6dfe399121daf14/DA4AFC82-4237-4FC6-936D-7ED38C657E98.png.jpg](Windows%20Command%20line%204c254b20b87b4486a6dfe399121daf14/DA4AFC82-4237-4FC6-936D-7ED38C657E98.png.jpg)

- mimikatz
**is a tool to get back clear text credentials (passwords) from memory without cracking, Microsoft added protections but mimikztz still working (:**

---