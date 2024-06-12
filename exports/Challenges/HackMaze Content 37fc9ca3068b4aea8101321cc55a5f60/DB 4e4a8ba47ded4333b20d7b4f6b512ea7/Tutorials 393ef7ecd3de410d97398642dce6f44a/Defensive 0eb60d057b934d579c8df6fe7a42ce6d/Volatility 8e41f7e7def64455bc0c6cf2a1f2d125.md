# Volatility

# memory forensics

Basically there is 2 types of data 

1. **Volatile data:** refers to information that exists only temporarily in a computer's memory (RAM) or CPU registers
2.  **Non-volatile data:** refers to information that is stored persistently on storage media, such as hard drives, SSDs, or other non-volatile memory devices.

Memory forensics is the process of capturing and analyzing the volatile data residing in a computer's Random Access Memory (RAM). This data, unlike information stored on a hard drive, is temporary and disappears when the computer is powered down. 

Memory forensics is particularly valuable in investigating advanced and stealthy threats, such as rootkits, memory-resident malware, and fileless attacks. Because volatile memory is overwritten when the system is powered off or rebooted, memory forensics requires a timely response to capture and preserve critical evidence.

**why memory forensics**

1. Memory forensics acts like a live feed of a computer's activity. Investigators can analyze what's happening right now, providing crucial insights into ongoing incidents.
2. Traditional security solutions might miss cleverly disguised criminals. Memory forensics acts like a detective with a keen eye, spotting hidden malware and  rootkits
3. It captures volatile data such as encryption keys and passwords, which are lost when the system is powered off.
4. During a security incident, time is of the essence. Memory forensics helps investigators quickly identify the culprit and take swift action to contain the damage.
5. It contributes to threat intelligence efforts by uncovering attack patterns and tactics, aiding in attribution of attacks to specific threat actors.

# volatility framework

> In 2007, the first version of  “The Volatility Framework”  was released publicly at Black Hat DC.  Volatility is now the world’s most widely used memory forensics platform, which is supported by one of the largest and most active communities in the forensics industry.
> 

***volatility foundation***

The Volatility Framework is a collection of tools and libraries designed to extract and analyze data from volatile memory dumps..

For Windows environments, Volatility boasts compatibility with all major 32- and 64-bit versions, including XP, 2003 Server, Vista, Server 2008, Server 2008 R2, Seven, 8, 8.1, Server 2012, and 2012 R2. Whether your memory dump comes in raw format, a Microsoft crash dump, hibernation file, or virtual machine snapshot, Volatility seamlessly handles it, ensuring no data is left unexamined.

Volatility is able to work with it. We also now support Linux memory dumps in raw or LiME format and include 35+ plugins for analyzing 32- and 64-bit Linux kernels from 2.6.11 - 3.16 and distributions such as Debian, Ubuntu, OpenSuSE, Fedora, CentOS, and Mandrake. 

Additionally, Volatility doesn't overlook macOS environments, offering compatibility with 38 versions of Mac OSX memory dumps from 10.5 to 10.9.4 Mavericks, covering both 32- and 64-bit architectures. 

Volatility is highly extensible, allowing analysts to develop custom plugins to extract specific information or perform specialized analyses.

***NOTE:*** there is different versions of volatility***,*** volatility 2 and volatility 3 

| Volatility 2 | Volatility 3 |
| --- | --- |
| -p $PID | --pid $PID |
| -D $dump_Directory | --dump |
| --profile=profile plugin_name | profile.plugin |
| Example: --profile=WinXPSP2x86 pstree | Example: windows.pstree |
| volatility -f $file --profile=WinXPSP2x86 -p $PID -D dump_directory memdump | volatility -f $file -o $output_file windows.memmap --dump --pid $PID |
| has more plugins than 3 | less plugins but is being developed  |

lets explore the most important plugins in volatility specifically for windows

# Installing Volatility

make sure that you have [**python**](https://www.python.org/downloads/) installed on your machine

**Download volatility3 form [here](https://github.com/volatilityfoundation/volatility)** (we will focus on volatility 3 but will give some information about volatility 2)

```bash
git clone https://github.com/volatilityfoundation/volatility3
cd volatility3 
pip3 install -r requirements-minimal.txt
python3 setup.py build 
python3 setup.py install
```

Running volatility 3 

```bash
python3 vol.py -h
```

you can create alias of of **`python3 vol.py`**  with **`vol3`**  by writing ** `echo "alias vol3='python3 $(pwd)/vol.py'" | sudo tee /etc/zsh/zshrc`**  in your zsh shell

installing volatility 2 

```bash
wget http://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6_lin64_standalone.zip 
unzip volatility_2.6_lin64_standalone.zip
sudo mv volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone /usr/bin/vol2
sudo chmod +x /usr/bin/vol2 
rm -rf volatility_2.6_lin64_standalone.zip volatility_2.6_lin64_standalone
```

# imageinfo

This information includes details about the memory dump itself, such as the operating system, architecture, and version, as well as the type of memory image and any additional metadata.  

is **`imageinfo`**, which provides a high-level summary of the memory sample you’re analyzing. 

**NOTE**: imageinfo is not always correct and can have varied results depending on the provided dump; use with caution and test multiple profiles from the provided list.

```bash
python3 vol.py -f $file windows.info
```

The logic that **`imageinfo`**used to  guess profiles is actually based on the functionality provided by  another  plugin **`kdbgscan`**  which is used to find and parse the debugger data block

**You may ask what is the profile and why may i  need it?**

 When you acquire a memory dump (a snapshot of a computer's RAM), you get a vast amount of data, but it's essentially encoded in the language of the specific operating system (OS) that was running. This is where the memory profile steps in. It acts like a decoder ring, specifically designed for a particular OS version (like Windows 10 x64 or Linux Ubuntu 20.04). It tells Volatility how to interpret the data structures and layouts within the memory dump

In other word we need to know the structures of the memory dump to know how to deal with it 

When you run **`windows.pslist`** in Volatility 3, the framework internally analyzes the memory dump to identify the appropriate profile for the target system. It then applies the detected profile to interpret the memory dump and extract information about running processes. However, if you prefer to specify the profile manually for any reason, Volatility 3 still allows you to do so using the **`--profile`** option. For example:

```bash
python3 vol.py --profile=$profile -f $file
```

**When did the provided memory image acquired?**  

2024-04-19 22:13:51

# processes, Dlls and Handles

### processes

Their is a few plugins that are used for dealing with the processes:

**`pslist`** lists the running processes present in the memory dump, providing details such as process ID (PID), parent process ID (PPID), process name, and process start time.

```bash
python3 vol.py -f $file windows.pslist
```

The **`pstree`** plugin is used to visualize the process hierarchy present in the memory dump.  It Show processes in parent/child tree

```bash
python3 vol.py -f $file windows.pstree
```

In Volatility 3, the **`psscan`** plugin is used to scan the memory dump for process objects and list them along with their metadata.

```bash
python3 vol.py -f $file windows.psscan
```

- **`pslist`** finds and walks the doubly linked list of processes and prints a summary of the data. This method typically cannot show you terminated or hidden processes.
- **`pstree`** takes the output from pslist and formats it in a tree view, so you can easily see parent and child relationships.
- **`psscan`** scans for _EPROCESS objects instead of relying on the linked list. This plugin can also find terminated and unlinked (hidden) processes.
- **`psxview`**  (only in volatility 2 )locates processes using alternate process listings, so you can then cross-reference different sources of information and reveal malicious discrepancies.

dumping processes 

To dump a specific process 

```bash
python3 vol.py -f $file -o $dumpdir windows.dumpfiles ‑‑pid $PID
```

### Dlls

DLL stands for **Dynamic-link library**. In the world of Windows (and other operating systems like OS/2), DLLs are like shared toolboxes filled with reusable code and data instead of writing the code multiple times. For listing dlls use **`dlllist`** 

```bash
python3 vol.py -f $file windows.dlllist
```

### Handles

at first we have to know what handles  are.  When a program needs to interact with a resource, like opening a file or accessing a network connection, it doesn't directly deal with the resource's location or internal details. Instead, it requests the operating system for a handle.

so we have to know what are the handles used by a process. fortunately volatility  provides a plugin for that 

```bash
python3 vol.py -f $file windows.handles ‑‑pid $PID
```

**Q2: How many  process on the device?**

148

**Q3:  How many dlls related to  explorer.exe**

297

# Network connection

**`netstat`  and `netscan`** meticulously scans the memory dump, searching for evidence of network connections that were active or established at the time the dump was acquired.
For each connection, they offers valuable details like:

- Local and remote IP addresses (if applicable)
- Local and remote ports
- The time the connection was established or bound
- The current state of the connection (e.g., listening, established)

```bash
python3 vol.py -f $file windows.netstat
python3 vol.py -f $file windows.netscan
```

Q4: what is the IP of the machine?

192.168.56.1

# Files in memory

for listing all the files in memory **`filescan`**  plugin comes in, this powerful plugin is used to list all the currently files exists in memory

```bash
python3 vol.py -f $file windows.filescan
```

for dumping a file from memory **`dumpfiles`**  is used you can dump by providing the the physical address or the virtual address

```bash
python3 vol.py -f $file -o $dumpdir windows.dumpfiles
python3 vol.py -f $file -o $dumpdir windows.dumpfiles ‑‑virtaddr $offset
python3 vol.py -f $file -o $dumpdir windows.dumpfiles ‑‑physaddr $offset
```

files loaded from the malware, you can provide the PID of the malicious process and then dump those files

```bash
python3 vol.py -f $file -o $output_file windows.filescan --pid $PID
```

**Q5: what is the offset of file $TxfLog.blf**

0xda09497b0910

# Users and Passwords

during the forensics investigations you may need to get the user password hashes from memory for several reasons 

```bash
python3 vol.py -f $file windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
python3 vol.py -f $file windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
python3 vol.py -f $file windows.lsadump.Lsadump #Grab lsa secrets
```

# Windows Registry

The Windows Registry is a vast and hierarchical database that stores low-level settings for the Microsoft Windows operating system and for applications that choose to use it. Imagine it as a central control panel for Windows, dictating everything from how hardware interacts with software to user preferences.

such information is completely important within investigations. volatility provides plugins for dealing with registry such as **`hivescan`**  which is used for listing registry hives in memory and **`printkey`**  List roots and get initial subkeys

```bash
python3 vol.py -f $file windows.registry.hivescan
python3 vol.py -f $file windows.registry.printkey
python3 vol.py -f $file windows.registry.printkey ‑‑key “Software\Microsoft\Windows\CurrentVersion”
```

**Windows** keeps track of programs you run using a feature in the registry called **UserAssist keys**. These keys record a very important information such as how many times each program is executed and when it was last run.

```bash
python3 vol.py -f $file windows.registry.userassist
```

# Useful Plugins during hunting malwares and malicious activities

**`malfind`**  is one of the most helpful plugins when dealing with a malware. according to he docs “ it Lists process memory ranges that potentially contain injected code.” so at some cases that plugin can be great in investigations 

```bash
python3 vol.py -f $file windows.malfind
```

### SSDT

The System Service Descriptor Table (SSDT) is a critical internal data structure within the Windows kernel. It acts like a phonebook for the kernel, storing pointers to the actual locations of system service routines. When a program makes a system call (requests a specific service from the kernel), the kernel consults the SSDT to find the appropriate routine to handle that call.

**How it is manipulated by malwares:**

 Malicious software can exploit a technique called hooking to manipulate the SSDT. Hooking essentially involves replacing the legitimate pointers in the SSDT with pointers to the malware's own code. To check SSDT use **`ssdt`**  within volatility

```bash
python3 vol.py -f $file windows.ssdt
```

### modules

Adversaries will also use malicious driver files as part of their evasion. Volatility offers two plugins to list drivers. The `modules` plugin will dump a list of loaded kernel modules; this can be useful in identifying active malware. However, if a malicious file is idly waiting or hidden, this plugin may miss it.

```bash
python3 vol.py -f $file windows.modules
```

### **driverscan**

- The **`driverscan`** plugin will scan for drivers present on the system at the time of extraction. This plugin can help to identify driver files in the kernel that the modules plugin might have missed or were hidden.

```bash
python3 vol.py -f $file windows.driverscan
```

### Mutex

Malware may use mutexes to ensure that only one instance of itself is running on the infected system at any given time. By creating a named mutex with a unique identifier, malware can check whether the mutex already exists before executing its malicious payload. If the mutex exists, it indicates that another instance of the malware is already running, so the new instance may terminate itself to avoid detection or interference.

```bash
python3 vol.py -f $file windows.mutantscan
```

# Misc

Here we will list important plugins that shows the power of volatility framework and how it can deal with most of the cases in forensics investigation

### **CMD**

Lists process command line arguments

```bash
python3 vol.py -f $file windows.cmdline
```

### Environment variables

 Environment variables in computing are dynamic named values that contain information about the operating system's environment. They are used by the system and applications to customize behavior, configure settings, and provide information about the current environment. volatility get that by plugin **`envars`**

```bash
python3 vol.py -f $file windows.envars 
python3 vol.py -f $file windows.envars --pid $PID
```

### **Token privileges**

Check for privileges tokens in unexpected services. It could be interesting to list the processes using some privileged token.

```bash
python3 vol.py -f $file windows.privileges.Privs --pid $PID
python3 vol.py -f $file windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```

### **Yara Rules**

It also allows to search for strings inside a process using the **`yarascan`  or  `vadyarascan`**:

```bash
python3 vol.py -f $file yarascan.YaraScan --yara-rules $string
python3 vol.py -f $file windows.vadyarascan --yara-rules $string --pid $PID
python3 vol.py -f $file windows.vadyarascan ‑‑yara-file $yarafile
```

**what is the number of processors?**

4

# volatility limitations

While the Volatility Framework is a powerful and versatile tool for memory forensics, it does have some limitations

1. Volatility does not acquire memory from target systems.
2. Volatility is a command line tool and a Python library that you can import from your own applications, but it does not include a front-end.
3. Volatility might require additional tools or expertise to crack such encryption and reveal the hidden secrets.

Despite these limitations, the Volatility Framework remains a valuable tool.  By understanding its strengths and weaknesses, investigators can leverage it effectively to uncover hidden evidence and conduct thorough digital investigations and till now we just covered some of the plugins of that great tool.