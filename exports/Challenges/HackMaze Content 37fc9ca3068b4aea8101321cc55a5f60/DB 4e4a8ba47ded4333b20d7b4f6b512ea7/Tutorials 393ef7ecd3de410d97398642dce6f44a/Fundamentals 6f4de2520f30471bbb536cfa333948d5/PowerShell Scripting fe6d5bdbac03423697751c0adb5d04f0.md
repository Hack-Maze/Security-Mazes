# PowerShell Scripting

- PowerShell is the Windows Scripting Language and shell environment built using the **.NET** framework.
- Most PowerShell commands, called ***cmdlets**,* are written in .NET.
- Unlike other scripting languages and shell environments, the output of these *cmdlets* are objects - making PowerShell somewhat **object-oriented**.
- The normal format of a *cmdlet* is represented using **Verb-Noun**; for example, the *cmdlet* to list commands is called **`Get-Command`**
- The most important 2 commands are **`Get-Help`** and **`Get-Command`**
- **`Get-Help <CmdletName> -Online`** displays the online documentation for the specified cmdlet or topic.
- PowerShell scripts usually have the ***.ps1*** file extension.

```powershell
#Common verbs to use include:
Get
Start
Stop 
Read
Write
New
Out
```

| Command alias | Cmdlet name | Description of command | Examples |
| --- | --- | --- | --- |
| shcm | Show-Command | Creates Windows PowerShell commands in a graphical command window. |  |
| ac | Add-Content | Appends content, such as words or data, to a file. | Add-Content -Path "C:\dir\test.txt" -Value "written in powershell” |
| cat, gc, type | Get-Content | Gets the contents of a file. | Get-Content -Path "C:\Users\UN\Desktop\test.txt” |
| sc | Set-Content  | Replaces the contents of a file with contents that you specify. | Set-Content .\test.txt "new content” |
| echo, write | Write-Output | Sends the specified objects to the next command in the pipeline. If the command is the last command in the pipeline, the objects are displayed in the console. | Write-Output "This is some text." |
| cd, chdir | Set-Location | Sets the current working location to a specified location. | Set-Location -Path "C:\DirectoryName” |
| gl, pwd | Get-Location | Gets information about the current working location or a location stack. | Get-Location -Provider Registry  #provider that defines the location |
|  ni | New-Item | Creates a new item file or folder | New-Item -Path "C:\path\to\newfile.txt" -ItemType "File” |
| clc | Clear-Content | Deletes the contents of an item, but does not delete the item. | Clear-Content -Path "C:\dir\test.txt”  #test.txt still exists |
| del, ri, rm, rmdir
 erase, rd | Remove-Item | Deletes files and folders. | Remove-Item -Path  “C:\path\to\item” |
| dir, gci , ls | Get-ChildItem | Gets the files and folders in a file system drive. | Get-ChildItem -Path "C:\MyFolder" -Hidden  || -Recurse  #list directories and subdirectories ||  -SortBY   sort based on a specific criteria || -Filter D*   #list directories starts with D || -System  #get system files |
| fl | Format-List | Formats the output as a list of properties in which each property appears on a new line. | Get-Process -Name "explorer" | Format-List -Property Name, Id, StartTime || -GroupBy <string> #group output by specific property  |
| fw | Format-Wide | Formats objects as a wide table that displays only one property of each object. | Get-Process | Format-Wide -Property Name -Column 4 #format the output in a wide table format |
| ft | Format-Table | Formats the output as a table. | Get-Process | Format-Table -Property Name, Id, CPU, WorkingSet  |
| measure | Measure-Object | Calculates the numeric properties of objects, and the characters, words, and lines in string objects, such as files of text. | @(75, 89, 62, 95, 82) | Measure-Object -Minimum -Maximum   |
|  ghy, h | Get-History | Gets a list of the commands entered during the current session.  | Get-History  | | Get-History -Id 5 # get command by id || Get-History -Count 10 #the last 10 commands  |
| clhy | Clear-History | Deletes entries from the command history. | Clear-History ||  Clear-History -Id 10 #clear a specific command with id 10 |
| cls | Clear-Host | Clears the display in the host program. | Clear-Host |
| copy | Copy-Item | Copies an item from one location to another. | Copy-Item -Path .\test.txt -Destination path\to\destination  || Copy-Item -Path "C:\Source\*" -Destination "D:\Destination\" -Exclude *.doc "   # exclude all doc files ||  -Include *.txt   #copy  txt files only |
| move, mi , mv  | Move-Item | Moves an item from one location to another. | Move-Item -Path "C:\Source\ReadOnlyFile.txt" -Destination "D:\Destination" -Force #allows you to move a read-only file without any restrictions. |
| ren | Rename-Item | Renames an item in a Windows PowerShell provider namespace. | Rename-Item -Path "C:\path\to\oldfile.txt" -NewName "newfile.txt” || -Force #rename items that are read-only or hidden.  |
| select | Select-Object | Selects objects or object properties. | Get-Command New-* | Select-Object CommandType #You can also use the following flags to select particular information ⇒  -first : gets the first x object || -last : gets the last x object || -unique : shows the unique objects || -skip : skips x objects |
| group | Group-Object | Groups objects that contain the same value for specified properties. | Get-ChildItem -Path "C:\Path\To\Directory" | Group-Object -Property Extension   |
| gu | Get-Unique | Returns unique items from a sorted list. | Get-Process | Sort-Object | Select-Object processname | Get-Unique -AsString |
| gps , ps | Get-Process | Gets the processes that are running on the local computer or a remote computer. | Get-Process -Name "explorer" #get process y name  || Get-Process -ComputerName “remotecomputer”  #get process on remote device |
| saps | Start-Process | Starts one or more processes on the local computer. | Start-Process notepad.exe || Start-Process -FilePath "D:\path\to\program.exe” ||  |
| kill | Stop-Process | Stops one or more running processes. | Stop-Process -Name ProcessName  || Stop-Process -Id pid |
| compare, diff | Compare-Object | Compares two sets of objects. | Compare-Object -ReferenceObject (Get-Content -Path C:\die\SrcOjb.txt) -DifferenceObject (Get-Content -Path C:\dir\DestObj.txt) |
| gi | Get-Item | Gets files and folders. | Get-Item -Path "C:\Example\Directory” |
| curl | Invoke-WebRequest | Gets content from a webpage on the Internet. | Invoke-WebRequest -Uri "https://www.example.com/"  ||  -Headers specify HTTP headers in the request || -Method specify HTTP method in request |
| icm | Invoke-Command | Runs commands on local and remote computers. | Invoke-Command -ComputerName Server1 -ScriptBlock { Get-Process } -AsJob |
| ihy | Invoke-History | Runs commands from the session history. | Invoke-History -Id 2 || Invoke-History -Id 5 -ErrorAction "Stop” #stops if error happen while execution |
| ii | Invoke-Item | Performs the default action on the specified item. | Invoke-Item -Path "C:\Path\To\File.txt” #invoke (open) file.txt |
| nal | New-Alias | Creates a new alias. | New-Alias -Name "ls" -Value "Get-ChildItem" #create alias ls for Get-ChildItem || -Force #to allow alias creation even if an alias with the same name exist  |
| epal | Export-Alias | Exports information about currently defined aliases to a file. | Export-Alias -Path "C:\path\to\alias_definitions.txt" |
| ipal | Import-Alias | Imports an alias list from a file. | Import-AliasFromFile -FilePath "C:\path\to\alias_definitions.txt” ||  |
| sal | Set-Alias | Creates or changes an alias (alternate name) for a cmdlet or other command element in the current Windows PowerShell session. | Set-Alias -Name "globalAlias" -Value Get-Command -Option AllScope #create a global alias accessible in all sessions |
| ogv | Out-GridView | Sends output to an interactive table in a separate window. | Get-Process | Out-GridView -Title "Running Processes” |
| gal | Get-Alias | Gets the aliases for the current session. | Get-Alias | Export-Csv -Path "C:\path\to\potput\alias_list.csv” #export the list of aliases to a csv file |
| epcsv | Export-Csv | Converts objects into a series of comma-separated (CSV) strings and saves the strings in a CSV file. | Get-Alias | Export-Csv -Path "C:\path\to\potput\alias_list.csv”   |
| ipcsv | Import-Csv | Creates table-like custom objects from the items in a CSV file. | Import-Csv -Path "C:\Users\MG\Desktop\task\alias_list.csv" | Format-Table #format the output of csv in table form |
| gdr | Get-PSDrive | Gets drives in the current session. | Get-PSDrive -Persist #list persistent drives || -Name C , D #list by name |
| gjb | Get-Job | Gets Windows PowerShell background jobs that are running in the current session. | Get-Job -State Running || -Id  #get job by id |
| sajb | Start-Job | Starts a Windows PowerShell background job. | Start-Job -ScriptBlock { Get-Service | Where-Object { $_.Status -eq 'Running' } } |
| rjb | Remove-Job | Deletes a Windows PowerShell background job. | Remove-Job -Id 1, 2, 3 |
| rujb | Resume-Job | Restarts a suspended job | Resume-Job -Job (Get-Job -Id 1) |
| gp | Get-ItemProperty | Gets the properties of a specified item. | Get-ItemProperty -Path "HKLM:\Software\SomeKey" |
|  cpp | Copy-ItemProperty | Copies a property and value from a specified location to another location. | Copy-ItemProperty -Path "MyApplication" -Destination "HKLM:\Software\MyApplicationRev2" -Name "MyProperty” |
| rp | Remove-ItemProperty | remove a property from an item (usually a registry key or a file system item) | Remove-ItemProperty -Path "HKLM:\Software\MyApp" -Name "ExampleProperty" |
| sp | Set-ItemProperty | modify the attributes and values associated with an item. | Set-ItemProperty -Path "C:\Path\To\File.txt" -Name "Attributes" -Value "ReadOnly” |
|  sasv | Start-Service | Starts one or more stopped services. | Start-Service -Name "Spooler"  ||   -ComputerName "RemoteComputer” #start process on remote computer || |
| spsv | Stop-Service | stop one or more services on a local or remote computer. | Stop-Service -Name "Spooler", "W32Time” |
| gsv | Get-Service | Gets the services on a local or remote computer. | Get-Service -Name "wuauserv" | Format-List * |
|  gsn | Get-PSSession | Gets the Windows PowerShell sessions on local and remote computers. | Get-PSSession -ComputerName "RemoteComputer”  |
| ipmo | Import-Module | Adds modules to the current session. | Import-Module -Name "MyModule” |
| ise | powershell_ise.exe | Explains how to use the PowerShell_ISE.exe command-line tool. | powershell_ise.exe #(GUI) application provided by Microsoft for scripting and automating tasks using PowerShell. |
| mount, ndr | New-PSDrive | Creates temporary and persistent mapped network drives. | New-PSDrive -Name "Z" -PSProvider FileSystem -Root "\\Server\Share" -Persist -Credential $credential # root Specifies the root path or location of the drive , -Presist Indicates whether the drive should persist across PowerShell sessions |
| rdr | Remove-PSDrive | Deletes temporary Windows PowerShell drives and disconnects mapped network drives. | Remove-PSDrive -Name "Z" |
| nsn | New-PSSession | Creates a persistent connection to a local or remote computer. |  New-PSSession -ComputerName "RemoteServer" -Credential $credential |
| none | Get-EventLog | retrieve entries from the Windows event logs on a local or remote computer. | Get-EventLog -LogName "Application" -Newest 10 || -UserName filter by username || -MachineName  #Specifies the name of the remote computer from which to retrieve event log entries |
| none | Get-NetAdapter | retrieve information about network adapters | Get-NetAdapter -Name "Ethernet" |
| none | Get-NetIPAddress | retrieve IP address information | Get-NetIPAddress -AddressFamily IPv4  || Get-NetIPAddress -InterfaceAlias "Ethernet”  #retrieve IP addresses associated with a specific network interface || -IPAddress  #IP addresses matching a specific IP |
| none | Get-FileHash  | Find file hash | Get-FileHash -Algorithm MD5-path path/to/file |
| none | GEt-NetTCPConnection | used to retrieve information about active TCP connections on computer | Get-NetTCPConnection -State Established |
| glu | Get-LocalUser | retrieve information about local user accounts | Get-LocalUser -Name "JohnDoe” || Get-LocalUser -AccountNeverExpires ||  Get-LocalUser -Group "Administrators”   ||-SID # find user with his sid |
| nlu | New-LocalUser | Creates a new local user account on the computer. | New-LocalUser -Name "Username" -Password "Password” |
| rlu | Remove-LocalUser | Deletes a local user account from the computer. | Remove-LocalUser -Name "Username" |
| slu | Set-LocalUser | Modifies properties of a local user account | Set-LocalUser -Name "Username" -PasswordNeverExpires $true |
| glg | Get-LocalGroup | Retrieves information about local groups on the computer. | Get-LocalGroup |
| nlg | New-LocalGroup | Creates a new local group on the computer. | New-LocalGroup -Name "GroupName” |
| algm | Add-LocalGroupMember | Adds a user or another group to a local group on the computer. | Add-LocalGroupMember -Group "GroupName" -Member "Username” |
| none | Get-ScheduleTask | retrieve information about scheduled tasks | Get-ScheduleTask -TaskName new-sched-task || -User "Administrator” #filter tasks by user ||-TriggerType Daily #filter by triagged type  |
| none | Get-Acl | retrieve the access control list (ACL) of a file, folder, or other system objects | Get-Acl -Path "HKLM:\SOFTWARE\MyApp”  |

# PowerShell scripting

## Commenting and Documentation

- In PowerShell, comments are denoted by the **`#`** (hash) symbol.
- Documentation can be provided as comments within your script or module, but it's often more structured and included in separate files or formats like Markdown, HTML, or XML.
- **`<# ... #>`** is commonly used for documentation in PowerShell scripts and functions.

## **System Environment Variables**

- Environment variables store data that's used by the operating system and other programs.
- You can access environment variables in PowerShell using the **`env:`** drive.
- When you change environment variables in PowerShell, the change affects only the current session.

```powershell
ls env:\                      #list all environment variables
echo $env:USERNAME            #print username
echo $env:windir              #echo path to the Windows directory.
$env:MyVariable = "MyValue"   #sets a new environment variable.
echo $env:Path                #specify directories where executable files are located.
```

## **Variables and Data Types**

- PowerShell infers the data type based on the assigned value.
- **Data Types:** PowerShell supports various data types, including: Strings, Integers, Floats, Booleans, Arrays, Hashtable, Null.
- Get variable type `$variable.GetType()`
- PowerShell can automatically convert between data types when necessary, based on the context.

```powershell
$result = 42

$name = "Alice"
$message = "Hello, $name!"  

$IsWorking = $true
Remove-Variable name         #name is removed 
```

## **Arrays & Primitive Vs Non Primitive Data Types**

- Primitive data types represent basic, single values and are the building blocks of more complex data structures (integers, boolean, double).
- Non-primitive data types are more complex and can store multiple values(array, Hashtable, ArrayList, objects).
    - **Array(`@()`) :** An ordered collection of values, which can be of different data types.
        
        ```powershell
        $myarray = "Alice" , "Jhon" , 20 
        $myarray[1]                          #John
        $myarray.Length                      #3
        $myArray += "US"                     #Array contains "Alice" , "Jhon" , 20 , US
        $myarray[0].EndsWith("e")            #True
        $myarray.Contains("US")              #True
        ```
        
    - **Hashtable(`@{}`) :** A collection of key-value pairs.
        
        ```powershell
        $hash = @{ Number = 1; Shape = "Square"; Color = "Blue"}
        $hash["Size"] = 30                         #add Key Size with value 30
        $hash.Remove("Number")                     #remove key "Number"
        $hash.Count                                #number of key-value pairs => 3 (Number was removed)
        $hash.ContainsKey("Shape")                 #check if it contains a key called Shape => True
        $hash.ContainsValue("Green")               #check if it contains a value Green => False
        ```
        
    - **ArrayList :** A dynamic array that can grow or shrink in size.
        
        ```powershell
        $myArrayList = New-Object System.Collections.ArrayList     #create an ArrayList
        $myArrayList.Add("EG")                                     # arraylist contains EG
        $myArrayList.Insert(0, "SU")                               #SU inserted at index 0 => SU , EG
        $myArrayList.Sort()                                        #sort arraylist => EG , SU
        $myArrayList.Remove("SU")                                  #SU is removed                                       
        $myArrayList.Clear()                                       # clear arraylist
        ```
        
    
    ## Operators in PowerShell
    
    **Arithmetic Operators:**
    
    1. **`+`** (Addition)
    2. `-` (Subtraction)
    3. `*` (Multiplication)
    4. **`/`** (Division)
    5. **`%`** (Modulus)
    6. **`++`** (Increment)
    7. **`-`** (Decrement)
    
    **Comparison Operators:**
    
    1. `-**eq**` (Equal)
    2. `-**ne**` (Not Equal)
    3. `-**gt**` (Greater Than)
    4. `-**lt**` (Less Than)
    5. `-**ge**` (Greater Than or Equal)
    6. `-**le**` (Less Than or Equal)
    7. **`-like`** (compares a test string)
    8. **`-match`** (pattern matching)
    
    **Logical Operators:**
    
    1. `-**and**` (Logical AND): Returns true if both conditions are true.
    2. `-**or**` (Logical OR): Returns true if at least one condition is true.
    3. `-**not**` (Logical NOT): Negates a condition, converting true to false and vice versa.
    4. `-**xor**` (Logical XOR): Returns true if one condition is true and the other is false.
    
    **Special Operators:**
    
    1. **`.`** (Dot Operator): Accesses properties and methods of objects.
    2. **`::`** (Static Member Operator): Accesses static properties and methods of classes.
    3. **`|`** (Pipeline Operator): Passes objects from one command to another.
    4. **`?`** (Where-Object Operator): Filters objects based on a condition.
    
    **Assignment Operators:** Perform operation and assign the result to variable 
    
    1. **`==`** (Assignment) 
    2. **`+=`** (Addition Assignment)
    3. `-**=**` (Subtraction Assignment)
    4. **`*=`** (Multiplication Assignment)
    5. **`/=`** (Division Assignment)
    6. **`%=`** (Modulus Assignment)
    
    ## **Redirection, Split and Join Operators**
    
    **`>`** Redirection Operator
    
    **`>>`** Appending Redirection Operator
    
    **`|`** Pipeline Operator
    
    ```powershell
    Get-Process > System.txt           #redirect output of get-process to System.txt and create it if it doesn't exist
    Get-Services >> System.txt         #append the output of Get-Services to System.txt
    Get-ChildItem | Where-Object { $_.Extension -eq ".txt" } | Sort-Object Length #pass the output of one command as the input to another command.
    ```
    
     **`-join`**  is used to concatenate an array of strings into a single string
    
    `-**Split**` method is used to split a string into an array of substrings based on a specified delimiter.
    
    ## **if Statement**
    
    ```powershell
    if (condition) {
        # Code to execute when the condition is true
    }
    if (Get-LocalUser "Admin") {"I am Admin"}                #check if the current user is admin
    ```
    
    ### if …. else
    
    ```powershell
    $directoryPath = "C:\MyFolder"
    if (-not (Test-Path -Path $directoryPath -PathType Container)) {
        New-Item -Path $directoryPath -ItemType Directory
        Write-Host "Directory created: $directoryPath"
    } else {
        Write-Host "Directory already exists: $directoryPath"
    }
    ```
    
    ### if …. elseif …. else
    
    ```powershell
    $userAccessLevel = "Guest"
    if ($userAccessLevel -eq "Admin") {
        Write-Host "Welcome, Admin! You have full access."
    } elseif ($userAccessLevel -eq "Jhon") {
        Write-Host "Welcome, Jhon! You have limited access."
    } else {
        Write-Host "Access denied. You are a Guest and have restricted access."
    }
    ```
    
    ## **Switch Statement**
    
    ```powershell
    Switch (<test-expression>)
    {
        <result1-to-be-matched> {<action>}
        <result2-to-be-matched> {<action>}
    }
    
    #Example
    
    $serviceName = "wuauserv"
    
    $serviceStatus = Get-Service -Name $serviceName
    
    switch ($serviceStatus.Status) {
        "Running" {
            Write-Host "$serviceName service is currently running. Stopping it..."
            Stop-Service -Name $serviceName -Force
            Write-Host "$serviceName service has been stopped."
        }
        "Stopped" {
            Write-Host "$serviceName service is currently stopped. Starting it..."
            Start-Service -Name $serviceName
            Write-Host "$serviceName service has been started."
        }
        default {
            Write-Host "$serviceName service is in an unexpected state: $($serviceStatus.Status)."
        }
    }
    ```
    
    ## **Loop Statements**
    
    ### **While**
    
    ```powershell
    while (<condition>) {
        # Code to be executed while the condition is true
    }
    
    #Example
    $countdown = 10
    Write-Host "Starting Countdown:"
    while ($countdown -ge 0) {
        Write-Host "$countdown"
        Start-Sleep -Seconds 1  
        $countdown--
    }
    Write-Host "Countdown Complete!"
    ```
    
    ### For
    
    ```powershell
    
    for ($i = 1; $i -le 5; $i++) {
        $fileName = "file$i.txt"
        Write-Host "Creating $fileName..."
    }
    ```
    
    ### Foreach
    
    ```powershell
    
    foreach ($item in $collection) {
        # Code to execute for each item
    }
    
    #loop on each file in directory and check if extension is png print filename
    foreach ($file in Get-ChildItem) {
    if ($file.Extension -eq ".png") {$file.name} }
    ```
    
    ## **Functions in PowerShell**
    
    - created by keyword **`function`**
    - **`param`** block is used to define input parameters
    - in PowerShell the **`return`** statement to specify the value that a function should return.
    - Static Parameters: are suitable for functions where the number and type of parameters are known in advance
    - Dynamic Parameters: are useful when you want the parameter names or data types to change depending on the situation. Dynamic parameters are defined using the **`DynamicParam`**
    
    ```powershell
    function Add-Numbers {
        Param( [int]$a, [int]$b)
        $result = $a + $b
        Write-host $result
    }
    #if int is not spicified a & b will be treated as string  
    
    #CALL Function by two ways
    Add-Numbers -a 8 -b 1         
    Add-Numbers 8 1 
    
    ```
    
    ```powershell
    function Add-Numbers {
        Param( [int]$a = 5, [int]$b = 12 )
        $result = $a + $b 
        Write-host $result
    }
    ```
    
    - you can define parameters for your functions or cmdlets as **mandatory**, which means that the user must provide a value for these parameters when calling the function
        
        ```powershell
        function My-Function {
            param (
                **[Parameter(Mandatory=$true)]**
                [int] $MandatoryParameter , [Parameter ()] [int] $N
        
            )
        
         Write-Host "Mandatory parameter is $MandatoryParameter"
         Write-Host "NOT Mandatory parameter is $N " 
        }
        #If a mandatory parameter is not provided, PowerShell will prompt the user for the required input, and the command **won't execute** until the user provides the necessary values.
        ```
        
    - When you define P**osition** parameters for a function or cmdlet, you can call that function or cmdlet and provide values for those parameters in a specific order, without needing to specify parameter names.
        
        ```powershell
        function My-Function {
            param (
                [Parameter(Position=1)]
                [int] $Param1,
        
                [Parameter(Position=0)]
                [int] $Param2
            )
        #block of code  
        }
        
        #The first input you provide when calling My-Function will be assigned to $Param2 because it has a position of 0
        #the second input will be assigned to $Param1 because it has a position of 1.
        ```
        
    
    ## **Modules in PowerShell**
    
    ```powershell
    Install-Module -Name ModuleName                 #install module
    Import-Module ModuleName                        #import module in powershell
    Remove-Module ModuleName                        #remove module
    ```
    
    # Powershell ISE
    
    - built-in development environment and script editor for PowerShell on Windows operating systems.
    - It provided a graphical interface for writing, editing, and debugging PowerShell scripts and commands.