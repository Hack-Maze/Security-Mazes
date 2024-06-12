# Challenges

---

# Defensive

- template
    
    ## ⇒ challenge name
    
    - These details will be here to explain the idea of the challenge, the milestones, and anything related to the challenge, but not the details added for users
    - **challenge idea:** explain the idea of the challenge here (for us not for the solvers)
    - the following callout is a demo example (this demo simulates the room details that will be added on HackMaze):
    
    <aside>
    <img src="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" alt="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" width="40px" />  **add the name here**
    
    - **Challenge description:** add the description
    - **Author: @Nourhan**
    - **Difficulty:** easy
    - **tags:** any topic or skill in the challenge like → `volatility`, `SQLi`, `fuzzing`, `Privilege Escalation`, etc.
    </aside>
    

## ⇒ CureMem

<aside>
🔎 **CureMem:**

- **Challenge Name:** `CureMem`
- **Challenge Idea:** test basic knowledge of memory forensics like identifying the malicious process and activities related to it
- **Challenge Description**: urgent mission to hunt the evil process to heal our machine, we need your help.
- **Author**: @Nourhan
- **Difficulty**: easy
- **Tags**: **`volatility`**, **`memory`, `info stealer`**
</aside>

### Questions & Answers

- Q: When was memory image captured?

```jsx
Ans: 2023-11-01 08:22:13
Format : **23-**-** **:*2:**
Points: 50
```

---

- Q: what is the malicious process?

```jsx
Ans: Healer.exe
Format: ******.***
Points: 100
```

---

- Q: What is the parent PID of the malicious Process?

```jsx
Ans: 4404
Format: ****
points: 100
```

---

- Q: When was the process started?

```jsx
Ans: 2023-11-01 00:08:21
Format: ****-**-** **:**:**
Points: 100
```

---

- Q: what is the attacker's C2 server

```jsx
Ans: 109.107.182.9
Format: ***.***.***.*
Points: 100
```

---

- Q: From where is the attack(City)

```jsx
Ans: Helsinki
Points: 100
```

---

- Q: What is the MD hash of that process?

```jsx
Ans: 4282f2127d9a2dd671b58e737c8fc351
Format: *********************************
points: 100
```

---

- Q: What is the location of that process?

```jsx
Ans: C:\\Users\\hazel\\Downloads\\Healer.exe
Format: *:\\*****\\*****\\********\\******.***
Points: 100
```

---

- Q: to which malware family does this malware belong?

```jsx
Ans: RiseProStealer
Format: **************
Points: 150
```

---

- Q: What is the Mitre Att&ck id of the technique the malware use for persistence

```jsx
Ans: T1053.005
Format: T****.***
Points: 150
```

---

---

## ⇒ Master

<aside>
🔎 **Master:**

- **challenge name**: `Master`
- **challenge idea**: investigate in windows disk image analyzing the most important parts of system such as registry, mft records, prefetch files and some browser files
- **Challenge description:** Hazel, a fellow cybersecurity enthusiast, has provided you with her disk image, daring you to uncover as much as possible about her. This is our way of having fun. Do you want to join in?
- **Author**: Nourhan
- **Difficulty**: Medium
- **Tags**: **`windows`** , **`registry`** , **`disk` , `file system`**
</aside>

### Questions & Answers

1 - what is the wallpaper

```jsx
ANS: itatchi.png
walkthrough : C:\\Users\\Username\\AppData\\Roaming\\Microsoft\\Windows\\Themes\\Tr```
anscodedWallpaper.jpg
```

2- how many did nmap run

```jsx
ANS: 5
walkthrough: prefetch file of nmap
```

3- what is the os you are working on

```jsx
ANS: windows 10 pro
walkthrough: software\\microsoft\\windows nt\\currentversion

```

4- when was the OS installed

```jsx
2023-10-26 19:44:54
walkthrough: software\\microsoft\\windows nt\\currentversion
```

5- How Many used languages on that machine

```jsx
ANS: 1
```

6- what is the targeted domain of nmap

```jsx
ans: nmap.org
walkthrough: open db of nmap
```

7- hazel had a tool for network sniffing what is that tool?

```jsx
ANS: wireshark
walkthrough: windows\\appcomapt\\install
```

8- what is the default web browser

```jsx
ANS: IE explorer
walkthrough: SOFTWARE\\Classes\\http\\shell\\open\\command
```

9- what is machine's name

```jsx
Ans : 6.3
walkthrogh: SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion
```

10- How many run once softwares

```jsx
ANS: 0
Walkthrogh:SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce
```

11- is Windows defender enabled? yay/nay

```jsx
ANS: yay
walkthrough: SOFTWARE\\Microsoft\\Windows Defender\\isservicerunning
```

12- what is machine's ip address

```jsx
ANS: 192.168.227.132
walkthrough: SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces
```

13- what is hazel's SID

```jsx
ans: S-1-5-21-791701653-437797070-2611115619-1001
```

14- I believe there is a way to find hazel's usb serial number

```jsx
Ans: 30c5d09c
walkthrough:SYSTEM\\ControlSet001\\Enum\\USB
```

15- what is her password

```jsx
ans: 2024
walkthrough: impacket-secretsdump -sam SAM -system SYSTEM LOCAL thn crack the hash
```

15- how many commands did hazel write

```jsx
ANS: 18
```

16- hazel created a text file to write her secrets i know she have put a link to that file somewhere what is the file name

```jsx
ans: my_s3cr3ts
walkthrouh: mft record
```

17- what is the email address that hazel used to get her encryption key

```jsx
ans: hazelgrace2090@gmail.com
```

18- what is hazel's university

```jsx
ans: new york univesrity
walkthrough: the file in hazel's directory
```

19- what is the vpn hazel is using

```jsx
ans: Touch VPN
```

20- what is her github username?

```jsx
ans: H4z3lnut
walkthrough: C:\\Users\\$username\\AppData\\Local\\Google\\Chrome\\User Data\\Default
and it's the Login Data
```

---

---

## ⇒ Table’s base

<aside>
🔍 **Table’s Base:**

- **Challenge Name:** `Table's Base`
- **Challenge Idea:** Exploring MFT record and get the flag the main part is to know The information in MFT file and how it’s valuable for forensics
- **Challenge Description:** At 64cm from the table's base, look closer to know the secret
- **Author:  @Nourhan**
- **Difficulty:**  Medium
- **Tags:  `disk` , `windows` , `file system`**
</aside>

```markdown
A: HM{$MFT_1s_4_r1ch_pl4c3_f0r_F0r3ns1cs_1sn't?}
```

---

---

## ⇒ Bmo’s Dream

<aside>
🔍 **Bmo’s Dream:**

- **Challenge Name:** `Bmo's Dream`
- **Challenge Idea:** Steganography challenge that is a bout identifying the correct file type and  use steganography skills to capture the flag
- **Challenge Description:** Bmo is exploring new video game worlds and going on adventures with Finn and Jake.
- **Author**: @Nourhan
- **Difficulty:** Medium
- **Tags**: **`steganography`**
</aside>

```markdown
HM{What_an_easy_challenge_u_made_it}
```

---

---

## ⇒ Intel 101

<aside>
🔍 **Intel 101**

- **Challenge Name:** `Intel 101`
- **Challenge Idea:** Teat basic knowledge in threat intel
- **Challenge Description:** Test Your knowledge in threat intelligence to investigate in SOC environment
- **Author**: @Nourhan
- **Difficulty:** Easy
- **Tags**: **`threat intel`  , `OSINT`**
</aside>

### Questions & Answers

Q1: You found an unusual connection to a domain with IP address "201.243.132.112" what is the hostname and location of that IP?

```jsx
A: Barquisimeto, CANTV.NET
format: city, hostname
```

Q2: during your SOC shift you received an alert of URL "[http://citeceramica.com](http://citeceramica.com/)" which seems malicious what is the ip addresses associated with that domain to block

```jsx
A: 81.17.18.196, 52.222.236.60, 34.111.47.92, 23.88.66.44, 18.235.69.81
format: ip addresses in desending order
```

Q3: after receiving a report from an employee calming that his device started acting strongly after opening a doc file apparently from phishing email the hash of the file is "d37df8d48f73df5e0e3e1ee84ef00587" what is the malware family of that file and the CVE exploited

```jsx
A: AgentTesla, CVE-2017-11882, CVE-2018-0798
Format: MalFamily, CVE-0000-00000, CVE-0000-0000 
```

Q4: with the same sample you received what is the Mitter ID of the execution & Defense Evasion Technique

```jsx
A: T1203, T1112
Format: *****, *****
```

Q5: what is the malicious file may be dropped by the malware

```jsx
A:  https://vauxhall.top/error/prinsozx.scr
Format: *****://********.***/*****/********.***
```

Q6: A ransomware attack attempts to scare its victims by then displaying a screen claims that the user has committed a crime what is the extension of that ransomware

```jsx
A: .crypt
Format: .*****
```

---

---

## ⇒ Pumpkin

<aside>
🔍 **Pumpkin:**

- **Challenge Name:** `Pumpkin`
- **Challenge Idea:** Basic Steganography Challenge
- **Challenge Description:** Cut the pumpkin to get the flag :)
- **Author**: @Nourhan
- **Difficulty:** Easy
- **Tags**: **`steganography`**
</aside>

```markdown
HM{Pumpk1n_c4n_h1d3_d4t4_w1th1n!}
```

---

---

## ⇒ The Square

<aside>
🔍 **The Square:**

- **Challenge Name:** `The Square`
- **Challenge Idea:** Steganography Challenge
- **Challenge Description:** I found that painting on my friends PC but that is suspicious. He was never an art enthusiast
- **Author**: @Nourhan
- **Difficulty:** Easy
- **Tags**: **`steganography`**
</aside>

```markdown
flag format: HM{write_flag_here}
ANS: HM{we_can_meet_in_the_big_square_at_10}
```

---

---

## ⇒ grep harder (DFIR)

- **challenge name**: `grep harder` (maybe we will change it)M
- **challenge idea**: forensics challenge which can be solved manually using volatility, and automated using `flagger`, so we can show the power of `flagger`

<aside>
<img src="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" alt="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" width="40px" /> **grep harder**

- **Challenge description: not determined**
- **Authors: @Nourhan, @Juba**
- **Difficulty:** easy
- **tags: `flagger`, `volatility`, `memory forensics`, `scripting`**
</aside>

---

---

# Offensive

## ⇒ Seeker (web)

- **challenge idea:** web challenge testing user skills in discovery and recon, and why it’s very important, showing how you can attack a website without exploiting a vulnerability
- it’s preferable to make this challenge on the user's machine, make him download the `dockerfile`, and run it locally to avoid DoS

<aside>
<img src="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" alt="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" width="40px" /> **Seeker**

- **Challenge description:  `it’s not always about having a quirk`**
- **Authors: @Juba**
- **Difficulty:** easy
- **tags: `content discovery`, `recon`, `fuzzing`**
- **content**: still thinking
</aside>

## ⇒ **Le Mans (scripting, web, network)**

- **challenge idea**: scripting challenges related to cybersecurity

<aside>
<img src="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" alt="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" width="40px" /> **Le Mans**

- **challenge description: `Do you think 911 is better than M3 GTR?`**
- **Author: @Juba**
- **Difficulty**: Medium
- **tags: `scripting`, `threading`, `sockets`, `encoding`**
- content:
    - easy task:
        
        <aside>
        <img src="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" alt="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" width="40px" />
        
        </aside>
        
    - medium task
        
        <aside>
        <img src="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" alt="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" width="40px" /> catch me if you can
        
        - **Task description: the target will listen on port 9090 for 1 second and expose SSH access, can you catch that and read `/flag.txt`**
        </aside>
        
    - hard task
        
        <aside>
        <img src="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" alt="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" width="40px" /> net yet
        
        </aside>
        
</aside>

## ⇒ PyJail

- **challenge idea**: python jail escaping
- not ready yet

<aside>
<img src="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" alt="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" width="40px" /> Quest

- **challenge description: `PLACE HOLDER`**
- **Author: @Juba**
- **Difficulty**: medium
- **tags: `scripting`**
- content:
    - flag
        
        <aside>
        <img src="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" alt="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" width="40px" /> insecure file read
        flag: `HM{N0t_411_j4i1s_4r3_unbr3@k@bl3}`
        
        </aside>
        
</aside>

## ⇒ Quest (Web & Linux)

- **challenge idea**: Basic JWT attack & Linux skills

<aside>
<img src="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" alt="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" width="40px" /> Quest

- **challenge description: `PLACE HOLDER`**
- **Author: @Juba**
- **Difficulty**: easy
- **tags: `JWT`, `Linux`, `Flask`**
- content:
    - Container files
        
        [Archive.tar.gz](Challenges%204e4a7ec860114751a5ba746eb065f6e3/Archive.tar.gz)
        
    - First vulnerability
        
        <aside>
        <img src="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" alt="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" width="40px" /> JWT unverified signature
        
        </aside>
        
    - second vulnerability
        
        <aside>
        <img src="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" alt="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" width="40px" /> insecure file read
        
        </aside>
        
    - flag
        
        <aside>
        <img src="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" alt="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" width="40px" /> insecure file read
        flag: **`HackMaze{JWT_1$_Aw3s0m3_R19ht!}`**
        
        </aside>
        
</aside>

## ⇒ Lemillion

- **challenge idea**: many tar compresses, many base64 encodings

<aside>
<img src="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" alt="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" width="40px" /> Quest

- **challenge description: `Reach for the stars!`**
- **Author: @Juba**
- **Difficulty**: **easy**
- **tags: `linux`, `scripting`, `python`, `bash`, `encoding`**
- content:
    - challenge file:
        
        [lemillion](Challenges%204e4a7ec860114751a5ba746eb065f6e3/data.txt)
        
</aside>

## ⇒ Port & Starboard

- **challenge idea**: Two images with common content
    
    ![Untitled](Challenges%204e4a7ec860114751a5ba746eb065f6e3/Untitled.jpeg)
    

<aside>
<img src="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" alt="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" width="40px" /> Port & Starboard

- **challenge description: `With eerie, bent dorsal fins, two enigmatic orcas glide through South Africa's waters, shrouded in mystery and legend.`**
- **Author: @Juba**
- **Difficulty**: **easy**
- **tags: `scripting`, `diff_tools`**
- content:
    
    [Port & Starboard](Challenges%204e4a7ec860114751a5ba746eb065f6e3/Untitled.zip)
    
    - can you find Port & Starboard
        
        <aside>
        <img src="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" alt="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" width="40px" /> `HM{C4n_U_C_Z_Diff?}`
        
        </aside>
        
</aside>

## ⇒ **Phantom Messages**

- **challenge idea**: Server logs with partial message hashes.
    
    ![Untitled](Challenges%204e4a7ec860114751a5ba746eb065f6e3/Untitled%201.jpeg)
    

<aside>
<img src="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" alt="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" width="40px" /> Port & Starboard

- **challenge description: `dictionaries do not help anymore`**
- **Author: @Juba**
- **Difficulty**: **`Medium`**
- **tags: `scripting`, `hashing`**
- content:
    
    [Phantom Messages](Challenges%204e4a7ec860114751a5ba746eb065f6e3/Untitled%201.zip)
    
    - Try Harder, not just Rainbow.
    
    <aside>
    <img src="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" alt="Challenges%204e4a7ec860114751a5ba746eb065f6e3/HM.png" width="40px" /> `HM{Scr1pt1ng_1s_Y0ur_Sup3rp0w3r}`
    
    </aside>
    
</aside>