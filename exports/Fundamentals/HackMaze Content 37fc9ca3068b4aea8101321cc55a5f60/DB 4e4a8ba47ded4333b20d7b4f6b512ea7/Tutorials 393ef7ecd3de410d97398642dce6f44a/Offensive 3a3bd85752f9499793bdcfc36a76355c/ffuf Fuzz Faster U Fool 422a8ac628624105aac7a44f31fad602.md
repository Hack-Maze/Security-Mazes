# ffuf: Fuzz Faster U Fool

- **Minimum arguments.**
    
    ```bash
    ffuf -u '**URL**/**FUZZ'** -w **WORDLIST** 
    ```
    

- **Custom Keyword**
    
    ```bash
    ffuf -u '**URL**/?username=**bruteForcing'** -w **WORDLIST:brute-forcing**
    ```
    
- **Fuzzing Extension**
    
    ```bash
    ffuf -u 'http://URL/index**FUZZ'** -w **/usr/share/seclists/Discovery/Web-Content/web-extensions.txt # .asp .html .php .css etc.**
    ```
    
- **Fuzzing With Specific Extensions**
    
    ```bash
    ffuf -u 'http://**IP**/**FUZZ'** -w **WORDLIST** -e **.php,.txt, .html, .js, .bak, .conf**
    ```
    

---

---

# Filter/Matching Options: `-%[options]`  % refers to Filter or Matching

- **Example `-fc` Filter Code, `-mc` Match Code**

### **`-%c`  status Code**

### **`-%l`   number of Lines**

### **`-%r`   Regex**

### **`-%s`   Size**

### **`-%t`   Time**

### **`-%w`   Words**

---

---

# Fuzzing Parameters

> What would you do when you find a page or API endpoint but don't know which parameters are accepted? You fuzz!
> 

> Discovering a vulnerable parameter could lead to file inclusion, path disclosure, XSS, SQL injection, or even command injection. Since ffuf allows you to put the keyword anywhere we can use it to fuzz for parameters.
> 
- **Fuzzing Parameter Name**
    
    ```bash
    ffuf -u 'http://URL/sqli-labs/Less-1/?**FUZZ**=1' -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fw 39
    ```
    
- **Fuzzing Parameter Value**
    
    ```bash
    for i in {0..255}; do echo $i; done | ffuf -u 'http://10.10.4.141/sqli-labs/Less-1/?id=FUZZ' -c -w - -fw 33
    ```
    
- **Password brute-force**
    
    ```bash
    ffuf -u URL -c -w WORDLIST -X POST -d 'uname=Dummy&passwd=**FUZZ**&submit=Submit' -fs 1435 -H 'Content-Type: application/x-www-form-urlencoded'
    ```
    

---

---

# Subdomain Enumeration

- **Subdomain Enumeration**
    
    ```bash
    ffuf -u 'http://**FUZZ**.mydomain.com' -c -w **/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt**
    ```
    
- **VHosts Enumeration**
    
    ```bash
    ffuf -u 'http://mydomain.com' -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: **FUZZ**.mydomain.com' -fs 0
    ```
    

> Some subdomains might not be resolvable by the DNS server you're using and are only resolvable from within the target's local network by their private DNS servers. So some virtual hosts (vhosts) may exist with private subdomains so the previous command doesn't find them. **To try finding private subdomains we'll have to use the Host HTTP header as these requests might be accepted by the web server.**
> 

> **Note**: [virtual hosts](https://httpd.apache.org/docs/2.4/en/vhosts/examples.html) (vhosts) is the name used by Apache HTTPd but for Nginx, the right term is [Server Blocks](https://www.nginx.com/resources/wiki/start/topics/examples/server_blocks/)
> 

---

---

# Proxy

```bash
ffuf -u 'http://URL/' -c -w **WORDLIST** **-replay-proxy** **http://127.0.0.1:8080**
```

---

---

# Various Options

### `-ic`  Ignore wordlist Comments

### `-of md -o Name.md`  Output Format, Output File Name

### `-r`  Follow Redirection (Default: False)

### `-c` Colorize output

---

---