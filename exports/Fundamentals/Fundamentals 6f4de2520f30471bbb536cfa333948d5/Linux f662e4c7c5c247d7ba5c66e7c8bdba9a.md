# Linux

---

- 

[Detailed](Linux%20f662e4c7c5c247d7ba5c66e7c8bdba9a/Detailed%208cb2547b08544f0a85711b6dad732e51.md)

# Users and Groups

- Linux was designed from the start to support multi-user systems.
- Each user can independently use the system without affecting other users.
- Each user has a unique numeric user ID (UID), a username, and a **(home directory) where their files and settings are stored.**

<aside>
💡 **User is an account. You can log in with your user account, or others using `su`.**

**Groups can be thought of as levels of privilege. A person who is part of a group can view or modify files belonging to that group, depending on the permissions of that file.**

</aside>

---

# IDs

- **UID 0** (**Superuser/root/administrator) has the highest privileges on a system.**
- **IDs 1:200** (**Main system accounts) part of OS.**
- **IDs 201:999** (**System accounts) which used for services run on OS.**
- **IDs 1000 and above** (**Normal users) for creation users.**

                               

<aside>
💡 **First user created by default take UID 1000 then 1001 ,1002,1003…… etc.
After user creation there is a created group with the same name of user by default.**

</aside>

---

# User Management

<aside>
💡 **Su VS Sudo**
 **`su`** :**Switch User** fully switch user to another account, root.
            When using   **`su`** , you are prompted for the password of the account you are switching to.

 **(Unless you are root, in which case you can switch to any account with a valid login shell).**
  **`su`** : Keep the home directory of user you logged with.
 **`su`  -** : Used to run the new shell as a login shell (As you logged in directly not just switch your account).

![**Remember `pwd`>>Print the current working directory.**](Linux%20f662e4c7c5c247d7ba5c66e7c8bdba9a/su.png)

**Remember `pwd`>>Print the current working directory.**

**`sudo` :  Super User Do** Run single command as root.

</aside>

## 

<aside>
💡 **/etc/shadow File**
 Important file on the system that contains:

1. Username.
2. Encrypted password.
3. Date of the last password changed - expressed as the number of days since Jan 1, 1970. If there is a 0 that means the user should change their password the next time they log in.
4. Minimum password age - Days that a user will have to wait before being able to change their password again.
5. Maximum password age - Maximum number of days before a user has to change their password.
6. Password warning period - Number of days before a password is going to expire.
7. Password inactivity period - Number of days after a password has expired to allow login with their password.
8. Account expiration date - the date that the user will not be able to log in.
9. Reserved field for future use.
</aside>

![**Remember `cat` >>used for reading from the file.**](Linux%20f662e4c7c5c247d7ba5c66e7c8bdba9a/etcshadow.png)

**Remember `cat` >>used for reading from the file.**

<aside>
💡 **/etc/passwd File**
Important file on the system that contains:

1. Username
2. User's password - the password is not really stored in this file, it's usually stored in the /etc/shadow file. You can see many different symbols that are in this field, if you see an "x" that means the password is stored in the /etc/shadow file, a "*" means the user doesn't have login access, and if there is a blank field that means the user doesn't have a password.
3. The user ID - as you can see root has the UID of 0
4. The group ID.
5. GECOS field - This is used to generally leave comments about the user or account such as their real name or phone number, it is comma-delimited.
6. User's home directory
7. User's shell - you'll probably see a lot of users defaulting to bash for their shell.
</aside>

![passwd.png](Linux%20f662e4c7c5c247d7ba5c66e7c8bdba9a/passwd.png)

  

## **-**Add User

                  **`useradd    [user name]`**

![**Note we used `sudo`because this action needed root privilege.**](Linux%20f662e4c7c5c247d7ba5c66e7c8bdba9a/adduser.png)

**Note we used `sudo`because this action needed root privilege.**

## -Set OR Change User Password

                       **`passwd   [user name]`**  

![changepass.png](Linux%20f662e4c7c5c247d7ba5c66e7c8bdba9a/changepass.png)

                                  

## **-Delete** User

                     **`userdel    [user name]`**

![deletusr.png](Linux%20f662e4c7c5c247d7ba5c66e7c8bdba9a/deletusr.png)

### 

## **-Switch** User

               **`su    [user name]`**

![swicjuser.png](Linux%20f662e4c7c5c247d7ba5c66e7c8bdba9a/swicjuser.png)

                                        

## **-**Add Group

                  **`groupadd    [group name]`**

![Untitled](Linux%20f662e4c7c5c247d7ba5c66e7c8bdba9a/Untitled.png)

                     

## **-Delete** Group

                  **`groupdel    [group name]`**

![groupdel.png](Linux%20f662e4c7c5c247d7ba5c66e7c8bdba9a/groupdel.png)

---

# **Permissions Management**

- **Permissions very important for security.**
- **It allows users are authorized to access related files.**
- **`ls -l` command is used to see the permissions of the files.**

![permissions.png](Linux%20f662e4c7c5c247d7ba5c66e7c8bdba9a/permissions.png)

![Untitled](Linux%20f662e4c7c5c247d7ba5c66e7c8bdba9a/Untitled%201.png)

<aside>
💡 **r: Read permission allows:**

- The contents of files to be read.
- The contents of directories to be listed.

w :**Write permission allows:**

- The contents of a file to be modified.
- allows users to add, remove, and rename files in a directory **(note that even with write permission on
a file, you cannot delete it without write permission on the directory).**

 x : **Execute permissions allows:**

- File to be executed as a program or shell script.
- Users to enter and access files in a directory (but not list its contents).

 - : **Empty (0)**

![Untitled](Linux%20f662e4c7c5c247d7ba5c66e7c8bdba9a/Untitled%202.png)

### Each r,w,x expression has a numerical equivalent:

**4>> read permission(r)
2>>write permission(w)
1>>execute permission(x)**

![Untitled](Linux%20f662e4c7c5c247d7ba5c66e7c8bdba9a/Untitled%203.png)

</aside>

---

## **Changing File Permissions**

<aside>
💡 **`chmod` command (short for "change mode") is used to change permissions on files and directories.**

### There are two ways to specify the desired permissions:

- **symbolic mode**
- **octal/numeric mode**

### Symbolic mode:

         **To set permissions in symbolic mode, first specify `"u"` for user/owner,`"g"`for group,
          `"o"` for other, or`"a"` for all three.
          Then, use a`"+"` to add permissions, a `"-"` to remove permissions, or `"="` to assign new permissions.
          Then, use `"r"`for read, "w" for write, and `"x"` for execute. You can combine any of the ownership types and any of the
          permissions types in a single command, such as "u+x" for adding execute permission for the user/ower.**

![**Before change Permission**](Linux%20f662e4c7c5c247d7ba5c66e7c8bdba9a/izin4.png)

**Before change Permission**

![**After Change Permission**](Linux%20f662e4c7c5c247d7ba5c66e7c8bdba9a/izin5.png)

**After Change Permission**

---

### octal/numeric mode:

**permissions can also be represented by three octal digits (0-7), one for each permission group.
This is a more efficient way to set all permissions bits at once.
To use octal, add the permission bits together for each group, and then put them in order as a three-digit number.
Read permission is`"4"` , write permission is`"2"` , and execute permission is`"1"` .** 

**All combinations can be expressed as a combination of these digits:**

![Untitled](Linux%20f662e4c7c5c247d7ba5c66e7c8bdba9a/Untitled%204.png)

![**Note the difference after 644 which mean r w - r - - r - -**](Linux%20f662e4c7c5c247d7ba5c66e7c8bdba9a/izin6.png)

**Note the difference after 644 which mean r w - r - - r - -**

---

### **Ownership Permissions**

**Each file has an owner as user and group.
Ownership information can be viewed with the `ls -l` command.**

![izin7.png](Linux%20f662e4c7c5c247d7ba5c66e7c8bdba9a/izin7.png)

- **Note that the owner of the file is the "debian" user.**
- **The owner as a group is also the "debian" group.**
- **The  `chown`  command is used to change the owner of the file.**

![izin8.png](Linux%20f662e4c7c5c247d7ba5c66e7c8bdba9a/izin8.png)

- **Note that the owner of the file has been changed to the "letsdefend" user with the `chown` command.**
</aside>

---

# **What Are Environment Variables?**

Environment variables are the variables specific to a certain environment. For example, each user in an operating system has its own environment. An admin user has a different environment than other users do, for example.

Here are some examples of environment variables in Linux:

- `USER` – This points to the currently logged-in user.
- `HOME` – This shows the home directory of the current user.
- `SHELL` – This stores the path of the current user’s shell, such as bash or zsh.
- `LANG` – This variable points to the current language/locales settings.
- `MAIL` – This shows the location of where the current user’s mail is stored.

Note —> These environment variables vary based on the current user session.

The command used to display all the environment variables defined for a current session is `env` .

two ways to print environment variables:

- `printenv VARIABLE_NAME`
- `echo $varname`

---

## path and shell variables

- PATH is the location of your binaries.
- shell is what type of shell you use Bash, SH, DASH, CSH.