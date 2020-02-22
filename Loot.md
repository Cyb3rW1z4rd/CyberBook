| Loot                                                         |
| ------------------------------------------------------------ |
| **Checklist**                                                |
| Proof:                                                       |
| Network secret:                                              |
| Passwords and hashes:                                        |
| Dualhomed:                                                   |
| Tcpdump:                                                     |
| Interesting files:                                           |
| Databases:                                                   |
| SSH-keys:                                                    |
| Browser:                                                     |
| Mail:                                                        |
|                                                              |
| **Passwords and hashes**                                     |
| cat /etc/passwd                                              |
| cat /etc/shadow                                              |
|                                                              |
| unshadow passwd shadow >  unshadowed.txt                     |
| john --rules  --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt |
|                                                              |
| **Dualhomed**                                                |
| ifconfig                                                     |
| ifconfig -a                                                  |
| arp -a                                                       |
|                                                              |
| **Tcpdump**                                                  |
| tcpdump -i any -s0 -w  capture.pcap                          |
| tcpdump -i eth0 -w capture -n  -U -s 0 src not 192.168.1.X and dst not 192.168.1.X |
| tcpdump -vv -i eth0 src not  192.168.1.X and dst not 192.168.1.X |
| Interesting files                                            |
|                                                              |
| **Meterpreter**                                              |
| search -f *.txt                                              |
| search -f *.zip                                              |
| search -f *.doc                                              |
| search -f *.xls                                              |
| search -f config*                                            |
| search -f *.rar                                              |
| search -f *.docx                                             |
| search -f *.sql                                              |
|                                                              |
| .ssh:                                                        |
| .bash_history                                                |
|                                                              |
| **Databases**                                                |
|                                                              |
| **SSH-Keys**                                                 |
|                                                              |
| **Browser**                                                  |
|                                                              |
| **Mail**                                                     |
| /var/mail                                                    |
| /var/spool/mail                                              |
| GUI                                                          |
|                                                              |
| **If there is a gui we want to  check out the browser.**     |
| echo $DESKTOP_SESSION                                        |
| echo $XDG_CURRENT_DESKTOP                                    |
| echo $GDMSESSION                                             |
|                                                              |
| **Recyclebin/**                                              |
|                                                              |
| **History**                                                  |
|                                                              |
| **log files**                                                |
|                                                              |
| **## LINUX LOOTING**                                         |
| search -f *.txt                                              |
| search -f *.zip                                              |
| search -f *.doc                                              |
| search -f *.xls                                              |
| search -f config*                                            |
| search -f *.rar                                              |
| search -f *.docx                                             |
| search -f *.sql                                              |
| find / -name "*.txt"                                         |
| find / -name  "*.doc*"                                       |
| find / -name "*.rar"                                         |
| find / -name  "*.xls*"                                       |
| find / -name "*.doc"                                         |
| find / -name "*.sql"                                         |
| .ssh:                                                        |
| .bash_history                                                |