# SNMP   

#### UDP 161  trap on UDP 162

```reStructuredText
exchange managemant information between network devices
```

```bash
apt-get install snmp-mibs-downloader
echo "" > /etc/snmp/snmp.conf
```

**nmap scripts: smb-security-mode,smb-os-discovery**



**find snmp services**
`nmap -sU -sS -Pn -sV -p 161 192.168.1.5`

**run nmap snmp enumeration scripts**

```shell
nmap -sU -sV -n -Pn -p 161 --script=snmp-* <target IP>
nmap -sV -p 161 --script=snmp-info $ip/24
nmap {nmap_extra} -sV -p {port} --script="(snmp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)"
nmap','-n','-sV','-Pn','-vv','-sU','-p','%s' % port,'--script=snmp-brute,snmp-hh3c-logins,snmp-info,snmp-ios-config,snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32-services,snmp-win32-shares,snmp-win32-software,snmp-win32-users,vulners','--script-args',"creds.snmp=:%s" % community,'-oA','/root/scripts/recon_enum/results/exam/snmp/%s_%s_snmp.nmap' % (ip_address,community),ip_address])

xprobe2 -v -p udp:161:open 192.168.1.200
```



## Brute - get community string
```shell
nmap -sU -sV -p 161 --script snmp-brute 10.10.10.5,20 --script-args snmp-brute.communitiesdb=/usr/share/wordlists/SecLists/Discovery/SNMP/common-snmp-community-strings.txt
nmap -sU -sV -p 161 --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt 10.10.10.5

snmpwalk -v 2c 192.168.102.149 -c public
snmpwalk -v 1 192.168.102.149 -c public
-v=version -c=community string

snmpwalk-system-processes' = snmpwalk -c public -v 1 {address} 1.3.6.1.2.1.25.1.6.0
snmpwalk-running-processes' = snmpwalk -c public -v 1 {address} 1.3.6.1.2.1.25.4.2.1.2
snmpwalk-process-paths' = snmpwalk -c public -v 1 {address} 1.3.6.1.2.1.25.4.2.1.4
snmpwalk-storage-units' =snmpwalk -c public -v 1 {address} 1.3.6.1.2.1.25.2.3.1.4
snmpwalk-software-names' = snmpwalk -c public -v 1 {address} 1.3.6.1.2.1.25.6.3.1.2 
snmpwalk-user-accounts' =snmpwalk -c public -v 1 {address} 1.3.6.1.4.1.77.1.2.25
snmpwalk-tcp-ports'= snmpwalk -c public -v 1 {address} 1.3.6.1.2.1.6.13.1.3

hrSWInstalledName - OID
snmpset - for setting values, works like snmpwalk
snmp-check -c public -w 192.168.100.1
```



## Metasploit

```
metasploit modules (auxiliary/scanner/snmp/snmp_login) 
msf > seach snmp
msf >  use auxiliary/scanner/snmp/snmp_login
msf > use auxiliary/scanner/snmp/snmp_enum
```



**SNMP Enumeration -Simple Network Management Protocol**

-   Fix SNMP output values so they are human readable
`apt-get install snmp-mibs-downloader download-mibs  `
`echo "" > /etc/snmp/snmp.conf`