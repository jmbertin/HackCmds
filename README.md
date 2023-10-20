# HackCmds
Collection of useful penetration testing and hacking commands.

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

## Metasploit
- Open console
````
msfconsole
````
- Search for exploit
````
search <SERVICE AND VERSION>
```
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

