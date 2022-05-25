---
title: Pickle Rick  
categories: [Try-Hack-Me] # Up to two elements only
tags: [tryhackme, easy, pickle rick, ctf]     # TAG names should always be lowercase, infinite number of elements
image: /assets/img/posts/Pickle_rick/Pickle_rick.webp    # If you want to add an image to the top of the post contents
# toc: false    # table of content - overwrite global configuration from _config.yml
# comments: false       # overwrite global configuration from _config.yml
# pin: true     # pin one or more posts to the top of the home page
excerpt_separator: <!--exc-->
permalink: /:categories/:year/:month/:day/:title:output_ext
published: true
---

This is a writeup for the Pickle Rick theme challenge on Try-Hack-Me which requires you to exploit a Webserver to find 3 ingredients that will help Rick make his potion to transform himself back into a human from a pickle. Rated as Easy/Beginner level machine.
<!--exc-->


# Introduction
In this post, we'll try to root [Pickle Rick](https://tryhackme.com/room/picklerick). It was created by [tryhackme](https://tryhackme.com/p/tryhackme). It is rated as **Easy/Beginner** level machine.


# Prerequisites
## Kali Linux / Parrot Security OS 
The virtual machine we'll use to source the attack vectors against the Pickle-Rick machine. These Linux distribution has all required tools pre-installed. Choose one of them.
* Kali Linux VM (based on Debian distribution) can be downloaded for both VMware and VirtualBox from [Offensive-Security](https://www.offensive-security.com/kali-linux-vm-vmware-virtualbox-image-download/)
* Parrot Security VM (based on Arch distribution with different desktop flavors) can be downloaded from [Parrot Security](https://www.parrotsec.org/download/)

## TryHackMe account
Signup or login to [TryHackMe](https://tryhackme.com/), deploy the [machine](https://tryhackme.com/room/picklerick) and give it a couple of minutes to boot.

## Dedicated Directory
We need to create a dedicated directory in our home directory `~` for our findings. We'll use `mkdir` to create the directory and `cd` to change into it:

```console
$ mkdir ~/tryhackme/pickle_rick
$ cd ~/tryhackme/pickle_rick/
```

## Add IP to hosts file [OPTIONAL]
For better readability we'll add the target IP to our local `/etc/hosts` file.
Please note this command requires sudo privileges. 

```console
$ sudo nano /etc/hosts

127.0.0.1       localhost
127.0.1.1       kali
10.10.128.137   pickle.rick
...
```

Now we can use the '**pickle.rick**' hostname instead of the IP in all the commands.


# Scanning
## Website
Using Firefox we can check the website on port 80. It is a Rick and Morty theme where the index page has one photo and text stating we need to look for three ingredients

![try-hack-me pickle rick homepage](/assets/img/posts/Pickle_rick/try-hack-me-pickle-rick-homepage.webp) _Pickle Rick homepage_

Nothing interesting to see here. Let's view the page source (right click on the page -> View Page Source). Here we find a **username**

![try-hack-me-pickle-rick-comment-view-page-source](/assets/img/posts/Pickle_rick/try-hack-me-pickle-rick-comment-view-page-source.webp) _Pickle Rick comment in page source_

Using the browser Developer Tools were not able to find any unusual HTTP headers.

## nikto
We'll use nikto to scan/enumerate the web application for known paths:

```console
$ nikto -h http://pickle.rick/
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.128.137
+ Target Hostname:    pickle.rick
+ Target Port:        80
+ Start Time:         2021-01-07 18:19:04 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server may leak inodes via ETags, header found with file /, inode: 426, size: 5818ccf125686, mtime: gzip
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
+ Cookie PHPSESSID created without the httponly flag
+ OSVDB-3233: /icons/README: Apache default file found.
+ /login.php: Admin login page/section found.
+ "robots.txt" contains 1 entry which should be manually viewed.
```

Two interesting paths:
* **robots.txt** - in this case the file contains only one string, nothing else. Might be useful in the future.
* **/login.php** - this is the Portal login page. 


# Gaining Access
We can try and use the username we found in the page source and use the string from the robots file as the password.

![try-hack-me-pickle-rick-login-page](/assets/img/posts/Pickle_rick/try-hack-me-pickle-rick-login-page.webp) _Pickle Rick login page_

**Success!** we now have access to the portal.

## First flag - Command Panel
The portal main page is a Command Panel which allow us to run Unix commands on the target (backend server).
Let's do a quick test and run `whoami` command and inspect the output. The output is `www-data` which is the user running the web service. If we issue a `ls` command we get a list of files:

```console
[REDACTED] 
assets
clue.txt
denied.php
index.html
login.php
portal.php
robots.txt
```
According it's name, the first file might contain valuable information for us.
As you recall, `robots.txt` file is accessible directly using a browser. Therefore we can assume the directory itself can be accessed by the web server. I leads us to try and access the above file using the browser path - `http://pickle.rick/REDACTED` - **Success!** the file content is the first ingredient we need.

- [x] First Flag
- [ ] Second Flag
- [ ] Third Flag

## Second flag - find
We should check the rest of the files in that directory. One of them is stating **"Look around the file system for the other ingredient."**. To do so we can use the `find` command. it will allow us to run a quick search for files/directories of interest (related to the ingredients).
**Keep in mind** - The search is limited by user permissions. The command we'll use is - `find / -iname "*ingred*" -type f 2>/dev/null` which breaks down to:
* `/` is the root path to start the scan from
* `-type f` search for file (d for directory)
* `-iname "*ingred*"` file name to look for. We also use wildcards (`*`) as the filename might start/end with additional string.
* `2>/dev/null` this will produce a cleaner output as it will discard errors, such as permission 

![try-hack-me-pickle-rick-find-search-results](/assets/img/posts/Pickle_rick/try-hack-me-pickle-rick-find-search-results.webp) _Pickle Rick find command results_

We know the first file, but the second one is new.

## cat / head / tail / less
The `cat`, `head` and `tail` commands are disabled. `less`, on the other hand is enabled and we're able to print the file content using `less /home/rick/"REDACTED"`

Note:
: The filename includes a space, therefore we **must use quotes** on the filename.

Success! we have the second ingredient.
- [x] First Flag
- [x] Second Flag
- [ ] Third Flag


# Privilege Escalation
## Third flag
We can use the `sudo -l` command to list which commands we can run as `sudo`:

Note:
: Links to further reading about `sudo -l` can be found at the Summary section below.

```console
Matching Defaults entries for www-data on ip-10-10-230-106.eu-west-1.compute.internal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ip-10-10-230-106.eu-west-1.compute.internal:
    (ALL) NOPASSWD: ALL
```

According to the output above, we can run "ALL" (**any**) commands as sudo. Nice. Let's investigate the root folder using `sudo ls /root`

```console
[REDACTED]
snap
```

OK, Let's print the first file using `less`: 
`sudo less /root/REDACTED`

Now we have the third ingredient.

- [x] First Flag
- [x] Second Flag
- [x] Third Flag


# Potential Rabbit Holes
## Stenography
Nikto found the /assets directory which contains multiple images. First instinct is to look for hidden data in these files. Not in this case.


# Summary
* Look into website source. F12 and Developer Tools are your friends.
* If one Unix command is being blocked or disabled, try to find another command to use e.g. `cat` and `less`.

## Reading Materials
* *sudo -l* - I see this technique used in many CTFs, It's simple to run and easy to understand. Make sure you feel comfortable with it. [READ](https://www.explainshell.com/explain?cmd=sudo+-l), [READ2](https://medium.com/better-programming/becoming-root-through-misconfigured-sudo-7b68e731d1f5)
