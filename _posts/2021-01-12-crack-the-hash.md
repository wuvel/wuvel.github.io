---
title: "TryHackMe - Crack the hash"
categories:
  - Writeup
tags:
  - linux
  - writeup
  - tryhackme
  - hacking
  - hash
  - crack
  - hashcat
---
Cracking hashes challenges

## Level 1
- 48bb6e862e54f2a795ffc4e541caed4d
    > MD5. Using crackstation, it's `easy`.

- CBFDAC6008F9CAB4083784CBD1874F76618D2A97 
    > SHA-1. Using crackstation, it's `password123`.

- 1C8BFE8F801D79745C4631D09FFF36C82AA37FC4CCE4FC946683D7B336B63032
    > SHA-256. Using crackstation, it's `letmein`.

- $2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom
    >

- 279412f945939ba78ce0758d3fd83daa
    > MD4. Using crackstation, it's `letmeEternity22in`.

## Level 2

- Hash: F09EDCB1FCEFC6DFB23DC3505A882655FF77375ED8AA2D1C13F640FCCC2D0C85
    - Identify:
        ```bash
        $ hash-identifier F09EDCB1FCEFC6DFB23DC3505A882655FF77375ED8AA2D1C13F640FCCC2D0C85                      1 ⨯
        #########################################################################
        #     __  __                     __           ______    _____           #
        #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
        #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
        #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
        #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
        #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
        #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
        #                                                             By Zion3R #
        #                                                    www.Blackploit.com #
        #                                                   Root@Blackploit.com #
        #########################################################################
        --------------------------------------------------

        Possible Hashs:
        [+] SHA-256
        [+] Haval-256

        Least Possible Hashs:
        [+] GOST R 34.11-94
        [+] RipeMD-256
        [+] SNEFRU-256
        [+] SHA-256(HMAC)
        [+] Haval-256(HMAC)
        [+] RipeMD-256(HMAC)
        [+] SNEFRU-256(HMAC)
        [+] SHA-256(md5($pass))
        [+] SHA-256(sha1($pass))
        --------------------------------------------------
        ```

    - Crack:
        ```bash
        $ hashcat -m 1400 hash.txt /usr/share/wordlists/rockyou.txt                   
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

        f09edcb1fcefc6dfb23dc3505a882655ff77375ed8aa2d1c13f640fccc2d0c85:paule
                                                        
        Session..........: hashcat
        Status...........: Cracked
        Hash.Name........: SHA2-256
        Hash.Target......: f09edcb1fcefc6dfb23dc3505a882655ff77375ed8aa2d1c13f...2d0c85
        Time.Started.....: Tue Jan 12 08:13:35 2021 (0 secs)
        Time.Estimated...: Tue Jan 12 08:13:35 2021 (0 secs)
        Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
        Guess.Queue......: 1/1 (100.00%)
        Speed.#1.........:  1213.0 kH/s (0.38ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
        Recovered........: 1/1 (100.00%) Digests
        Progress.........: 79872/14344385 (0.56%)
        Rejected.........: 0/79872 (0.00%)
        Restore.Point....: 73728/14344385 (0.51%)
        Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
        Candidates.#1....: compu -> Bulldog

        Started: Tue Jan 12 08:13:14 2021
        Stopped: Tue Jan 12 08:13:37 2021
        ```

- Hash: 1DFECA0C002AE40B8619ECF94819CC1B
    - It's probably NTLM.
    - Crack:
        ```bash
        $ hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt                                             1 ⨯
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

        1dfeca0c002ae40b8619ecf94819cc1b:n63umy8lkf4i    
                                                        
        Session..........: hashcat
        Status...........: Cracked
        Hash.Name........: NTLM
        Hash.Target......: 1dfeca0c002ae40b8619ecf94819cc1b
        Time.Started.....: Tue Jan 12 08:21:16 2021 (1 sec)
        Time.Estimated...: Tue Jan 12 08:21:17 2021 (0 secs)
        Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
        Guess.Queue......: 1/1 (100.00%)
        Speed.#1.........:  6157.9 kH/s (0.19ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
        Recovered........: 1/1 (100.00%) Digests
        Progress.........: 5240832/14344385 (36.54%)
        Rejected.........: 0/5240832 (0.00%)
        Restore.Point....: 5234688/14344385 (36.49%)
        Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
        Candidates.#1....: nabete -> n36873687

        Started: Tue Jan 12 08:21:05 2021
        Stopped: Tue Jan 12 08:21:17 2021
        ```

- Hash: $6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02.<br>Salt: aReallyHardSalt<br>Rounds: 5
    ```bash
    $ hashcat -m 1800 hash.txt /usr/share/wordlists/rockyou.txt
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

    Dictionary cache hit:
    * Filename..: /usr/share/wordlists/rockyou.txt
    * Passwords.: 14344385
    * Bytes.....: 139921507
    * Keyspace..: 14344385

    [s]tatus [p]ause [b]ypass [c]heckpoint [q]uit => s

    Session..........: hashcat
    Status...........: Running
    Hash.Name........: sha512crypt $6$, SHA512 (Unix)
    Hash.Target......: $6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPM...ZAs02.
    Time.Started.....: Tue Jan 12 08:29:31 2021 (1 min, 28 secs)
    Time.Estimated...: Tue Jan 12 09:59:18 2021 (1 hour, 28 mins)
    Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
    Guess.Queue......: 1/1 (100.00%)
    Speed.#1.........:     2663 H/s (7.48ms) @ Accel:64 Loops:256 Thr:1 Vec:4
    Recovered........: 0/1 (0.00%) Digests
    Progress.........: 234240/14344385 (1.63%)
    Rejected.........: 0/234240 (0.00%)
    Restore.Point....: 234240/14344385 (1.63%)
    Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4864-5000
    Candidates.#1....: sigurd -> sexxy12

    $6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02.:waka99
                                                    
    Session..........: hashcat
    Status...........: Cracked
    Hash.Name........: sha512crypt $6$, SHA512 (Unix)
    Hash.Target......: $6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPM...ZAs02.
    Time.Started.....: Tue Jan 12 08:29:31 2021 (17 mins, 31 secs)
    Time.Estimated...: Tue Jan 12 08:47:02 2021 (0 secs)
    Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
    Guess.Queue......: 1/1 (100.00%)
    Speed.#1.........:     2649 H/s (6.86ms) @ Accel:64 Loops:256 Thr:1 Vec:4
    Recovered........: 1/1 (100.00%) Digests
    Progress.........: 2832000/14344385 (19.74%)
    Rejected.........: 0/2832000 (0.00%)
    Restore.Point....: 2831616/14344385 (19.74%)
    Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4864-5000
    Candidates.#1....: wake21188 -> wajidmok

    Started: Tue Jan 12 08:29:04 2021
    Stopped: Tue Jan 12 08:47:03 2021
    ```

- Hash: e5d8870e5bdd26602cab8dbe07a942c8669e56d6<br>Salt: tryhackme
    ```bash
    $ hashcat -m 160 -a 0 hash.txt /usr/share/wordlists/rockyou.txt                                         1 ⨯
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
    * Not-Iterated
    * Single-Hash
    * Single-Salt

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

    e5d8870e5bdd26602cab8dbe07a942c8669e56d6:tryhackme:481616481616
                                                    
    Session..........: hashcat
    Status...........: Cracked
    Hash.Name........: HMAC-SHA1 (key = $salt)
    Hash.Target......: e5d8870e5bdd26602cab8dbe07a942c8669e56d6:tryhackme
    Time.Started.....: Tue Jan 12 08:59:05 2021 (3 secs)
    Time.Estimated...: Tue Jan 12 08:59:08 2021 (0 secs)
    Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
    Guess.Queue......: 1/1 (100.00%)
    Speed.#1.........:  3725.9 kH/s (0.63ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
    Recovered........: 1/1 (100.00%) Digests
    Progress.........: 12318720/14344385 (85.88%)
    Rejected.........: 0/12318720 (0.00%)
    Restore.Point....: 12312576/14344385 (85.84%)
    Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
    Candidates.#1....: 48162450 -> 4799876hawa

    Started: Tue Jan 12 08:58:53 2021
    Stopped: Tue Jan 12 08:59:10 2021
    ```

