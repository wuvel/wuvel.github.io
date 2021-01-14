---
title: "TryHackMe - Reversing ELF"
categories:
  - Writeup
tags:
  - ctf
  - writeup
  - tryhackme
  - hacking
  - reversing
---
Room for beginner Reverse Engineering CTF players

## Crackme1
- Check the file.
    ```bash
    $ file crackme1                                                 
    crackme1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=672f525a7ad3c33f190c060c09b11e9ffd007f34, not stripped
    ```
- Run the binary.
    ```bash
    $ chmod +x crackme1 
    $ ./crackme1 
    flag{REDACTED}
    ```

## Crackme2
- Check the file.

    ```bash
    $ file crackme2
    crackme2: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=b799eb348f3df15f6b08b3c37f8feb269a60aba7, not stripped
    ```

- Crack it with IDA!

    <a href="/assets/images/tryhackme/reversing-elf/1.png"><img src="/assets/images/tryhackme/reversing-elf/1.png"></a>

- Get the flag.

    ```bash
    $ ./crackme2 super_secret_password                                                                      1 ⨯
    Access granted.
    flag{REDACTED}
    ```

## Crackme3
- Check the file.

    ```bash
    $ file crackme3
    crackme3: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=4cf7250afb50109f0f1a01cc543fbf5ba6204a73, stripped
    ```

- Crack it with IDA!

    <a href="/assets/images/tryhackme/reversing-elf/2.png"><img src="/assets/images/tryhackme/reversing-elf/2.png"></a>

- Get the flag.

    ```bash
    $ ./crackme3 ZjByX3kwdXJfNWVjMG5kX2xlNTVvbl91bmJhc2U2NF80bGxfN2gzXzdoMW5nNQ==                         255 ⨯
    Come on, even my aunt Mildred got this one!

    $ echo "ZjByX3kwdXJfNWVjMG5kX2xlNTVvbl91bmJhc2U2NF80bGxfN2gzXzdoMW5nNQ==" | base64 -d
    REDACTED                                                                                                              
    $ ./crackme3 REDACTED                        
    Correct password!
    ```

## Crackme4
- Check the file.

    ```bash
    $ file crackme4
    crackme4: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=862ee37793af334043b423ba50ec91cfa132260a, not stripped
    ```

#### I'll do research first