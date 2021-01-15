---
title: "TryHackMe - Reverse Engineering"
categories:
  - Writeup
tags:
  - sqli
  - writeup
  - tryhackme
  - hacking
  - privesc
---
This room focuses on teaching the basics of assembly through reverse engineering

## crackme1
- Check the file.

    ```bash
    $ file crackme1.bin 
    crackme1.bin: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=3864320789154e8960133afdf58ddf65f6f8273d, not stripped
    ```

- Crack the binary.

    <a href="/assets/images/tryhackme/RE/1.png"><img src="/assets/images/tryhackme/RE/1.png"></a>

    We got the password after decompiling the `main` function with IDA64. It compares our input and `hax0r` string.

- Test the binary.

    ```bash
    $ ./crackme1.bin 
    enter password
    hax0r
    password is correct
    ```

## crackme2
- Check the file.

    ```bash
    $ file crackme2.bin 
    crackme2.bin: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=8af6d80df94ca5466ba8a2b9284abf6d703f5cac, not stripped
    ```

- Crack the binary.

    <a href="/assets/images/tryhackme/RE/2.png"><img src="/assets/images/tryhackme/RE/2.png"></a>

    We got the password after decompiling the `main` function with IDA64. It checks our input if the value is 4998.

- Test the binary.

    ```bash
    $ ./crackme2.bin                  
    enter your password
    4988
    password is valid
    ```

## crackme3
- Check the file.

    ```bash
    $ file crackme3.bin
    crackme3.bin: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=a5df36880cc5174fe34ee4cb962778521c79bc26, not stripped
    ```

- Crack the binary.

    <a href="/assets/images/tryhackme/RE/3.png"><img src="/assets/images/tryhackme/RE/3.png"></a>

    We got the password after decompiling the `main` function with IDA64. It compares our input in a loop if the value is `azt`.

- Test the binary.

    ```bash
    $ ./crackme3.bin
    enter your password
    azt
    password is correct
    ```