---
title: "TryHackMe - Classic Passwd"
categories:
  - Writeup
tags:
  - writeup
  - tryhackme
  - reversing
---
Practice your skills in reversing and get the flag bypassing the login

## Get the flag.
Donwload the file and check the file.

```bash
$ file Challenge.Challenge
Challenge.Challenge: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=b80ce38cb25d043128bc2c4e1e122c3d4fbba7f7, for GNU/Linux 3.2.0, not stripped
```

64-bit ELF. Let's disassemble it with IDA64.

<a href="/assets/images/tryhackme/classic-passwd/1.png"><img src="/assets/images/tryhackme/classic-passwd/1.png"></a>

We got the password at the `vuln` function. Let's input the password to the binary and we got the flag.

```bash
$ ./Challenge.Challenge 
Insert your username: AGB6js5d9dkG7

Welcome
THM{REDACTED}
```