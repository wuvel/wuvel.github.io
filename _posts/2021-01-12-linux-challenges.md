---
title: "TryHackMe - Linux Challenges"
categories:
  - Writeup
tags:
  - basic
  - challenge
  - linux
  - writeup
  - tryhackme
  - hacking
  - linux commands 
---
Test your Linux skills by finding flags using various Linux commands and concepts. Do you have what it takes to solve these challenges?

## Linux Challenges Introduction
- SSH to the machine with this credential. `garry:letmein`.
    ```bash
    $ ssh garry@10.10.150.192
    
    garry@10.10.150.192's password: 
    Last login: Tue Jan 12 07:03:07 2021 from 10.100.2.57
    garry@ip-10-10-150-192:~$
    ```
- How many visible files can you see in garrys home directory?
    ```bash
    garry@ip-10-10-150-192:~$ ls
    flag1.txt  flag24  flag29
    ``` 
    There are 3 files.

## The Basics
- What is flag 1?
    ```bash
    garry@ip-10-10-150-192:~$ cat flag1.txt
    There are flags hidden around the file system, its your job to find them.

    Flag 1: REDACTED

    Log into bobs account to get flag 2.

    Username: bob
    Password: linuxrules
    ```

- What is flag 2?
```bash
    garry@ip-10-10-150-192:~$ su bob
    Password: 
    bob@ip-10-10-150-192:/home/garry$ cd ~
    bob@ip-10-10-150-192:~$ ls
    Desktop    Downloads  flag21.php  flag8.tar.gz  Pictures  Templates
    Documents  flag13     flag2.txt   Music         Public    Videos
    bob@ip-10-10-150-192:~$ cat flag2.txt
    Flag 2: REDACTED
    ```

- Flag 3 is located where bob's bash history gets stored.
    ```bash
    bob@ip-10-10-150-192:~$ cat ~/.bash_history
    REDACTED
    cat ~/.bash_history 
    rm ~/.bash_history
    vim ~/.bash_history
    exit
    ls
    crontab -e
    ls
    cd /home/alice/
    ls
    cd .ssh
    ssh -i .ssh/id_rsa alice@localhost
    exit
    ls
    cd ../alice/
    cat .ssh/id_rsa
    cat /home/alice/.ssh/id_rsa
    exit
    cat ~/.bash_history 
    exit
    ```

- Flag 4 is located where cron jobs are created.
    ```bash
    bob@ip-10-10-150-192:/$ crontab -l
    # Edit this file to introduce tasks to be run by cron.
    # 
    # Each task to run has to be defined through a single line
    # indicating with different fields when the task will be run
    # and what command to run for the task
    # 
    # To define the time you can provide concrete values for
    # minute (m), hour (h), day of month (dom), month (mon),
    # and day of week (dow) or use '*' in these fields (for 'any').# 
    # Notice that tasks will be started based on the cron's system
    # daemon's notion of time and timezones.
    # 
    # Output of the crontab jobs (including errors) is sent through
    # email to the user the crontab file belongs to (unless redirected).
    # 
    # For example, you can run a backup of all your user accounts
    # at 5 a.m every week with:
    # 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
    # 
    # For more information see the manual pages of crontab(5) and cron(8)
    # 
    # m h  dom mon dow   command

    0 6 * * * echo 'REDACTED' > /home/bob/flag4.txt
    ```

- Find and retrieve flag 5.
    ```bash
    bob@ip-10-10-150-192:/$ find -type f -name flag5.txt 2>/dev/null
    ./lib/terminfo/E/flag5.txt
    bob@ip-10-10-150-192:/$ cat ./lib/terminfo/E/flag5.txt
    REDACTED
    ```

- "Grep" through flag 6 and find the flag. The first 2 characters of the flag is c9.
    ```bash
    bob@ip-10-10-150-192:/$ cat ./home/flag6.txt | grep "c9"
    Sed sollicitudin eros quis vulputate rutrum. Curabitur mauris elit, elementum quis sapien sed, ullamcorper pellentesque neque. Aliquam erat volutpat. Cras vehicula mauris vel lectus hendrerit, sed malesuada ipsum consectetur. Donec in enim id erat condimentum vestibulum c9REDACTED vitae eget nisi. Suspendisse eget commodo libero. Mauris eget gravida quam, a interdum orci. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae; Quisque eu nisi non ligula tempor efficitur. Etiam eleifend, odio vel bibendum mattis, purus metus consectetur turpis, eu dignissim elit nunc at tortor. Mauris sapien enim, elementum faucibus magna at, rutrum venenatis ipsum.
    ```

- Look at the systems processes. What is flag 7.
    ```bash
    bob@ip-10-10-150-192:/$ ps aux | grep flag
    root      1404  0.0  0.0   6008   328 ?        S    07:02   0:00 flag7:REDACTED 1000000
    bob       2697  0.0  0.0  12944  1012 pts/1    S+   07:38   0:00 grep --color=auto flag
    ```

- De-compress and get flag 8.
    ```bash
    bob@ip-10-10-150-192:/$ find -type f -name "flag8*" 2>/dev/null
    ./home/bob/flag8.tar.gz
    bob@ip-10-10-150-192:~$ cd ~
    bob@ip-10-10-150-192:~$ tar -xvf flag8.tar.gz 
    flag8.txt
    bob@ip-10-10-150-192:~$ ls
    Desktop    Downloads  flag21.php  flag8.tar.gz  Music     Public     Videos
    Documents  flag13     flag2.txt   flag8.txt     Pictures  Templates
    bob@ip-10-10-150-192:~$ cat flag8.txt 
    REDACTED
    ```

- By look in your hosts file, locate and retrieve flag 9.
    ```bash
    bob@ip-10-10-150-192:~$ cat /etc/hosts 
    127.0.0.1 localhost

    # The following lines are desirable for IPv6 capable hosts
    ::1 ip6-localhost ip6-loopback
    fe00::0 ip6-localnet
    ff00::0 ip6-mcastprefix
    ff02::1 ip6-allnodes
    ff02::2 ip6-allrouters
    ff02::3 ip6-allhosts

    127.0.0.1       REDACTED.com
    ```

- Find all other users on the system. What is flag 10.
    ```bash
    bob@ip-10-10-150-192:~$ cat /etc/passwd
    root:x:0:0:root:/root:/bin/bash
    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    bin:x:2:2:bin:/bin:/usr/sbin/nologin
    sys:x:3:3:sys:/dev:/usr/sbin/nologin
    sync:x:4:65534:sync:/bin:/bin/sync
    games:x:5:60:games:/usr/games:/usr/sbin/nologin
    man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
    lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
    mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
    news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
    uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
    proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
    www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
    backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
    list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
    irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
    gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
    nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
    systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
    systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
    systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
    systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
    syslog:x:104:108::/home/syslog:/bin/false
    _apt:x:105:65534::/nonexistent:/bin/false
    lxd:x:106:65534::/var/lib/lxd/:/bin/false
    messagebus:x:107:111::/var/run/dbus:/bin/false
    uuidd:x:108:112::/run/uuidd:/bin/false
    dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
    sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
    pollinate:x:111:1::/var/cache/pollinate:/bin/false
    ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
    bob:x:1001:1001:Bob,,,:/home/bob:/bin/bash
    REDACTED:x:1002:1002:,,,:/home/REDACTED:/bin/bash
    alice:x:1003:1003:,,,:/home/alice:/bin/bash
    mysql:x:112:117:MySQL Server,,,:/nonexistent:/bin/false
    xrdp:x:113:118::/var/run/xrdp:/bin/false
    whoopsie:x:114:120::/nonexistent:/bin/false
    avahi:x:115:121:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
    avahi-autoipd:x:116:122:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
    colord:x:117:125:colord colour management daemon,,,:/var/lib/colord:/bin/false
    geoclue:x:118:126::/var/lib/geoclue:/bin/false
    speech-dispatcher:x:119:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
    hplip:x:120:7:HPLIP system user,,,:/var/run/hplip:/bin/false
    kernoops:x:121:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
    pulse:x:122:127:PulseAudio daemon,,,:/var/run/pulse:/bin/false
    rtkit:x:123:129:RealtimeKit,,,:/proc:/bin/false
    saned:x:124:130::/var/lib/saned:/bin/false
    usbmux:x:125:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
    gdm:x:126:131:Gnome Display Manager:/var/lib/gdm3:/bin/false
    garry:x:1004:1006:,,,:/home/garry:/bin/bash
    bob@ip-10-10-150-192:~$
    ```

## Linux Functionality
- Run the command flag11. Locate where your command alias are stored and get flag 11.
    ```bash
    bob@ip-10-10-150-192:~$ cat ~/.bashrc
    # ~/.bashrc: executed by bash(1) for non-login shells.
    # see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
    # for examples
    ...
    #custom alias
    alias flag11='echo "You need to look where the alias are created..."' #REDACTED
    ```

- locate motd
    ```bash
    bob@ip-10-10-150-192:~$ cat /etc/update-motd.d/00-header
    #!/bin/sh
    #
    #    00-header - create the header of the MOTD
    #    Copyright (C) 2009-2010 Canonical Ltd.
    #
    #    Authors: Dustin Kirkland <kirkland@canonical.com>
    #
    #    This program is free software; you can redistribute it and/or modify
    #    it under the terms of the GNU General Public License as published by
    #    the Free Software Foundation; either version 2 of the License, or
    #    (at your option) any later version.
    #
    #    This program is distributed in the hope that it will be useful,
    #    but WITHOUT ANY WARRANTY; without even the implied warranty of
    #    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    #    GNU General Public License for more details.
    #
    #    You should have received a copy of the GNU General Public License along
    #    with this program; if not, write to the Free Software Foundation, Inc.,
    #    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

    [ -r /etc/lsb-release ] && . /etc/lsb-release

    if [ -z "$DISTRIB_DESCRIPTION" ] && [ -x /usr/bin/lsb_release ]; then
            # Fall back to using the very slow lsb_release utility
            DISTRIB_DESCRIPTION=$(lsb_release -s -d)
    fi

    # Flag12: REDACTED

    cat logo.txt
    ```

- Find the difference between two script files to find flag 13.
    ```bash
    bob@ip-10-10-150-192:~$ cd flag13
    bob@ip-10-10-150-192:~/flag13$ ls
    script1  script2
    bob@ip-10-10-150-192:~/flag13$ diff script1 script2
    2437c2437
    < Lightoller sees Smith walking stiffly toward him and quickly goes to him. He yells into the Captain's ear, through cupped hands, over the roar of the steam... 
    ---
    > Lightoller sees REDACTED Smith walking stiffly toward him and quickly goes to him. He yells into the Captain's ear, through cupped hands, over the roar of the steam... 
    ```

- Where on the file system are logs typically stored? Find flag 14.
    ```bash
    bob@ip-10-10-150-192:~$ cd /var/log/
    bob@ip-10-10-150-192:/var/log$ ls
    alternatives.log    btmp                   flagtourteen.txt  kern.log.2.gz      syslog.3.gz
    alternatives.log.1  btmp.1                 fontconfig.log    lastlog            unattended-upgrades
    amazon              cloud-init.log         fsck              lxd                wtmp
    apache2             cloud-init-output.log  gdm3              mysql              wtmp.1
    apt                 cups                   gpu-manager.log   speech-dispatcher  Xorg.0.log
    auth.log            dist-upgrade           hp                syslog             Xorg.0.log.old
    auth.log.1          dpkg.log               kern.log          syslog.1           xrdp-sesman.log
    auth.log.2.gz       dpkg.log.1             kern.log.1        syslog.2.gz
    bob@ip-10-10-150-192:/var/log$ cat flagtourteen.txt 
    ...
    REDACTED
    ```

- Find flag 15.
    ```bash
    bob@ip-10-10-150-192:~$ cat /proc/version; uname -a; uname -mrs; rpm -q kernel; dmesg | grep Linux; ls /boot | grep vmlinuz-; file /bin/ls; cat /etc/lsb-release
    Linux version 4.4.0-1075-aws (buildd@lgw01-amd64-035) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.10) ) #85-Ubuntu SMP Thu Jan 17 17:15:12 UTC 2019
    Linux ip-10-10-150-192 4.4.0-1075-aws #85-Ubuntu SMP Thu Jan 17 17:15:12 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
    Linux 4.4.0-1075-aws x86_64
    The program 'rpm' is currently not installed. To run 'rpm' please ask your administrator to install the package 'rpm'
    [    0.000000] Linux version 4.4.0-1075-aws (buildd@lgw01-amd64-035) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.10) ) #85-Ubuntu SMP Thu Jan 17 17:15:12 UTC 2019 (Ubuntu 4.4.0-1075.85-aws 4.4.167)
    [    1.369358] Linux agpgart interface v0.103
    vmlinuz-4.4.0-1072-aws
    vmlinuz-4.4.0-1075-aws
    /bin/ls: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=d0bc0fb9b3f60f72bbad3c5a1d24c9e2a1fde775, stripped
    FLAG_15=REDACTED
    DISTRIB_ID=Ubuntu
    DISTRIB_RELEASE=16.04
    DISTRIB_CODENAME=xenial
    DISTRIB_DESCRIPTION="Ubuntu 16.04.5 LTS"
    ```

- Flag 16 lies within another system mount.
    ```bash
    bob@ip-10-10-150-192:/$ cd media/

    # type cd then spam tab
    bob@ip-10-10-150-192:/media$ cd f/l/a/g/1/6/is/REDACTED/
    ```

- Login to alice's account and get flag 17. Her password is TryHackMe123
    ```bash
    bob@ip-10-10-150-192:~$ su alice
    Password: 
    alice@ip-10-10-150-192:/home/bob$ cd ~
    alice@ip-10-10-150-192:~$ ls
    flag17  flag19  flag20  flag22  flag23  flag32.mp3
    alice@ip-10-10-150-192:~$ cat flag17 
    REDACTED
    ```

- Find the hidden flag 18.
    ```bash
    alice@ip-10-10-150-192:~$ ls -la
    total 172
    drwxr-xr-x 4 alice alice  4096 Feb 20  2019 .
    drwxr-xr-x 6 root  root   4096 Feb 20  2019 ..
    -rw------- 1 alice alice   518 Mar  7  2019 .bash_history
    -rw-r--r-- 1 alice alice   220 Feb 18  2019 .bash_logout
    -rw-r--r-- 1 alice alice  3771 Feb 18  2019 .bashrc
    drwx------ 2 alice alice  4096 Feb 18  2019 .cache
    -rw-rw-r-- 1 alice alice    33 Feb 18  2019 flag17
    -rw-rw-r-- 1 alice alice    33 Feb 18  2019 .flag18
    -rw-rw-r-- 1 alice alice 99001 Feb 19  2019 flag19
    -rw-rw-r-- 1 alice alice    45 Feb 19  2019 flag20
    -rw-rw-r-- 1 alice alice    96 Feb 19  2019 flag22
    -rw-rw-r-- 1 alice alice    33 Feb 19  2019 flag23
    -rw-rw-r-- 1 alice alice 10560 Feb 19  2019 flag32.mp3
    -rw------- 1 alice alice    32 Feb 19  2019 .lesshst
    -rw-r--r-- 1 alice alice   655 Feb 18  2019 .profile
    drw-r--r-- 2 alice alice  4096 Mar  7  2019 .ssh
    -rw------- 1 alice alice  3075 Feb 19  2019 .viminfo
    alice@ip-10-10-150-192:~$ cat .flag18 
    REDACTED
    ```

- Read the 2345th line of the file that contains flag 19.
    ```bash
    alice@ip-10-10-150-192:~$ sed -n '2345p' flag19 
    REDACTED
    ```


## Data Representation, Strings and Permissions
- Find and retrieve flag 20.
    ```bash
    alice@ip-10-10-150-192:~$ ls
    flag17  flag19  flag20  flag22  flag23  flag32.mp3
    alice@ip-10-10-150-192:~$ cat flag20 
    MDJiOWFhYjhhMjk5NzBkYjA4ZWM3N2FlNDI1ZjZlNjg=
    alice@ip-10-10-150-192:~$ cat flag20 | base64 -d
    REDACTED
    ```

- Inspect the flag21.php file. Find the flag.
    ```bash
    lice@ip-10-10-150-192:~$ find / -type f -name flag21.php 2>/dev/null
    /home/bob/flag21.php
    alice@ip-10-10-150-192:~$ cat /home/bob/flag21.php
    <?='MoreToThisFileThanYouThink';?>
    alice@ip-10-10-150-192:~$ ^C
    alice@ip-10-10-150-192:~$ nano /home/bob/flag21.php
    ```
    Output: 
    <a href="/assets/images/tryhackme/linux-challeges/1.png"><img src="/assets/images/tryhackme/linux-challeges/1.png"></a>

- Locate and read flag 22. Its represented as hex.
    ```bash
    alice@ip-10-10-150-192:~$ ls
    flag17  flag19  flag20  flag22  flag23  flag32.mp3
    alice@ip-10-10-150-192:~$ cat flag22
    39 64 31 61 65 38 64 35 36 39 63 38 33 65 30 33 64 38 61 38 66 36 31 35 36 38 61 30 66 61 37 64
    alice@ip-10-10-150-192:~$ cat flag22 | xxd -r -p
    REDACTED
    ```

- Locate, read and reverse flag 23.
    ```bash
    alice@ip-10-10-150-192:~$ ls
    flag17  flag19  flag20  flag22  flag23  flag32.mp3
    alice@ip-10-10-150-192:~$ rev flag23 
    REDACTED
    ```

- Analyse the flag 24 compiled C program. Find a command that might reveal human readable strings when looking in the machine code code.
    ```bash
    alice@ip-10-10-150-192:~$ find / -type f -name "flag24" 2>/dev/null
    /home/garry/flag24
    alice@ip-10-10-150-192:~$ strings /home/garry/flag24
    ...
    flag_24_is_REDACTED
    __libc_start_main@@GLIBC_2.2.5
    __data_start
    ...
    ```

- Find flag 26 by searching the all files for a string that begins with 4bceb and is 32 characters long. 
    ```bash
    alice@ip-10-10-150-192:~$ find / -xdev -type f -print0 2>/dev/null | xargs -0 grep -E '^[a-z0-9]{32}$' 2>/dev/null
    Binary file /var/cache/apt/pkgcache.bin matches
    Binary file /var/cache/apt/srcpkgcache.bin matches
    /var/cache/apache2/mod_cache_disk/config.json:REDACTED
    ```

- Locate and retrieve flag 27, which is owned by the root user.
    ```bash
    alice@ip-10-10-150-192:~$ find / -user root 2>/dev/null | grep flag27
    /home/flag27
    alice@ip-10-10-150-192:~$ sudo -l
    Matching Defaults entries for alice on ip-10-10-150-192.eu-west-1.compute.internal:
        env_reset, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

    User alice may run the following commands on ip-10-10-150-192.eu-west-1.compute.internal:
        (ALL) NOPASSWD: /bin/cat /home/flag27
    alice@ip-10-10-150-192:~$ sudo cat /home/flag27
    REDACTED
    ```

- Whats the linux kernel version?
    ```bash
    alice@ip-10-10-150-192:~$ uname -a
    Linux ip-10-10-150-192 4.4.0-1075-aws #85-Ubuntu SMP Thu Jan 17 17:15:12 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
    ```

- Find the file called flag 29 and do the following operations on it:
    1. Remove all spaces in file.
    1. Remove all new line spaces.
    1. Split by comma and get the last element in the split.

    ```bash
    alice@ip-10-10-150-192:~$ cat /home/garry/flag29 | tr -d " \t\n\r" | sed 's@,@ @'
    Loremipsumdolorsitamet melperfectovolutpatassueveritno,ususonetphaedrumvulputateet.Periculisevertiturconstitutonoeam,vimeidelectusoportere.Sedquidamadmodumrecusabout,vimsteteleifendlaboramusex.Iudicoaliquidquian,adquopossitmolestiae.Iderosmunerevix.Necsolumtritanieu,odiopersequerissitin.Cumeurebumdicantpopulo,eueamnibhnostroliberavisse,adpostealuptatumpartiendoest.Adestrebumsaperettheophrastus,duisviditponderumutest,melnonumyprobatusea.Eumnononumespraesent.Eamutiustosoleat,vocentassueveritusuid.Librisaudiamreprimiqueeuvix,etullumiustoexplicarivim,nametzrilnostro.Populoquodsiatpri.Utamuraliquipvisei,hisdoloremaiestatisex.Viditcotidiequeseate.Noeostantasfacilispertinacia,estidrebumpericulaconsulatu.Quianmutatoporterequalisque,cumeipopulomuciusurbanitas.Tollitminimumeasea,dictapartemverearaneum.Necatquioptionpertinaxat,causaeaccommodareidvim.Admagnaerantmandamusqui.Eamodusmalorumoporteatvix,mazimdolorumappareatprono,adaliquamatomorumsea.Viditsimuldolorumvixea,atmeispossittractatosquo,neusuerosverovocent.Noiusgraecoomittamindoctum.Hisneposteaaliquid,hisvivendumnecessitatibusan.Pereiaffertadmodumdissentiet,namaliquidmentitummaiestatisea,uttacimatesdissentiasquo.Addiscereveritusintellegamius.Utmelnovummundiprincipes,nectalenostrolabiturut.Temeimodusluciliuslegendos.Etseaexercilatinesalutandi,etiusaeternointellegatsuscipiantur,euperenimfierentscriptorem.Adinanidictasblanditmel,idnatumhendreritreferrentursed.Ceteromaluissetiusei,visnonovumtritanivoluptua.Namquotassueveritid,persiusconceptamnecne.Estofficiisvoluptatibusan,seaeamunereomnesqueposidonium.Inaperiritibiqueapeirianvim,veleudecorepartiendo,verorepudiaretemei.Hastotaadipiscingat,velquotfacernusquamid,velilludaliquamex.Euullumpartiendoqualisquesea,usuethincmodussigniferumque,epicuripercipiturhonestatiseisit.Erantpercipitestat,nullaapeirianvelat.Unumlaudemvoluptatumquiad,duisautemidsed,atvelexplicariefficiantur.Eiatquiscribentureum,salutandimnesarchumdisputandousuan,nevixnumquamdoloremperfecto.Eiseasumocontentiones,necomnesoffenditconseteturut.Cumutplaceratpraesentpatrioque,neduoalterumphaedrumadipisci.Adipisciadversariumeumei,eameasuscipitpericulareprimique.Cuiudicoquaestiovis.Audiamrecusaboeupro,scriptacommunemeaan.Pereanibhomnesque,nejustolibriscommunequi,atiusilludposseefficiantur.Sintnobisquaerendumatpri,eaaliitollitscripseritquo,eisalequaerendumvoluptatibushis.Illudurbanitasduocu,quisdicereteuvis.Usuurbanitasconceptamdisputationiat.Nihillatineconsequatexmel,vocentblanditurbanitasvimin.Adeamexerciconcludaturque,neneczrilsapientemcontentiones.Hasidputantdictasquodsi.Vissimuldictasconvenireex,priesseexpetendahendreritne.Visessevivendono,neerremlegimusvolutpateos.Etvocibussensibussuavitatemea,brutelegimusestcu.Tehisetiamtritanialiquid,tehisnobisquaestio.Inpereripuitpersecutirationibus,dicoconstituamsitid.Sitmovetquandoeligendiut,ignotainterpretariseosat.Inenimiisqueinermisvel,eimelpersiusprompta.Neseasanctusdelicatissimi,meinecaseferrivulputate,atmelpericulisocurreret.Dicoverearaccusamusuex,fastidiisuscipitmeaei.
    ```

## SQL, FTP, Groups and RDP
- Use curl to find flag 30.
    ```bash
    alice@ip-10-10-150-192:~$ curl 10.10.150.192
    flag30:REDACTED
    ```

- Flag 31 is a MySQL database name.
    ```bash
    alice@ip-10-10-150-192:~$ mysql -u root -phello
    mysql: [Warning] Using a password on the command line interface can be insecure.
    Welcome to the MySQL monitor.  Commands end with ; or \g.
    Your MySQL connection id is 5
    Server version: 5.7.25-0ubuntu0.16.04.2 (Ubuntu)

    Copyright (c) 2000, 2019, Oracle and/or its affiliates. All rights reserved.

    Oracle is a registered trademark of Oracle Corporation and/or its
    affiliates. Other names may be trademarks of their respective
    owners.

    Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
    mysql> show databases;
    +-------------------------------------------+
    | Database                                  |
    +-------------------------------------------+
    | information_schema                        |
    | database_REDACTED |
    | mysql                                     |
    | performance_schema                        |
    | sys                                       |
    +-------------------------------------------+
    5 rows in set (0.01 sec)
    ```

- Bonus flag question, get data out of the table from the database you found above!
    ```bash
    mysql> use database_2fb1cab13bf5f4d61de3555430c917f4;
    Reading table information for completion of table and column names
    You can turn off this feature to get a quicker startup with -A

    Database changed
    mysql> show tables;
    +-----------------------------------------------------+
    | Tables_in_database_REDACTED |
    +-----------------------------------------------------+
    | flags                                               |
    +-----------------------------------------------------+
    1 row in set (0.00 sec)

    mysql> select * from flags
        -> ;
    +----+----------------------------------+
    | id | flag                             |
    +----+----------------------------------+
    |  1 | REDACTED |
    +----+----------------------------------+
    1 row in set (0.00 sec)
    ```

- Using SCP, FileZilla or another FTP client download flag32.mp3 to reveal flag 32.
    ```bash
    $ scp alice@10.10.150.192:flag32.mp3 .
    alice@10.10.150.192's password: 
    flag32.mp3 
    ```
    Listen to the mp3 and we got the password.

- Flag 33 is located where your personal $PATH's are stored.
    ```bash
    alice@ip-10-10-150-192:/home$ cd bob
    alice@ip-10-10-150-192:/home/bob$ ls
    Desktop    Downloads  flag21.php  flag8.tar.gz  Music     Public     Videos
    Documents  flag13     flag2.txt   flag8.txt     Pictures  Templates
    alice@ip-10-10-150-192:/home/bob$ cat .profile
    #Flag 33: REDACTED

    # ~/.profile: executed by the command interpreter for login shells.
    # This file is not read by bash(1), if ~/.bash_profile or ~/.bash_login
    # exists.
    # see /usr/share/doc/bash/examples/startup-files for examples.
    # the files are located in the bash-doc package.

    # the default umask is set in /etc/profile; for setting the umask
    # for ssh logins, install and configure the libpam-umask package.
    #umask 022

    # if running bash
    if [ -n "$BASH_VERSION" ]; then
        # include .bashrc if it exists
        if [ -f "$HOME/.bashrc" ]; then
            . "$HOME/.bashrc"
        fi
    fi

    # set PATH so it includes user's private bin directories
    PATH="$HOME/bin:$HOME/.local/bin:$PATH
    ```

- Switch your account back to bob. Using system variables, what is flag34?
    ```bash
    bob@ip-10-10-150-192:~$ cat /etc/environment 
    PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games"
    flag34="7a88306309fe05070a7c5bb26a6b2def"
    ```

- Look at all groups created on the system. What is flag 35?\
    ```bash
    alice@ip-10-10-150-192:/home/bob$ cat /etc/group
    ...
    gdm:x:131:
    flag35_769afb6:x:1005:
    garry:x:1006:
    ```

- Find the user which is apart of the "hacker" group and read flag 36.
    ```bash
    alice@ip-10-10-150-192:/home/bob$ getent group hacker
    hacker:x:1004:bob
    alice@ip-10-10-150-192:/home/bob$ find / -type f -name flag36 2>/dev/null
    /etc/flag36
    ^C
    alice@ip-10-10-150-192:/home/bob$ ls -l /etc/flag36
    -rw-r----- 1 root hacker 33 Feb 19  2019 /etc/flag36
    alice@ip-10-10-150-192:/home/bob$ su bob
    Password: 
    bob@ip-10-10-150-192:~$ cat /etc/flag36
    REDACTED
    ```
