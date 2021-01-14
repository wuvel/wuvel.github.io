---
title: "TryHackMe - Reversing ELF"
categories:
  - Writeup
tags:
  - ctf
  - writeup
  - tryhackme
  - hacking
  - reversing
---
Room for beginner Reverse Engineering CTF players

## Crackme1
- Check the file.
    ```bash
    $ file crackme1                                                 
    crackme1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=672f525a7ad3c33f190c060c09b11e9ffd007f34, not stripped
    ```
- Run the binary.
    ```bash
    $ chmod +x crackme1 
    $ ./crackme1 
    flag{REDACTED}
    ```

## Crackme2
- Check the file.

    ```bash
    $ file crackme2
    crackme2: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=b799eb348f3df15f6b08b3c37f8feb269a60aba7, not stripped
    ```

- Crack it with IDA!

    <a href="/assets/images/tryhackme/reversing-elf/1.png"><img src="/assets/images/tryhackme/reversing-elf/1.png"></a>

- Get the flag.

    ```bash
    $ ./crackme2 super_secret_password                                                                      1 ⨯
    Access granted.
    flag{REDACTED}
    ```

## Crackme3
- Check the file.

    ```bash
    $ file crackme3
    crackme3: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=4cf7250afb50109f0f1a01cc543fbf5ba6204a73, stripped
    ```

- Crack it with IDA!

    <a href="/assets/images/tryhackme/reversing-elf/2.png"><img src="/assets/images/tryhackme/reversing-elf/2.png"></a>

- Get the flag.

    ```bash
    $ ./crackme3 ZjByX3kwdXJfNWVjMG5kX2xlNTVvbl91bmJhc2U2NF80bGxfN2gzXzdoMW5nNQ==                         255 ⨯
    Come on, even my aunt Mildred got this one!

    $ echo "ZjByX3kwdXJfNWVjMG5kX2xlNTVvbl91bmJhc2U2NF80bGxfN2gzXzdoMW5nNQ==" | base64 -d
    REDACTED                                                                                                              
    $ ./crackme3 REDACTED                        
    Correct password!
    ```

## Crackme4
- Check the file.

    ```bash
    $ file crackme4
    crackme4: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=862ee37793af334043b423ba50ec91cfa132260a, not stripped
    ```

- Here i'll use IDA debugger to solve this problem.
    - Add breakpoint before `compare_pwd` function.
    
        <a href="/assets/images/tryhackme/reversing-elf/5.png"><img src="/assets/images/tryhackme/reversing-elf/5.png"></a>

    - Run debugger.
    - Forward the process-by-process (using step-into) until we find `get_pwd` function.

        <a href="/assets/images/tryhackme/reversing-elf/6.png"><img src="/assets/images/tryhackme/reversing-elf/6.png"></a>

    - Skip the `get_pwd` function by using step-over.
    - Forward and stop before `strcmp` function.
    - Inspect the variables before `strcmp` and we got the password.

        <a href="/assets/images/tryhackme/reversing-elf/4.png"><img src="/assets/images/tryhackme/reversing-elf/4.png"></a>

## Crackme5
- Check the file.

    ```bash
    $ file crackme5
    crackme5: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a426dcf8ed3de8cb02f3ee4f38ee36b4ed568519, not stripped
    ```

- Let's use IDA again. After i see the pseudocode, our input must be the same as image below and we got the `good game` output.

    <a href="/assets/images/tryhackme/reversing-elf/7.png"><img src="/assets/images/tryhackme/reversing-elf/7.png"></a>

## Crackme6
- Check the file.

    ```bash
    $ file crackme6
    crackme6: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=022f1a8e479cab9f7263af75bcdbb328bda7f291, not stripped
    ```

- Crack it with IDA. Decompile the source code and go to `my_secure_test` function. There is some conditional statement. We just need to convert the number to ASCII.

    <a href="/assets/images/tryhackme/reversing-elf/8.png"><img src="/assets/images/tryhackme/reversing-elf/8.png"></a>

- Convert it.

    ```bash
    >>> a = [49, 51, 51, 55, 95, 112, 119, 100]
    >>> str = ""
    >>> for i in a:
    ...     str += chr(i)
    ... 
    >>> print(str)
    1337_pwd
    ```

- Test it.

    ```bash
    $ ./crackme6 1337_pwd 
    password OK
    ```

## Crackme7
- Check the file.

    ```bash
    $ file crackme7
    crackme7: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=7ee4206d91718e7b0bef16a7c03f8fa49c4a39e7, not stripped
    ```

- It's pretty easy. We just have to input `31337' and we got the flag.

    <a href="/assets/images/tryhackme/reversing-elf/9.png"><img src="/assets/images/tryhackme/reversing-elf/9.png"></a>

- Test it

    ```bash
    $ ./crackme7
    Menu:

    [1] Say hello
    [2] Add numbers
    [3] Quit

    [>] 31337
    Wow such h4x0r!
    flag{REDACTED}
    ```

## Crackme8
- Check the file.

    ```bash
    $ file crackme8
    crackme8: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=fef76e38b5ff92ed0d08870ac523f9f3f8925a40, not stripped
    ```

- Decompile the program and. We found if-condition that will grant our access if our input is `3405705229`. It comes with `atoi` function, it converts string to integer. 

    <a href="/assets/images/tryhackme/reversing-elf/10.png"><img src="/assets/images/tryhackme/reversing-elf/10.png"></a>

- So if we want to get the same value, we just need to reverse the function. After i research about how to reverse `atoi` function, i found we can use `sprintf` function to reverse it.

    ```c
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>

    int main () {
    char str[111111]; 
    sprintf(str,"%d", 3405705229);
    printf(str);

    return(0);
    }
    ```

    - Output:
        ```bash
        $gcc -o main *.c
        $main
        -889262067
        ```
    
- Run the binary with `-889262067` as parameter and we got the flag.

    ```bash
    $ ./crackme8 -889262067                                                                                 1 ⨯
    Access granted.
    flag{REDACTED}
    ```