---
title: "TryHackMe - The find command"
categories:
  - TryHackMe
tags:
  - find
  - writeup
  - tryhackme
---
A learn-by-doing approach to the find command

## Start finding
- The syntax of the `find` command can be broken down as such:

    ```bash
    $ find where what
    ```

    Firstly you tell the system to find something; secondly you tell it where to look; and finally, you tell it what to look for.

    We don’t need to specify when you’re looking in your working directory. Also, we can use wildcards as well, in specifying both a directory and a name.

- Example:

    ```bash
    $ touch file-1 file-2

    # find all files starting with file
    $ find file*   
    file-1
    file-2

    # find all files that have 1 in the back.
    $ find *1
    file-1
    ```

## Be more specific
- More spesific commands:

```bash
$ find / -type SOMETHING -name test

# /             Search at root (/) directory
# -type         Specify the type, directory or file
# SOMETHING     Use d for directory and f for file
# -name         Specify the file or directory name. We can use -iname for case insensitive
# test          name of the file or the directory
```

#### Find all files whose name ends with ".xml"

```bash
$ find / -type f -name *.xml
```

#### Find all files in the /home directory (recursive) whose name is "user.txt" (case insensitive)

```bash
$ find /home -type f -iname user.txt
```

#### Find all directories whose name contains the word "exploits"

```bash
$ find / -type d -name *exploits*
```

## Know exactly what you're looking for
- In some situations, specifying just the name of a file will not be enough. You can also specify the owner, the size, the permissions, and the time the file was last accessed/modified as well.
- The username of the **owner** of a file is specified with the `-user` flag.
- The **size** of a file is specified with the `-size` flag. When using numerical values, the formats `-n`, `+n`, and `n` can be used, where `n` is a number. -n matches values lesser than `n`, `+n` matches values greater than `n`, and `n` matches values exactly `n`. To specify a size, you also need a suffix. `c` is the suffix for bytes, `k` for KiB’s, and `M` for MiB’s. So, if you want to specify a size less than 30 bytes, the argument `-30c` should be used.
- The `-perm` flag is used to specify **permissions**, either in octal form (ex. `644`) or in symbolic form (ex. `u=r`).  If you specify the permission mode as shown above (ex. `644` or `u=r`), then `find` will only return files with those permissions exactly. You can use the `–` or `/` prefix to make your search more inclusive. Using the `–` prefix will return files with at least the permissions you specify; this means that the `-444` mode will match files that are readable by everyone, even if someone also has write and/or execute permissions. Using the `/` prefix will return files that match any of the permissions you have set; this means that the `/666` mode will match files that are readable and writeable by at least one of the groups (owner, group, or others).
- Lastly, **time-related** searches will be covered. These are more complex but may prove useful. The flag consists of a word and a prefix. The words are min and time, for minutes and days, respectively. The prefixes are `a`, `m`, and `c`, and are used to specify when a file was last accessed, modified, or had its status changed. As for the numerical values, the same rules of the `-size` flag apply, except there is no suffix. To put it all together: in order to specify that a file was last accessed more than 30 minutes ago, the option `-amin +30` is used. To specify that it was modified less than 7 days ago, the option `-mtime -7` is used. (Note: when you want to specify that a file was modified within the last 24 hours, the option `-mtime 0` is used.)

#### Find all files owned by the user "kittycat"

```bash
$ find / -type f -user kittycat
```

#### Find all files that are exactly 150 bytes in size

```bash
$ find / -type f -size 150c
```

#### Find all files in the /home directory (recursive) with size less than 2 KiB’s and extension ".txt"

```bash
$ find /home -type f -name *.txt -size -2k 
```

#### Find all files that are exactly readable and writeable by the owner, and readable by everyone else (use octal format)

```bash
$ find / -type f -perm 644
```

#### Find all files that are only readable by anyone (use octal format)

```bash
$ find / -type f -perm /444
```

#### Find all files with write permission for the group "others", regardless of any other permissions, with extension ".sh" (use symbolic format)

```bash
$ find / -type f -perm o=w -name *.sh
```

#### Find all files in the /usr/bin directory (recursive) that are owned by root and have at least the SUID permission (use symbolic format)

```bash
$ find /usr/bin -type f -user root -perm -u=s
```

#### Find all files that were not accessed in the last 10 days with extension ".png"

```bash
$ find / -type f -atime 10 -name *.png
```

#### Find all files in the /usr/bin directory (recursive) that have been modified within the last 2 hours

```bash
$ find /usr/bin -type f -mmin 120
```

## Have you found it?
- To conclude this tutorial, there are two more things that you should know of. The first is that you can use the redirection operator `>` with the `find` command. You can save the results of the search to a file, and more importantly, you can suppress the output of any possible errors to make the output more readable. This is done by appending `2> /dev/null` to your command. This way, you won’t see any results you’re not allowed to access.
- The second thing is the `-exec` flag. You can use it in your `find` command to execute a new command, following the -`exec` flag, like so: `-exec whoami \;`. The possibilities enabled by this option are beyond the scope of this tutorial, but most notably it can be used for privilege escalation.