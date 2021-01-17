---
title: "TryHackMe - Crack The Hash Level 2"
categories:
  - TryHackMe
tags:
  - linux
  - writeup
  - tryhackme
  - hacking
  - hash
  - crack
  - hashcat
---
Advanced cracking hashes challenges and wordlist generation

## Hash Identification
- [Haiti](https://noraj.github.io/haiti/#/) is a CLI tool to identify the hash type of a given hash. Install it.
    - Install from rubygems.org.
        ```bash
        $ gem install haiti-hash 
        Fetching paint-2.2.1.gem
        Fetching docopt-0.6.1.gem
        Fetching haiti-hash-1.0.1.gem
        Successfully installed docopt-0.6.1
        Successfully installed paint-2.2.1
        Successfully installed haiti-hash-1.0.1
        Parsing documentation for docopt-0.6.1
        Installing ri documentation for docopt-0.6.1
        Parsing documentation for paint-2.2.1
        Installing ri documentation for paint-2.2.1
        Parsing documentation for haiti-hash-1.0.1
        Installing ri documentation for haiti-hash-1.0.1
        Done installing documentation for docopt, paint, haiti-hash after 1 seconds
        3 gems installed
        ```
- Launch Haiti on this hash:
`741ebf5166b9ece4cca88a3868c44871e8370707cf19af3ceaa4a6fba006f224ae03f39153492853`
What kind of hash it is?

    ```bash
    $ haiti 741ebf5166b9ece4cca88a3868c44871e8370707cf19af3ceaa4a6fba006f224ae03f39153492853
    RIPEMD-320
    ```

- Launch Haiti on this hash:
`1aec7a56aa08b25b596057e1ccbcb6d768b770eaa0f355ccbd56aee5040e02ee`

    ```bash
    $ haiti 1aec7a56aa08b25b596057e1ccbcb6d768b770eaa0f355ccbd56aee5040e02ee                
    Snefru-256 [JtR: snefru-256]
    SHA-256 [HC: 1400] [JtR: raw-sha256]
    RIPEMD-256
    Haval-256 [JtR: haval-256-3]
    GOST R 34.11-94 [HC: 6900] [JtR: gost]
    GOST CryptoPro S-Box
    SHA3-256 [HC: 17400]
    Keccak-256 [HC: 17800] [JtR: raw-keccak-256]
    Skein-256 [JtR: skein-256]
    Skein-512(256)
    ```

- What is Keccak-256 Hashcat code?
> 17800

- What is Keccak-256 John the Ripper code?
> Raw-Keccak-25

## Wordlists
Useful wordlists:
- [SecLists](https://github.com/danielmiessler/SecLists) is a collection of multiple types of lists used during security assessments, collected in one place. List types include usernames, passwords, URLs, sensitive data patterns, fuzzing payloads, web shells, and many more.
- [wordlistctl](https://github.com/BlackArch/wordlistctl) is a script to fetch, install, update and search wordlist archives from websites offering wordlists with more than 6300 wordlists available.
- [Rawsec's CyberSecurity Inventory](https://inventory.raw.pm/overview.html) is an inventory of tools and resources about CyberSecurity. The Cracking category will be especially useful to find wordlist generator tools.

#### What is the name of the first wordlist in the usernames category?
> CommonAdminBase64 (from SecLists)

## Cracking tools, modes & rules
Finally you'll need a cracking tool, the 2 very common ones are:
- Hashcat
- John the Ripper (jumbo version)

There are several modes of cracking you can use:
- Wordlist mode, which consist in trying all words contained in a dictionary. For example, a list of common passwords, a list of usernames, etc.
- Incremental mode, which consist in trying all possible character combinations as passwords. This is powerful but much more longer especially if the password is long.
- Rule mode, which consist in using the wordlist mode by adding it some pattern or mangle the string. For example adding the current year, or appending a common special character.

There are 2 ways of performing a rule based bruteforce:
- Generating a custom wordlist and using the classic wordlist mode with it.
- Using a common wordlist and tell the cracking tool to apply some custom mangling rules on it.

John the Ripper already include various mangling rules but you can create your [owns](https://www.openwall.com/john/doc/RULES.shtml) and apply them the wordlist when cracking:<br>
```bash
$ john hash.txt --wordlist=/usr/share/wordlists/passwords/rockyou.txt rules=norajCommon02
```

Main ideas of mutation rules, of course several can be combined together.
- Border mutation - commonly used combinations of digits and special symbols can be added at the end or at the beginning, or both
- Freak mutation - letters are replaced with similarly looking special symbols
- Case mutation - the program checks all variations of uppercase/lowercase letters for any character
- Order mutation - character order is reversed
- Repetition mutation - the same group of characters are repeated several times
- Vowels mutation - vowels are omitted or capitalized
- Strip mutation - one or several characters are removed
- Swap mutation - some characters are swapped and change places
- Duplicate mutation - some characters are duplicated
- Delimiter mutation - delimiters are added between characters

#### Now let's crack the SHA1 hash `2d5c517a4f7a14dcb38329d228a7d18a3b78ce83`, we just have to write the hash in a text file and to specify the hash type, the wordlist and our rule name. `john hash.txt --format=raw-sha1 --wordlist=/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt --rules=THM01`
```bash
$ john hash.txt --format=raw-sha1 --wordlist=/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10k-most-common.txt --rules=THM01
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 128/128 AVX 4x])
Warning: no OpenMP support for this hash type, consider --fork=6
Press 'q' or Ctrl-C to abort, almost any other key for status
moonligh56       (?)
1g 0:00:00:00 DONE (2021-01-14 01:03) 14.28g/s 8076Kp/s 8076Kc/s 8076KC/s hotrats56..modena56
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed
```

## Custom wordlist generation
As I said in the previous task mangling rules avoid to waste storage space and time but there are some cases where generating a custom wordlist could be a better idea:
- You will often re-use the wordlist, generating one will save computation power rather than using a mangling rule
- You want to use the wordlist with several tools
- You want to use a tool that support wordlists but not mangling rules
- You find the custom rule syntax of John too complex

#### I'll update later.