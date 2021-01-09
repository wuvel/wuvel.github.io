---
title: "TryHackMe - Hashing - Crypto 101"
categories:
  - Writeup
tags:
  - crypto
  - hashing
  - hashing algorithm
  - writeup
  - tryhackme
  - hacking
---
An introduction to Hashing, as part of a series on crypto.

## Key Terms
Here are the **important** key terms to hashing:

| Terms | Description |
| ----- | ----------- |
| Plaintext | **Data before encryption or hashing**, often text but not always. Could be a photograph or other file |
| Encoding | **NOT** a form of encryption, just a form of **data representation** like base64. Immediately reversible |
| Hash | A hash is the **output of a hash function**. Hashing can also be used as a verb, "to hash", meaning to produce the hash value of some data |
| Brute force | **Attacking** cryptography by trying every **different password** or every **different key** |
| Cryptanalysis | **Attacking** cryptography by finding a **weakness** in the **underlying maths** |


#### Is base64 encryption or encoding?
> In programming, Base64 is a group of binary-to-text **encoding** schemes that represent binary data ...

Reference: [Wikipedia](https://en.wikipedia.org/wiki/Base64).

## What is a hash function?
Hash function 101:
- Hash functions are quite different from encryption. There is no key, and it’s meant to be impossible (or very very difficult) to go from the output back to the input.
- A hash function takes some input data of any size, and creates a summary or "digest" of that data and the output is a fixed size.
- Good hashing algorithms will be (relatively) fast to compute, and slow to reverse (Go from output and determine input). 
Any small change in the input data (even a single bit) should cause a large change in the output.
- The output of a hash function is normally raw bytes, which are then **encoded**. Common encodings for this are **base64** or **hexadecimal**. Decoding these won’t give you anything useful.

Attacking hash:
- A hash collision is when 2 different inputs give the same output. 
- Due to the **pigeonhole** effect, collisions are not avoidable. The pigeonhole effect is basically, there are a set number of different output values for the hash function, but you can give it any size input. As there are more inputs than outputs, some of the inputs must give the same output. If you have 128 pigeons and 96 pigeonholes, some of the pigeons are going to have to share.
- MD5 and SHA1 have been attacked, and made technically insecure due to engineering hash collisions.
- The MD5 collision example is available from [https://www.mscs.dal.ca/~selinger/md5collision/](https://www.mscs.dal.ca/~selinger/md5collision/) and details of the SHA1 Collision are available from [https://shattered.io/](https://shattered.io/).

#### What is the output size in bytes of the MD5 hash function?
> The MD5 message-digest algorithm is a widely used hash function producing a **128-bit** hash value. \*_Note: 128-bit = 16 bytes._

#### Can you avoid hash collisions? (Yea/Nay)
> Nay, because all the hash come with fixed size, so it's still possible but need much more time.

#### If you have an 8 bit hash output, how many possible hashes are there?
```python
>>> pow(2,8)
256
# 1 bit can fill 1 or 0.
```

## Uses for hashing
Hashing is used for 2 main purposes in Cyber Security. To verify integrity of data (More on that later), or for verifying passwords.
- Most webapps need to verify a user's password at some point. Storing these passwords in plain text would be bad.
- A rainbow table is a lookup table of hashes to plaintexts, so you can quickly find out what password a user had just from the hash. A rainbow table trades time taken to crack a hash for hard disk space, but they do take time to create.
- To protect against rainbow tables, we add a salt to the passwords. The salt is randomly generated and stored in the database, unique to each user.

Rainbow table example:

| Hash | Password |
| ---- | -------- |
| 02c75fb22c75b23dc963c7eb91a062cc | zxcvbnm |
| b0baee9d279d34fa1dfd71aadb908c3f | 11111 |
| c44a471bd78cc6c2fea32b9fe028d30a | asdfghjkl |
| d0199f51d2728db6011945145a1b607a | basketball |
| dcddb75469b4b4875094e14561e573d8 | 000000 |
| e10adc3949ba59abbe56e057f20f883e | 123456 |
| e19d5cd5af0378da05f63f891c7467af | abcd1234 |
| e99a18c428cb38d5f260853678922e03 | abc123 |
| fcea920f7412b5da7be0cf42b8c93759 | 1234567 |

#### Crack the hash "d0199f51d2728db6011945145a1b607a" using the rainbow table manually.
> From the table above, it's:<br>d0199f51d2728db6011945145a1b607a:basketball 

#### Crack the hash "5b31f93c09ad1d065c0491b764d04933" using online tools
> Result: 5b31f93c09ad1d065c0491b764d04933:tryhackme<br><br>From [this](https://hashes.com/en/decrypt/hash) site.

Should you encrypt passwords? Yea/Nay
> Nay, we need the password to verify our session, so we better hash passwords.

## Recognising password hashes
- Automated hash recognition tools such as [hashID](https://pypi.org/project/hashID/) exist, but they are unreliable for many formats.
- Use a healthy combination of context and tools.  If you found the hash in a web application database, it's more likely to be md5 than NTLM. Automated hash recognition tools often get these hash types mixed up, which highlights the importance of learning yourself.
- Unix style password hashes are very easy to recognise, as they have a prefix. The standard format is `$format$rounds$salt$hash`. 
- Windows passwords are hashed using NTLM, which is a variant of md4. They're visually identical to md4 and md5 hashes, so it's very important to use context to work out the hash type.
- On Linux, password hashes are stored in `/etc/shadow` that readable by root only and usually store in `/etc/passwd` file that readable by everyone.
- On Windows, password hashes are stored in the SAM. Windows tries to prevent normal users from dumping them, but tools like mimikatz exist for this.

Most Unix style password prefixes:

| Prefix | Algorithm |
| ------ | --------- |
| $1$	md5crypt | used in Cisco stuff and older Linux/Unix systems |
| $2$, $2a$, $2b$ | $2x$, $2y$	Bcrypt (Popular for web applications) |
| $6$	| sha512crypt(Default for most Linux/Unix systems) |

A great place to find more hash formats and password prefixes is the hashcat example page, available here: [https://hashcat.net/wiki/doku.php?id=example_hashes](https://hashcat.net/wiki/doku.php?id=example_hashes).

#### How many rounds does sha512crypt ($6$) use by default?
- We can see the default value for `rounds` at `sha512-crypt.c` file or you can found it [here](https://github.com/lattera/glibc/blob/master/crypt/sha512-crypt.c).
```c++
...
/* Maximum salt string length.  */
#define SALT_LEN_MAX 16
/* Default number of rounds if not explicitly specified.  */
#define ROUNDS_DEFAULT 5000
/* Minimum number of rounds.  */
#define ROUNDS_MIN 1000
/* Maximum number of rounds.  */
#define ROUNDS_MAX 999999999
...
```

#### What's the hashcat example hash (from the website) for Citrix Netscaler hashes?
> 8100	Citrix NetScaler	1765058016a22f1b4e076dccd1c3df4e8e5c0839ccded98ea<br><br>From [https://hashcat.net/wiki/doku.php?id=example_hashes](https://hashcat.net/wiki/doku.php?id=example_hashes).

#### How long is a Windows NTLM hash, in characters?
> Example: b4b9b02e6f09a9bd760f388b67351e2b<br><br>So, it's 32 characters.

## Password Cracking
- You can't "decrypt" password hashes. They're not encrypted. 
You have to crack the hashes by hashing a large number of different inputs (often rockyou, these are the possible passwords), potentially adding the salt if there is one and comparing it to the target hash. Once it matches, you know what the password was.
- Tools like Hashcat and John the Ripper are normally used for Password Cracking.

**NEVER** use `--force` for hashcat. It can lead to false positives (wrong passwords being given to you) and false negatives (skips over the correct hash).
{: .notice--warning}

#### Crack this hash: $2a$06$7yoU3Ng8dHTXphAg913cyO6Bjs3K5lB nwq5FJyA6d01pMSrddr1ZG
```bash
$ john -format=bcrypt -wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 64 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
REDACTED         (?)
1g 0:00:00:03 DONE (2021-01-09 02:15) 0.2666g/s 3945p/s 3945c/s 3945C/s backoff..puisor
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

#### Crack this hash: 9eb7ee7f551d2f0ac684981bd1f1e2fa4a37590199636753ef e614d4db30e8e1
> Hash	Type	Result<br>
9eb7ee7f551d2f0ac684981bd1f1e2fa4a37590199636 753efe614d4db30e8e1	sha256	halloween<br><br>From [crackstation](https://crackstation.net/).

#### Crack this hash: $6$GQXVvW4EuM$ehD6jWiMsfNorxy5SI NsgdlxmAEl3.yif0/c3NqzGLa0P.S7KRDYjycw5bnYkF5 ZtB8wQy8KnskuWQS3Yr1wQ0
```bash
$ john -format=sha512crypt -wordlist=/usr/share/wordlists/rockyou.txt hash.txt                1 ⨯
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
REDACTED         (?)
1g 0:00:00:03 DONE (2021-01-09 02:18) 0.2597g/s 4887p/s 4887c/s 4887C/s sweetgurl..cordoba
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

#### Bored of this yet? Crack this hash: b6b0d451bbf6fed658659a9e7e5598fe
> Hash	Type	Result<br>
b6b0d451bbf6fed658659a9e7e5598fe	md5	funforyou<br><br>From [crackstation](https://crackstation.net/).

## Hashing for integrity checking
- Hashing can be used to check that files haven't been changed. If you put the same data in, you always get the same data out. If even a single bit changes, the hash will change a lot. 
This means you can use it to check that files haven't been modified or to make sure that they have downloaded correctly.
- You can also use hashing to find duplicate files, if two pictures have the same hash then they are the same picture.
- HMAC is a method of using a cryptographic hashing function to verify the authenticity and integrity of data.
-  A HMAC can be used to ensure that the person who created the HMAC is who they say they are (authenticity), and that the message hasn’t been modified or corrupted (integrity). They use a secret key, and a hashing algorithm in order to produce a hash.

#### What's the SHA1 sum for the amd64 Kali 2019.4 ISO? [http://old.kali.org/kali-images/kali-2019.4/](http://old.kali.org/kali-images/kali-2019.4/)
> 186c5227e24ceb60deb711 f1bdc34ad9f4718ff9  kali-linux-2019.4-amd64.iso<br><br>From [kali](http://old.kali.org/kali-images/kali-2019.4/SHA1SUMS).

#### What's the hashcat mode number for HMAC-SHA512 (key = $pass)?
> 1750<br><br>From [Hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes).
