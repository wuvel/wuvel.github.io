---
title: "TryHackMe - Encryption - Crypto 101"
categories:
  - Writeup
tags:
  - crypto
  - encryption
  - cryptography
  - writeup
  - tryhackme
  - hacking
---
An introduction to encryption, as part of a series on crypto

## Key Terms
Here are the **important** key terms to cryptography:

| Terms | Description |
| ----- | ----------- |
| Ciphertext | The **result** of **encrypting** a plaintext, encrypted data |
| Cipher | A **method** of **encrypting** or **decrypting** data. Modern ciphers are cryptographic, but there are many non cryptographic ciphers like Caesar |
| Plaintext | **Data before encryption**, often text but not always. Could be a photograph or other file |
| Encryption | **Transforming** data into ciphertext, using a cipher |
| Encoding | NOT a form of encryption, just a form of **data representation** like base64. Immediately reversible |
| Key | Some **information** that is needed to **correctly decrypt** the ciphertext and obtain the plaintext |
| Passphrase | Separate to the key, a passphrase is similar to a password and used to protect a key |
| Asymmetric encryption | Uses **different** keys to encrypt and decrypt |
| Symmetric encryption | Uses the **same** key to encrypt and decrypt |
| Brute force | **Attacking** cryptography by trying every **different password** or every **different key** |
| Cryptanalysis | **Attacking** cryptography by finding a **weakness** in the **underlying maths** |
| Alice and Bob | Used to represent 2 people who generally want to communicate. They’re named Alice and Bob because this gives them the initials A and B. Go to this [link](https://en.wikipedia.org/wiki/Alice_and_Bo) for more information, as these extend through the alphabet to represent many different people involved in communication |

#### Are SSH keys protected with a passphrase or a password?
> SSH keys are used for authenticating users in information systems. The SSH keys themselves are **private keys**; the **private key** is further encrypted using a **symmetric encryption** key derived from a **passphrase**. The key derivation is done using a **hash function**.

Reference: [ssh](https://www.ssh.com/ssh/passphrase).

## Why is Encryption important?
- Cryptography is used to protect **confidentiality**, ensure **integrity**, ensure **authenticity**.
- When logging into **TryHackMe**, your credentials were sent to the server. These were encrypted, otherwise someone would be able to capture them by snooping on your connection.
- When you connect to **SSH**, your client and the server establish an encrypted tunnel so that no one can snoop on your session.
- When you connect to your **bank**, there’s a certificate that uses cryptography to prove that it is actually your bank rather than a hacker.
- When you download a **file**, how do you check if it downloaded right? You can use cryptography here to verify a checksum of the data.
- Whenever sensitive user data needs to be stored, it **should be encrypted**. 
- [PCI-DSS](https://www.pcisecuritystandards.org/documents/PCI_DSS_for_Large_Organizations_v1.pdf) state that the data should be **encrypted** both at rest (in storage) AND while being transmitted.
- Passwords should not be stored in plaintext, and you should use hashing to manage them safely.

#### What does SSH stand for?
> SSH or **Secure Shell** is a cryptographic network protocol for operating network services securely over an unsecured network. Typical applications include remote command-line, login, and remote command execution, but any network service can be secured with SSH

Reference: [Wikipedia](https://en.wikipedia.org/wiki/SSH_(Secure_Shell)).

#### How do webservers prove their identity?
> Certificates are also a key use of public key cryptography, linked to digital signatures. It prove the identity of who we are (webservers).

#### What is the main set of standards you need to comply with if you store or process payment card details?
> [PCI-DSS](https://www.pcisecuritystandards.org/documents/PCI_DSS_for_Large_Organizations_v1.pdf) state that the data should be encrypted both at rest (in storage) AND while being transmitted, including when we store payment card details.

## Crucial Crypto Maths
There's a little bit of math(s) that comes up relatively often in cryptography, which is the **Modulo operator**.
- Modulo operator has the "**`%`**" symbol.
- X % Y is the **remainder** when X is divided by Y.
- Modulo is **not reversible**. If I gave you an equation: x % 5 = 4, there are infinite values of x that will be valid.

For an example:
- 25 % 5 = 0 (5*5 = 25 so it divides exactly with no remainder).
- 23 % 6 = 5 (23 does not divide evenly by 6, there would be a remainder of 5)

#### What's 30 % 5?
> 30 % 5 = 0 (5*6 = 30, no remainder).

#### What's 25 % 7
> 25 % 7 = 4 (25 does not divide evenly by 7, there would be a reminder of 4).

#### What's 118613842 % 9091
```python
print(118613842 % 9091)

//Output:
3565
```

## Types of Encryption
The two main categories of Encryption are **symmetric** and **asymmetric**.
- **Symmetric encryption** uses the **same key** to encrypt and decrypt the data. Examples of Symmetric encryption are **DES** (Broken) and **AES**. These algorithms tend to be faster than asymmetric cryptography, and use smaller keys (128 or 256 bit keys are common for AES, DES keys are 56 bits long).
- **Asymmetric encryption** uses a **pair of keys**, one to encrypt and the other in the pair to decrypt. Examples are **RSA** and **Elliptic Curve Cryptography**. Normally these keys are referred to as a **public key** and a **private key**. Data encrypted with the private key can be decrypted with the public key, and vice versa. Your private key needs to be kept private, hence the name. Asymmetric encryption tends to be slower and uses larger keys, for example RSA typically uses 2048 to 4096 bit keys.
- RSA and Elliptic Curve cryptography are based around different mathematically difficult (intractable) problems, which give them their strength.

#### Should you trust DES? Yea/Nay
> Nay, because DES using **symmetric encryption** that use **same key** to encrypt and decrypt.

#### What was the result of the attempt to make DES more secure so that it could be used for longer?
> AES is an important algorithm and was originally meant to replace DES (and its **more secure variant triple DES**) as the standard algorithm for non-classi?ed material

Reference: [UMSL](http://www.umsl.edu/~siegelj/information_theory/projects/des.netau.net/des%20history.html).

#### Is it ok to share your public key? Yea/Nay
> Yea, remember to never share your **private key**, because it everything!

## RSA - Rivest Shamir Adleman
RSA from the math(s) side:
- RSA is based on the mathematically difficult problem of working out the **factors** of a large number. It’s very quick to multiply two prime numbers together, say 17*23 = 391, but it’s quite difficult to work out what two prime numbers multiply together to make 14351 (113x127 for reference).

RSA from the attacking side:
- Normally requiring you to calculate variables or break some encryption based on RSA on some CTFs challenge(s).
- There are some excellent tools for defeating RSA challenges in CTFs, which is [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool) and [rsatool](https://github.com/ius/rsatool).
- The key variables that we need to know about for RSA in CTFs are p, q, m, n, e, d, and c.
- "p" and "q" are large prime numbers, "n" is the product of p and q. The public key is "n" and "d", the private key is "n" and "e". "m" is used to represent the message (in plaintext) and "c" represents the ciphertext (encrypted text).

**Info Notice:** There’s a lot more maths to RSA, and it gets quite complicated fairly quickly. If you want to learn the maths behind it, I recommend reading **MuirlandOracle’s blog** post [here]( https://muirlandoracle.co.uk/2020/01/29/rsa-encryption/).
{: .notice--info}

#### p = 4391, q = 6659. What is n?
> We can use RSA calculator online at [here](https://www.cs.drexel.edu/~jpopyack/IntroCS/HW/RSAWorksheet.html). The result from p*q is _29239669_.

## Establishing Keys Using Asymmetric Cryptography
- A very common use of asymmetric cryptography is **exchanging keys** for symmetric encryption.
- Asymmetric encryption tends to be slower, so for things like HTTPS symmetric encryption is better.
- More detail about HTTPS [here](https://robertheaton.com/2014/03/27/how-does-https-actually-work/).

## Digital signatures and Certificates
- Digital signatures are a way to prove the **authenticity** of **files**, to prove who created or modified them. Using asymmetric cryptography, you produce a signature with your private key and it can be verified using your public key.
- The simplest form of digital signature would be encrypting the document with your private key, and then if someone wanted to verify this signature they would decrypt it with your public key and check if the files match.
- Certificates are also a key use of public key cryptography, linked to digital signatures. A common place where they’re used is for HTTPS.
- The certificates have a chain of trust, starting with a root CA (certificate authority). Root CAs are automatically trusted by your device, OS, or browser from install. Certs below that are trusted because the Root CAs say they trust that organisation.

#### What company is TryHackMe's certificate issued to?
1. Visit TryHackMe website.
2. Click the "Lock" logo besides the URL.
3. Click the ">" logo.
4. Here is the results:
<center><a href="/assets/images/tryhackme/encryption-crypto-101/1.png"><img src="/assets/images/tryhackme/encryption-crypto-101/1.png"></a></center>

## SSH Authentication
- By default, SSH is authenticated using **usernames** and **passwords** in the same way that you would log in to the physical machine. 
- At some point, you’re almost certain to hit a machine that has SSH configured with **key authentication** instead that uses public and private keys to prove that the client is a valid and authorised user on the server.
- By default, SSH keys are **RSA keys**.
- We can generate pairs of keys using `ssh-keygen` program.
- It’s very important to mention that the passphrase to decrypt the key isn’t used to identify you to the server at all, all it does is decrypt the SSH key. The passphrase is never transmitted, and never leaves your system.
- We can use tools like** John the Ripper**, you can attack an encrypted SSH key to attempt to find the passphrase, which highlights the importance of using a secure passphrase and keeping your private key private.
- On Linux, the `~/.ssh` folder is the default place to store these keys for OpenSSH. The `authorized_keys` file in this directory holds **public keys** that are allowed to access the server if key authentication is enabled.
- We can use private SSH key with `ssh -i keyNameGoesHere user@host` command with the correct permission for the key (600 or stricter).

**Info!** SSH keys are an excellent way to “upgrade” a reverse shell, assuming the user has login enabled (www-data normally does not, but regular users and root will). 
{: .notice--info}

**Watch Out!** Leaving an SSH key in authorized_keys on a box can be a useful backdoor, and you don't need to deal with any of the issues of reverse shells like Control-C or lack of tab completion.
{: .notice--danger}

#### What algorithm does the key use?
```bash
$ cat idrsa.id_rsa                                                                            1 ⨯
-----BEGIN **RSA** PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,0B5AB4FEB69AFB92B2100435B42B7949
...
```

#### Crack the password with John The Ripper and rockyou, what's the passphrase for the key?
1. Using ssh2john to make hashed format.
```bash
$ python /usr/share/john/ssh2john.py ~/Downloads/idrsa.id_rsa > ~/Downloads/id_rsa.hash
```
2. Crack it using wordlist rockyou!
```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash                      
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 6 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
**REDACTED**        (/home/kali/Downloads/idrsa.id_rsa)
1g 0:00:00:02 DONE
```

## Explaining Diffie Hellman Key Exchange
- Key exchange allows 2 people/parties to establish a set of common cryptographic keys without an observer being able to get these keys. Generally, to establish common symmetric keys.
- DH Key Exchange is often used alongside RSA public key cryptography, to prove the identity of the person you’re talking to with digital signing. This prevents someone from attacking the connection with a man-in-the-middle attack by pretending to be Bob.

how Diffie Hellman Key Exchange works:
1. Alice and Bob want to talk securely. They want to establish a common key, so they can use symmetric cryptography, but they don’t want to use key exchange with asymmetric cryptography. This is where DH Key Exchange comes in.
1. Alice and Bob both have secrets that they generate, let’s call these A and B. They also have some common material that’s public, let’s call this C.
1. We need to make some assumptions. Firstly, whenever we combine secrets/material it’s impossible or very very difficult to separate. Secondly, the order that they're combined in doesn’t matter.
1. Alice and Bob will combine their secrets with the common material, and form AC and BC. They will then send these to each other, and combine that with their secrets to form two identical keys, both ABC. Now they can use this key to communicate.

**Info!** Visual explanation [here](https://www.youtube.com/watch?v=NmM9HA2MQGI).
{: .notice--info}

## PGP, GPG and AES
- PGP stands for **Pretty Good Privacy**. It’s a software that implements encryption for encrypting files, performing digital signing and more.
- GPG is an Open Source implementation of PGP from the GNU project. You may need to use GPG to decrypt files in CTFs. With PGP/GPG, private keys can be protected with passphrases in a similar way to SSH private keys. You can attempt to crack this passphrase using John The Ripper and gpg2john.
- AES, sometimes called Rijndael after its creators, stands for Advanced Encryption Standard. It was a replacement for DES which had short keys and other cryptographic flaws. AES and DES both operate on blocks of data (a block is a fixed size series of bits).

##### You have the private key, and a file encrypted with the public key. Decrypt the file. What's the secret word?
```bash
$ gpg --import tryhackme.key                 
gpg: /home/kali/.gnupg/trustdb.gpg: trustdb created
gpg: key FFA4B5252BAEB2E6: public key "TryHackMe (Example Key)" imported
gpg: key FFA4B5252BAEB2E6: secret key imported
gpg: Total number processed: 1
gpg:               imported: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1
                                                                                                    
$ gpg --decrypt message.gpg                                   
gpg: encrypted with 1024-bit RSA key, ID 2A0A5FDC5081B1C5, created 2020-06-30
      "TryHackMe (Example Key)"
You decrypted the file!
The secret word is **REDACTED**.
```