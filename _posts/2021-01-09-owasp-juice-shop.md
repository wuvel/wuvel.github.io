---
title: "TryHackMe - OWASP Juice Shop"
categories:
  - TryHackMe
tags:
  - OWASP Juice Shop
  - writeup
  - tryhackme
  - hacking
---
This room uses the Juice Shop vulnerable web application to learn how to identify and exploit common web application vulnerabilities.

## Let's go on an adventure!
In Burp, set the Intercept mode to off and then browse around the site. This allows Burp to log different requests from the server that may be helpful later. We will do a **reconnaissance** to the web.


### 1. What's the Administrator's email address?
- Follow the instructions at [TryHackMe](https://tryhackme.com/room/owaspjuiceshop) and we can get the answer.

<center><a href="/assets/images/tryhackme/owasp-juice-shop/1.png"><img src="/assets/images/tryhackme/owasp-juice-shop/1.png"></a></center>

### 2. What parameter is used for searching? 
- Follow the instructions at [TryHackMe](https://tryhackme.com/room/owaspjuiceshop) and we can get the answer.

<center><a href="/assets/images/tryhackme/owasp-juice-shop/2.png"><img src="/assets/images/tryhackme/owasp-juice-shop/2.png"></a></center>

### 3. What show does Jim reference in his review? 
- Follow the instructions at [TryHackMe](https://tryhackme.com/room/owaspjuiceshop) and we can get the answer.

<center><a href="/assets/images/tryhackme/owasp-juice-shop/3.png"><img src="/assets/images/tryhackme/owasp-juice-shop/3.png"></a></center>


## Inject the juice
- Injection vulnerabilities are quite dangerous to a company as they can potentially cause **downtime** and/or **loss of data**.
- Identifying injection points within a web application is usually quite simple, as most of them will **return an error**.

Type of injection attacks:

| Name | Description |
| ---- | ----------- |
| SQL Injection | When attacker enters a malicious or malformed query to either retrieve or tamper data from a database. And in some cases, log into accounts. |
| Command Injection | When web applications take input or user-controlled data and run them as system commands. An attacker may tamper with this data to execute their own system commands. This can be seen in applications that perform misconfigured ping tests. |
| Email Injection | Security vulnerability that allows malicious users to send email messages without prior authorization by the email server. These occur when the attacker adds extra data to fields, which are not interpreted by the server correctly. |

### 1. Log into the administrator account!
- Follow the instructions at [TryHackMe](https://tryhackme.com/room/owaspjuiceshop) and we can get the flag after we logged in.

<center><a href="/assets/images/tryhackme/owasp-juice-shop/4.png"><img src="/assets/images/tryhackme/owasp-juice-shop/4.png"></a></center>

### 2. Log into the Bender account!
- Follow the instructions at [TryHackMe](https://tryhackme.com/room/owaspjuiceshop) and we can get the flag after we logged in.

<center><a href="/assets/images/tryhackme/owasp-juice-shop/5.png"><img src="/assets/images/tryhackme/owasp-juice-shop/5.png"></a></center>

## Who broke my lock?!
We will look at exploiting authentication through different **flaws**. When talking about flaws within authentication, we include mechanisms that are **vulnerable** to **manipulation**. These mechanisms, listed below, are what we will be exploiting. 
- Weak passwords in high privileged accounts
- Forgotten password pages
- More information: [Broken Authentication](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A2-Broken_Authentication)

### 1. Bruteforce the Administrator account's password!
- Follow the instructions at [TryHackMe](https://tryhackme.com/room/owaspjuiceshop) and we can get the flag after we logged in as admin.

<center><a href="/assets/images/tryhackme/owasp-juice-shop/6.png"><img src="/assets/images/tryhackme/owasp-juice-shop/6.png"></a></center>

### 2. Reset Jim's password!
- Follow the instructions at [TryHackMe](https://tryhackme.com/room/owaspjuiceshop) and we can get the flag after we resetted jim's password.

<center><a href="/assets/images/tryhackme/owasp-juice-shop/7.png"><img src="/assets/images/tryhackme/owasp-juice-shop/7.png"></a></center>

## AH! Don't look!
Most of the time, data protection is not applied consistently across the web application making certain pages **accessible** to the public. Other times information is **leaked** to the public without the knowledge of the developer, making the web application **vulnerable** to an attack. 

### 1. Access the Confidential Document!
- Follow the instructions at [TryHackMe](https://tryhackme.com/room/owaspjuiceshop) and we can get the flag after we downloaded the ftp file.

<center><a href="/assets/images/tryhackme/owasp-juice-shop/8.png"><img src="/assets/images/tryhackme/owasp-juice-shop/8.png"></a></center>

### 2. Log into MC SafeSearch's account!
- Follow the instructions at [TryHackMe](https://tryhackme.com/room/owaspjuiceshop) and we can get the flag after we downloaded the ftp file.

<center><a href="/assets/images/tryhackme/owasp-juice-shop/9.png"><img src="/assets/images/tryhackme/owasp-juice-shop/9.png"></a></center>

### 3. Download the Backup file!
- Follow the instructions at [TryHackMe](https://tryhackme.com/room/owaspjuiceshop) and we can get the flag after we downloaded the backup file.

<center><a href="/assets/images/tryhackme/owasp-juice-shop/10.png"><img src="/assets/images/tryhackme/owasp-juice-shop/10.png"></a></center>

## Who's flying this thing?
- Modern-day systems will allow for **multiple users** to have access to different pages.
- Administrators most commonly use an **administration page** to edit, add and remove different elements of a website.

When Broken Access Control exploits or bugs are found, it will be categorised into one of two types:

| Type | Description |
| ----------- | ----- |
| **Horizontal** Privilege Escalation | Occurs when a user can perform an action or access data of another user with the **same level** of permissions. |
| **Vertical** Privilege Escalation | Occurs when a user can perform an action or access data of another user with a **higher level** of permissions. |

### 1. Access the administration page!
- Follow the instructions at [TryHackMe](https://tryhackme.com/room/owaspjuiceshop) and we can get the flag.

<center><a href="/assets/images/tryhackme/owasp-juice-shop/11.png"><img src="/assets/images/tryhackme/owasp-juice-shop/11.png"></a></center>

### 2. View another user's shopping basket!
- Follow the instructions at [TryHackMe](https://tryhackme.com/room/owaspjuiceshop) and we can get the flag.

<center><a href="/assets/images/tryhackme/owasp-juice-shop/12.png"><img src="/assets/images/tryhackme/owasp-juice-shop/12.png"></a></center>

### 3. Remove all 5-star reviews!
- Follow the instructions at [TryHackMe](https://tryhackme.com/room/owaspjuiceshop) and we can get the flag.

<center><a href="/assets/images/tryhackme/owasp-juice-shop/13.png"><img src="/assets/images/tryhackme/owasp-juice-shop/13.png"></a></center>

## Where did that come from?
XSS or _Cross-site scripting_ is a vulnerability that allows attackers to **run javascript** in web applications. These are one of the most found bugs in web applications. Their complexity ranges from easy to extremely hard, as each web application parses the **queries** in a different way. 

There are three major types of XSS attacks:

| Type | Description |
| ----------- | ----- |
| DOM (Special)     | **DOM XSS** (Document Object Model-based Cross-site Scripting) uses the HTML environment to execute malicious javascript. This type of attack commonly uses the `<script>...</script>` HTML tag. |
| Persistent (Server-side)     | **Persistent XSS** is javascript that is run when the server loads the page containing it. These can occur when the server **does not sanitise** the user data when it is **uploaded** to a page. These are commonly found on **blog posts**.  |
| Reflected (Client-side)        | **Reflected XSS** is javascript that is run on the *client-side* end of the web application. These are most commonly found when the server doesn't sanitise **search** data.  |

### 1. Perform a DOM XSS!
- Follow the instructions at [TryHackMe](https://tryhackme.com/room/owaspjuiceshop) and we can get the flag.

<center><a href="/assets/images/tryhackme/owasp-juice-shop/14.png"><img src="/assets/images/tryhackme/owasp-juice-shop/14.png"></a></center>

### 2. Perform a persistent XSS!
- Follow the instructions at [TryHackMe](https://tryhackme.com/room/owaspjuiceshop) and we can get the flag.

<center><a href="/assets/images/tryhackme/owasp-juice-shop/15.png"><img src="/assets/images/tryhackme/owasp-juice-shop/15.png"></a></center>

### 3. Perform a reflected XSS!
- Follow the instructions at [TryHackMe](https://tryhackme.com/room/owaspjuiceshop) and we can get the flag.

<center><a href="/assets/images/tryhackme/owasp-juice-shop/16.png"><img src="/assets/images/tryhackme/owasp-juice-shop/16.png"></a></center>

## Exploration
We can check out the `/#/score-board/` section on Juice-shop. Here e can see your completed tasks as well as other tasks in varying difficulty.

### 1. Access the /#/score-board/ page
- Paste `/#/score-board/` to the Browser after the machine IP.
<center><a href="/assets/images/tryhackme/owasp-juice-shop/17.png"><img src="/assets/images/tryhackme/owasp-juice-shop/17.png"></a></center>