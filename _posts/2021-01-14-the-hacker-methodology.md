---
title: "TryHackMe - The Hacker Methodology"
categories:
  - TryHackMe
tags:
  - linux
  - writeup
  - tryhackme
  - hacking
  - methodology
---
Introduction to the Hacker Methodology

## Methodology Outline 
The Process that pentesters follow is summarized in the following steps:
1. Reconnaissance
1. Enumeration/Scanning
1. Gaining Access
1. Privilege Escalation
1. Covering Tracks
1. Reporting

## Reconnaissance Overview
- Reconnaissance is all about **collecting information** about your target. Reconnaissance usually involves **no interaction** with the target(s) or system(s). 
- Reconnaissance is a pretty simple concept, think about what tools we can use on the internet to gather information about people.
- Reconnaissance usually involves using publicly available tools like Google to conduct research about your target.
- There are some specialized tools that we can utilize but for this introduction it is good to know the following tools. 
    - Google (specifically Google Dorking)
    - Wikipedia
    - PeopleFinder.com
    - who.is
    - sublist3r
    - hunter.io
    - builtwith.com
    - wappalyzer

#### Who is the CEO of SpaceX?
> Elon Musk

#### Do some research into the tool: sublist3r, what does it list?
> Subdomain enumeration

#### What is it called when you use Google to look for specific vulnerabilities or to research a specific topic of interest?
> Google dorking

## Enumeration and Scanning Overview
- This is where a hacker will start interacting with (scanning and enumerating) the target to attempt to find vulnerabilities related to the target.
- This is where more specialized tools start to come in to the arsenal. Tools like nmap, dirb, metasploit, exploit-db, Burp Suite and others are very useful to help us try to find vulnerabilities in a target.
- In the scanning and enumeration phase, the attacker is interacting with the target to determine its overall **attack surface**.
- The attack surface determines what the target might be vulnerable to in the Exploitation phase. These vulnerabilities might be a range of things: anything from a webpage not being properly locked down, a website leaking information, SQL Injection, Cross Site Scripting or any number of other vulnerabilities.
- To simplify - the enumeration and scanning phase is where we will try to **determine** WHAT the target might be **vulnerable** to.

#### What does enumeration help to determine about the target?
> Attack surface

#### Do some reconnaissance about the tool: Metasploit, what company developed it?
> Rapid7

#### What company developed the technology behind the tool Burp Suite?
> Portswigger

## Exploitation
- The exploitation phase can only be as good as the recon and enumeration phases before it, if you did not enumerate all vulnerabilities you may miss an opportunity, or if you did not look hard enough at the target - the exploit you have chosen may fail entirely!

**Remember!** Professional penetration tester never jumps into the exploitation phase without doing adequate reconnaissance and enumeration. 
{: .notice--info}

#### What is one of the primary exploitation tools that pentester(s) use?
> Metasploit

## Privilege Escalation
- After we have gained access to a victim machine via the exploitation phase, the next step is to escalate privileges to a higher user account.
- The following accounts are what we try to reach as a pentester:
    - In the Windows world, the target account is usually: Administrator or System.
    - In the Linux world, the target account is usually: root
- Once we gain access as a lower level user, we will try to run another exploit or find a way to become root or administrator.
- Privilege escalation can take many, many forms, some examples are:
- Cracking password hashes found on the target
    - Finding a vulnerable service or version of a service which will allow you to escalate privilege THROUGH the service
    - Password spraying of previously discovered credentials (password re-use)
    - Using default credentials
    - Finding secret keys or SSH keys stored on a device which will allow pivoting to another machine
    - Running scripts or commands to enumerate system settings like 'ifconfig' to find network settings, or the - command `find / -perm -4000 -type f 2>/dev/null` to see if the user has access to any commands they can run as root

#### In Windows what is usually the other target account besides Administrator?
> System

#### What thing related to SSH could allow you to login to another machine (even without knowing the username or password)?
> SSH Keys

## Covering Tracks
- Most professional/ethical penetration testers never have the need to "cover their tracks".
- Since the rules of engagement for a penetration test should be agreed to before the test occurs, the penetration tester should stop IMMEDIATELY when they have achieved privilege escalation and report the finding to the client. 
- As such, a professional will never cover their tracks because the assessment was planned to and agreed to beforehand.
- However, even though you do not cover your tracks, this does not resolve you of liability for your exploitation. Often you will need to assist the IT Administrator or system owner in cleaning up the exploit code that you utilized, and also recommending HOW to prevent the attack in the future.
- While ethical hackers rarely have a need to cover their tracks, you still must carefully track and notate all of the tasks that you performed as part of the penetration test to assist in fixing the vulnerabilities and recommending changes to the system owner.

## Reporting
- This is one of the most important phases where you will outline everything that you found. 
- The reporting phase often includes the following things:
    - The Finding(s) or Vulnerabilities
    - The CRITICALITY of the Finding
    - A description or brief overview of how the finding was discovered
    - Remediation recommendations to resolve the finding
- The amount of reporting documentation varies widely by the type of engagement that the pentester is involved in. A findings report generally goes in three formats:
    - Vulnerability scan results (a simple listing of vulnerabilities)
    - Findings summary (list of the findings as outlined above)
    - Full formal report.
- Here is how each type of reporting would look in practice:
    - A vulnerability report usually looks like this: 
    
        <a href="https://images.squarespace-cdn.com/content/v1/5516199be4b05ede7c57f94f/1446545768422-58BN3F2CNKLKMP22FHM4/ke17ZwdGBToddI8pDm48kJ510zKrPqMYDklP4IHY6ghZw-zPPgdn4jUwVcJE1ZvWQUxwkmyExglNqGp0IvTJZamWLI2zvYWH8K3-s_4yszcp2ryTI0HqTOaaUohrI8PIXMtOr48_aO8ZpATxJus3Zikh6e0Sdr9qHJBhZ3Dc8CI/Acunetix%2Bsample%2Breport.png"><img src="https://images.squarespace-cdn.com/content/v1/5516199be4b05ede7c57f94f/1446545768422-58BN3F2CNKLKMP22FHM4/ke17ZwdGBToddI8pDm48kJ510zKrPqMYDklP4IHY6ghZw-zPPgdn4jUwVcJE1ZvWQUxwkmyExglNqGp0IvTJZamWLI2zvYWH8K3-s_4yszcp2ryTI0HqTOaaUohrI8PIXMtOr48_aO8ZpATxJus3Zikh6e0Sdr9qHJBhZ3Dc8CI/Acunetix%2Bsample%2Breport.png"></a>

    - A findings summary is usually something like this:
        - **Finding:** SQL Injection in ID Parameter of Cats Page
        - **Criticality:** Critical
        - *Description:* Placing a payload of 1' OR '1'='1 into the ID parameter of the website allowed the viewing of all cat names in the cat Table of the database. Furthermore, a UNION SELECT SQL statement allowed the attacker to view all usernames and passwords stored in the Accounts table. 
        - **Remediation Recommendation:** Utilize a Prepared SQL statement to prevent SQL injection attacks

    - A full formal report sample can be found here: [https://github.com/hmaverickadams/TCM-Security-Sample-Pentest-Report](https://github.com/hmaverickadams/TCM-Security-Sample-Pentest-Report.).

#### What would be the type of reporting that involves a full documentation of all findings within a formal document?
> full formal report

#### What is the other thing that a pentester should provide in a report beyond: the finding name, the finding description, the finding criticality
> Remediation Recommendation