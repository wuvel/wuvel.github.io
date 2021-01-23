---
title: "TryHackMe - Web Scanning"
categories:
  - TryHackMe
tags:
  - zap
  - nikto
  - writeup
  - tryhackme
---
Learn the basics of automated web scanning!

## ...I'm supposed to scan with that?
A short quiz over the various switches used with Nikto as well as a quick scan against our target. All we'll need for this is the help menu for nikto. 
- First and foremost, what switch do we use to set the target host?
> -h
- Websites don't always properly redirect to their secure transport port and can sometimes have different issues depending on the manner in which they are scanned. How do we disable secure transport?
> -nossl
- How about the opposite, how do we force secure transport?
> -ssl
- What if we want to set a specific port to scan?
> -p
- As the web is constantly evolving, so is Nikto. A database of vulnerabilities represents a core component to this web scanner, how do we verify that this database is working and free from error?
> -dbcheck
- If instructed to, Nitko will attempt to guess and test both files within directories as well as usernames. Which switch and numerical value do we use to set Nikto to enumerate usernames in Apache? Keep in mind, this option is deprecated in favor of plugins, however, it's still a great option to be aware of for situational usage.
> -mutate 3
- Suppose we know the username and password for a web forum, how do we set Nikto to do a credentialed check? Suppose the username is admin and the password is PrettyAwesomePassword1234
> -id admin:PrettyAwesomePassword1234
- Let's scan our target machine, what web server do we discover and what version is it?

    ```bash
    $ nikto -h 10.10.198.253                         
    - Nikto v2.1.6
    ---------------------------------------------------------------------------
    + Target IP:          10.10.198.253
    + Target Hostname:    10.10.198.253
    + Target Port:        80
    + Start Time:         2021-01-23 02:10:42 (GMT-5)
    ---------------------------------------------------------------------------
    + Server: Apache/2.4.7 (Ubuntu)
    + Cookie PHPSESSID created without the httponly flag
    + Retrieved x-powered-by header: PHP/5.5.9-1ubuntu4.26
    + The anti-clickjacking X-Frame-Options header is not present.
    + The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
    + The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
    + Root page / redirects to: login.php
    + No CGI Directories found (use '-C all' to force check all possible dirs)
    + Apache/2.4.7 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
    + OSVDB-3268: /config/: Directory indexing found.
    + /config/: Configuration information may be available remotely.
    ```

- This box is vulnerable to very poor directory control due to it's web server version, what directory is indexed that really shouldn't be?
> config
- Nikto scans can take a while to fully complete, which switch do we set in order to limit the scan to end at a certain time?
> -until
- But wait, there's more! How do we list all of the plugins are available?
> -list-plugins
- On the flip-side of the database, plugins represent another core component to Nikto. Which switch do we use to instruct Nikto to use plugin checks to find out of date software on the target host? Keep in mind that when testing this command we need to specify the host we intend to run this against. For submitting your answer, use only the base command with the out of date option. 
> -Plugins outdated
- Finally, what if we'd like to use our plugins to run a series of standard tests against the target host?
> -Plugins tests

## Zip ZAP!
- Launch ZAP, what option to we set in order to specify what we are attacking?
> URL to attack
- ZAP will discover a file that typically contains pages which well-behaved web indexing engines will read in order to know which sections of a site to avoid. What is the name of this file? (Lucky for us, our scanner isn't what we would call 'well-behaved'!)
> robots.txt
- One entry is included in the disallow section of this file, what is it?
> /
- ZAP will find a directory that contains images for our application, what is the path for that directory? (This is what will follows the name/ip of the website)
> /dvwa/images
- This website doesn't force a secure connection by default and ZAP isn't pleased with it. Which related cookie is ZAP upset about?
> httponly
- Featured in various rooms on TryHackMe, Cross-Site Scripting is a vicious attack that is becoming ever more common on the open web. What Alert does ZAP produce to let us know that this site is vulnerable to XSS? Note, there are often a couple warnings produced for this, look for one more so directly related to the web client.
> Web Browser XSS Protection Not Enabled
- The ZAP proxy spider represents the component responsible for 'crawling' the site. What site is found to be out of scope?
> http://www.dvwa.co.uk
- ZAP will use primarily two methods in order to scan a website, which of these two HTTP methods requests content?
> GET
- Which option attempts to submit content to the website?
> POST