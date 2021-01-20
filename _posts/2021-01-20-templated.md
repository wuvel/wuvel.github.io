---
title: "Hack The Box - Templated"
categories:
  - HackTheBox
tags:
  - hackthebox
  - challenges
  - ssti
---
Can you exploit this simple mistake?

## Enumeration
Let's check the given IP.

<a href="/assets/images/hackthebox/templated/1.png"><img src="/assets/images/hackthebox/templated/1.png"></a>

It's powered by Flask/Jinja2. The most common vulnerabilities at Flask/Jinja 2 is Server Side Template Injection (SSTI). So, let's try basic SSTI payload. We can inject the payload at the URL, because there is no form here.

<a href="/assets/images/hackthebox/templated/2.png"><img src="/assets/images/hackthebox/templated/2.png"></a>

SSTI confirmed! I used the payload from [this site](https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2/) and i got Remote Command Execution (RCE) here!

<a href="/assets/images/hackthebox/templated/3.png"><img src="/assets/images/hackthebox/templated/3.png"></a>

## The flag

Let's look for the `flag` by listing the directories and files.

<a href="/assets/images/hackthebox/templated/4.png"><img src="/assets/images/hackthebox/templated/4.png"></a>

There is `flag.txt` there. Let's `cat` it out.

<a href="/assets/images/hackthebox/templated/5.png"><img src="/assets/images/hackthebox/templated/5.png"></a>

We got our flag! It's **HTB{t3mpl4t3s_4r3_m0r3_p0w3rfu1_th4n_u_th1nk!}**.

## Lesson learned
- RCE from SSTI at Jinja2


