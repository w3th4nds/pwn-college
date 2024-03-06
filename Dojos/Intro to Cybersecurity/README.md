<div align="center">
    <h1 style="color:#008000;"> Talking Web </h1>
</div>

I need to clarify that I am not familiar with web exploitation so my solvers might not be the best out there.

### Level 1 - Send an HTTP request using curl

```bash
$ curl http://127.0.0.1:80
```

### Level 2 - Send an HTTP request using nc

From the `man` page of `nc`:

```bash
TALKING TO SERVERS
     It is sometimes useful to talk to servers “by hand” rather than through a user interface.
     It can aid in troubleshooting, when it might be necessary to verify what data a server is
     sending in response to commands issued by the client.  For example, to retrieve the home
     page of a web site:

           $ printf "GET / HTTP/1.0\r\n\r\n" | nc host.example.com 80
```

```bash
$ echo -e "GET / HTTP/1.0\r\n\r\n" | nc 127.0.0.1 80 | grep pwn.college{
```

### Level 3 - Send an HTTP request using python

```python
import requests

url = 'http://127.0.0.1:80'

response = requests.get(url)

print(response.text)
```

### Level 4 - Set the host header in an HTTP request using curl

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag.
The Host HTTP header must be 997560d9948a1c045d184fcc079009eb
You must make this request using the curl command
```

```bash
$ curl -H "Host: 997560d9948a1c045d184fcc079009eb" 127.0.0.1 80
```

### Level 5 - Set the host header in an HTTP request using nc

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag.
The Host HTTP header must be 738ad737419bb5d94d6d73478eb31c28
You must make this request using the nc command
```

```bash
$ echo -e "GET / HTTP/1.0\r\nHost: 738ad737419bb5d94d6d73478eb31c28\r\nConnection: close\r\n\r\n" | nc 127.0.0.1 80 | grep pwn.college{
```

### Level 6 - Set the host header in an HTTP request using python

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag.
The Host HTTP header must be 99ccd39cd5ee7951d63bd7b4206d361a
You must make this request using python
```

```python
import requests

url = 'http://127.0.0.1:80'

headers = {'Host': '99ccd39cd5ee7951d63bd7b4206d361a', 'Connection': 'close'}

response = requests.get(url, headers=headers)

print(response.text)
```

### Level 7 - Set the path in an HTTP request using curl

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag.
The path of the HTTP request must be /ff5ec5b94f4e6dc0977d84ecc31f177f
You must make this request using the curl command
```

```bash
$ curl http://127.0.0.1/ff5ec5b94f4e6dc0977d84ecc31f177f
```

### Level 8 - Set the path in an HTTP request using nc

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag.
The path of the HTTP request must be /6d935a704f3e719158d7b81d60e2ea6c
You must make this request using the nc command
```

```bash
$ echo -e "GET http://127.0.0.1/6d935a704f3e719158d7b81d60e2ea6c HTTP/1.0\r\n\r\nConnection: close\r\n\r\n" | nc 127.0.0.1 80 | grep pwn.college{
```

### Level 9 - Set the path in an HTTP request using python

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag.
The path of the HTTP request must be /8fa26d5b8f22a96833c8c31fb8324e32
You must make this request using python
```

```python
import requests

url = 'http://127.0.0.1:80/8fa26d5b8f22a96833c8c31fb8324e32'

response = requests.get(url)

print(response.text)
```

### Level 10 - URL encode a path in an HTTP request using curl

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag.
The path of the HTTP request must be /1f6532bb 2a767e23/c2cbd027 2b784ec9
You must make this request using the curl command
```

```bash
$ curl http://127.0.0.1//1f6532bb%202a767e23/c2cbd027%202b784ec9
```

### Level 11 - URL encode a path in an HTTP request using nc

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag.
The path of the HTTP request must be /27b74021 f153a262/b41c6552 f6ef541c
You must make this request using the nc command
```

```bash
$ echo -e "GET /27b74021%20f153a262/b41c6552%20f6ef541c HTTP/1.0\r\n\r\nConnection: close\r\n\r\n" | nc 127.0.0.1 80 | grep pwn.college{
```

### Level 12 - URL encode a path in an HTTP request using python

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag.
The path of the HTTP request must be /9254b04e 1d424c80/5ee41e71 562ca7a6
You must make this request using python
```

```python
import requests
from urllib.parse import quote

path = quote('/9254b04e 1from urllib.parse import quoted424c80/5ee41e71 562ca7a6')

url = f'http://127.0.0.1:80/{path}'

response = requests.get(url)

print(response.text)
```

### Level 13 - Specify an argument in an HTTP request using curl

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag.
The HTTP request must specify HTTP GET parameter `a` as value aafa6e990f769bd50b9b76929e3829d2
You must make this request using the curl command
```

```bash
$ curl "http://127.0.0.1?a=aafa6e990f769bd50b9b76929e3829d2"
```

### Level 14 - Specify an argument in an HTTP request using nc

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag.
The HTTP request must specify HTTP GET parameter `a` as value ad5bff22d15e25f09db47cd0a564a4f4
You must make this request using the nc command
```

```bash
$ echo -e "GET /?a=ad5bff22d15e25f09db47cd0a564a4f4 HTTP/1.0\r\n\r\nConnection: close\r\n\r\n" | nc 127.0.0.1 80 | grep pwn.college{
```

### Level 15 - Specify an argument in an HTTP request using python

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag.
The HTTP request must specify HTTP GET parameter `a` as value f2cc1fdc18ae0deece982a0a7dd535e4
You must make this request using python
```

```python
import requests

url = 'http://127.0.0.1:80'

params = {'a': 'f2cc1fdc18ae0deece982a0a7dd535e4'}

response = requests.get(url, params=params)

print(response.text)
```

### Level 16 - Specify multiple arguments in an HTTP request using curl

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag.
The HTTP request must specify HTTP GET parameters:
`a` as value 639d139a4a53f3c1b92eeb926907efae
`b` as value 8f14da6a 5715436f&2b7389c2#0f3bd326
You must make this request using the curl command
```

```bash
$ curl "http://127.0.0.1?a=639d139a4a53f3c1b92eeb926907efae&b=8f14da6a%205715436f%262b7389c2%230f3bd326"
```

### Level 17 - Specify multiple arguments in an HTTP request using nc

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag.
The HTTP request must specify HTTP GET parameters:
`a` as value 61bbd54df2200a7058068e9bf1369708
`b` as value 19cb394a ad42b92f&5234b9a0#30400f3e
You must make this request using the nc command
```

```bash
$ echo -e "GET /?a=61bbd54df2200a7058068e9bf1369708&b=19cb394a%20ad42b92f%265234b9a0%2330400f3e HTTP/1.0\r\n\r\nConnection: close\r\n\r\n" | nc 127.0.0.1 80 | grep pwn.college{
```

### Level 18 - Specify multiple arguments in an HTTP request using python

```bash
The HTTP request must specify HTTP GET parameters:
`a` as value 7210936e8f1659d0553f917faa5800ad
`b` as value 98cea0b5 116eece4&d8036b81#658afd32
You must make this request using python
```

```python
import requests

url = 'http://127.0.0.1:80'

params = {
    'a': '7210936e8f1659d0553f917faa5800ad', 
    'b': '98cea0b5 116eece4&d8036b81#658afd32'
}

response = requests.get(url, params=params)

print(response.text)
```

### Level 19 - Include form data in an HTTP request using curl

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag.
The HTTP request must specify HTTP POST parameter `a` as value b0e2f82feba705c3b68e00f750f4ea86
You must make this request using the curl command
```

```bash
$ curl -X POST -d 'a=b0e2f82feba705c3b68e00f750f4ea86' http://127.0.0.1
```

### Level 20 - Include form data in an HTTP request using nc

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag.
The HTTP request must specify HTTP POST parameter `a` as value 04b551668d4ab39ceea36514e99131d0
You must make this request using the nc command
```

```bash
$ echo -e "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 34\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\na=04b551668d4ab39ceea36514e99131d0" | nc 127.0.0.1 80 | grep pwn.college{
```

### Level 21 - Include form data in an HTTP request using python

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag.
The HTTP request must specify HTTP POST parameter `a` as value 1b50a6801067e940dbbc143e3a36da2d
You must make this request using python
```

```python
import requests

url = 'http://127.0.0.1:80'

data = {'a': '1b50a6801067e940dbbc143e3a36da2d'}

response = requests.post(url, data=data)

print(response.text)
```

### Level 22 - Include form data with multiple fields in an HTTP request using curl

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag.
The HTTP request must specify HTTP POST parameters:
`a` as value 12a7b2bf7e6a76d2e24012802ca598ad
`b` as value 68a89307 04ff27eb&038361c5#1483166c
You must make this request using the curl command
```

```bash
$ curl -X POST -d 'a=12a7b2bf7e6a76d2e24012802ca598ad' -d 'b=68a89307%2004ff27eb%26038361c5%231483166c' http://127.0.0.1
```

### Level 23 - Include form data with multiple fields in an HTTP request using nc

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag.
The HTTP request must specify HTTP POST parameters:
`a` as value 6cc4156dbe46aea9dd57ff5488d52144
`b` as value cd83e2c8 c12192ae&dac34e77#5eb7fffc
You must make this request using the nc command
```

```bash
echo -e "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 78\r\nContent-Type: application/x-www-form-urlenco
ded\r\n\r\na=6cc4156dbe46aea9dd57ff5488d52144&b=cd83e2c8%20c12192ae%26dac34e77%235eb7fffc" | nc 127.0.0.1 80 | grep pwn.college{
```

### Level 24 - Include form data with multiple fields in an HTTP request using python

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag.
The HTTP request must specify HTTP POST parameters:
`a` as value 4834203e1de2e436e7deae1adfbffa9a
`b` as value fa09ca97 f55e6df0&77100a04#a9621251
You must make this request using python
```

```python
import requests

url = 'http://127.0.0.1:80'

data = {
    'a': '4834203e1de2e436e7deae1adfbffa9a',
    'b': 'fa09ca97 f55e6df0&77100a04#a9621251'    
}

response = requests.post(url, data=data)

print(response.text)
```

### Level 25 - Include json data in an HTTP request using curl

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag.
The HTTP request must specify a content type HTTP header of 'application/json'
Must send an HTTP POST with the body as a JSON object that has a pair with name of `a` and a value of 2d21ef36c1e2880142e0f3c249049813
You must make this request using the curl command
```

```bash
$ curl -X POST -H "Content-Type: application/json" -d '{"a": "2d21ef36c1e2880142e0f3c249049813"}' http://127.0.0.1:80
```

### Level 26 - Include json data in an HTTP request using nc

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag.
The HTTP request must specify a content type HTTP header of 'application/json'
Must send an HTTP POST with the body as a JSON object that has a pair with name of `a` and a value of 3e030cadf2192109879aa1ebe0be5aad
You must make this request using the nc command
```

```bash
$ echo -e "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 41\r\n\r\n{\"a\": \"3e030cadf2192109879aa1ebe0be5aad\"}" | nc 127.0.0.1 80 | grep pwn.college{
```

### Level 27 - Include json data in an HTTP request using python

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag.
The HTTP request must specify a content type HTTP header of 'application/json'
Must send an HTTP POST with the body as a JSON object that has a pair with name of `a` and a value of 394cba9d8b2abeb88820308803a68c63
You must make this request using python
```

```python
import requests

url = 'http://127.0.0.1:80'

data = {'a': '394cba9d8b2abeb88820308803a68c63'}

response = requests.post(url, json=data)

print(response.text)
```

### Level 28 - Include complex json data in an HTTP request using curl

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag.
The HTTP request must specify a content type HTTP header of 'application/json'
Must send an HTTP POST with the body as a JSON object that has:
        a pair with name of `a` and a value of d50fd2c3886ed35f6278d53eb3310163
        a pair with name of `b` and a value of a object that has:
                a pair with name of `c` and a value of bfebc15b
                a pair with name of `d` and a value that is a list with the following elements:
                        f2bf88a3
                        44014de9 d0da8468&ad0b0612#f0ec4766
You must make this request using the curl command
```

```bash
$ curl -X POST -H "Content-Type: application/json" -d '{"a": "d50fd2c3886ed35f6278d53eb3310163", "b": {"c": "bfebc15b", "d": ["f2bf88a3", "44014de9 d0da8468&ad0b0612#f0ec4766"]} }' http://127.0.0.1:80
```

### Level 29 - Include complex json data in an HTTP request using nc

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag.
The HTTP request must specify a content type HTTP header of 'application/json'
Must send an HTTP POST with the body as a JSON object that has:
        a pair with name of `a` and a value of 3756062c87aa10f389a287c784199c4c
        a pair with name of `b` and a value of a object that has:
                a pair with name of `c` and a value of c1fad6d2
                a pair with name of `d` and a value that is a list with the following elements:
                        bac1d43b
                        dfd0db29 78dc0d18&ad0fc24e#9bd35059
You must make this request using the nc command
```

This is a pretty big command so I will make a `bash` script instead.

```bash
json_payload='{
    "a": "3756062c87aa10f389a287c784199c4c",
    "b": {
        "c": "c1fad6d2",
        "d": ["bac1d43b", "dfd0db29 78dc0d18&ad0fc24e#9bd35059"]
    }
}'

# Define the length of the JSON payload
content_length=$(echo -n "$json_payload" | wc -c)

# Send the HTTP request using nc
{
    echo -ne "POST / HTTP/1.1\r\n"
    echo -ne "Host: 127.0.0.1\r\n"
    echo -ne "Content-Type: application/json\r\n"
    echo -ne "Content-Length: $content_length\r\n"
    echo -ne "\r\n"
    echo -ne "$json_payload"
} | nc 127.0.0.1 80 | grep pwn.college{
```

### Level 30 - Include complex json data in an HTTP request using python

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag.
The HTTP request must specify a content type HTTP header of 'application/json'
Must send an HTTP POST with the body as a JSON object that has:
        a pair with name of `a` and a value of 7c2e89e4810653cd17f0541d2afa733d
        a pair with name of `b` and a value of a object that has:
                a pair with name of `c` and a value of 96bdc2ef
                a pair with name of `d` and a value that is a list with the following elements:
                        a795b15e
                        2eb18062 23c9f5f1&3e6018c8#91688a52
You must make this request using python
```

``` python
import requests

url = 'http://127.0.0.1:80'

data = {
	'a': '7c2e89e4810653cd17f0541d2afa733d',
	'b': {
        'c': '96bdc2ef',
        'd': ['a795b15e', '2eb18062 23c9f5f1&3e6018c8#91688a52']
    }
}

response = requests.post(url, json=data)

print(response.text)
```

### Level 31 - Follow an HTTP redirect from HTTP response using curl

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag. Make any HTTP request, and the server will send you an HTTP response that redirects you to the flag.
You must make this request using the curl command
```

```bash
$ curl -L http:/127.0.0.1
```

### Level 32 - Follow an HTTP redirect from HTTP response using nc

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag. Make any HTTP request, and the server will send you an HTTP response that redirects you to the flag.
You must make this request using the nc command
```

```bash
# Make the initial request
echo -e "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n" | nc 127.0.0.1 80 > response.txt

# Extract the URL from the Location header
redirect_url=$(grep -i '^Location:' response.txt | awk '{print $2}')

# Make another request to the redirected URL
echo -e "GET $redirect_url HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n" | nc 127.0.0.1 80 | grep pwn.college{
```

### Level 33 - Follow an HTTP redirect from HTTP response using python

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag. Make any HTTP request, and the server will send you an HTTP response that redirects you to the flag.
You must make this request using python
```

```python
import requests

url = 'http://127.0.0.1:80'

response = requests.get(url)

print(response.text)
```

### Level 34 - Include a cookie from HTTP response using curl

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag. Make any HTTP request, and the server will ask you to set a cookie. Make another request with that cookie to get the flag.
You must make this request using the curl command
```

```bash
# Step 1: Make the initial request to the server
response=$(curl -i http://127.0.0.1:80)

# Step 2: Extract the cookie information from the response
cookie=$(echo "$response" | grep -i 'Set-Cookie' | awk '{print $2}')

# Step 3: Make another request to the server with the extracted cookie information to retrieve the flag
flag=$(curl -b "$cookie" http://127.0.0.1:80/flag)

clear

echo "$flag"
```

### Level 35 - Include a cookie from HTTP response using nc

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag. Make any HTTP request, and the server will ask you to set a cookie. Make another request with that cookie to get the flag.
You must make this request using the nc command
```

```bash
# Make the initial request and save the response
response=$(echo -e "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n" | nc 127.0.0.1 80)

# Extract the cookie from the response headers
cookie=$(echo "$response" | grep -i '^Set-Cookie:' | awk '{print $2}')

# Make a new request with the extracted cookie
echo -e "GET /flag HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: $cookie\r\nConnection: close\r\n\r\n" | nc 127.0.0.1 80 | grep pwn.college{
```

### Level 36 - Include a cookie from HTTP response using python

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag. Make any HTTP request, and the server will ask you to set a cookie. Make another request with that cookie to get the flag.
You must make this request using python
```

```python
import requests

# Make the initial HTTP request
initial_response = requests.get('http://127.0.0.1:80')

# Extract the cookie from the initial response
cookie = initial_response.cookies.get_dict()

# Make another request with the extracted cookie to get the flag
flag_response = requests.get('http://127.0.0.1:80/flag', cookies=cookie)

# Print the flag if the request was successful
if flag_response.status_code == 200:
    print(flag_response.text)
else:
    print("Failed to retrieve the flag.")
```

### Level 37 - Make multiple requests in response to stateful HTTP responses using curl

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag. The server requires that you make 4 stateful requests.
You must make this request using the curl command
```

```bash
# Make the first request to establish a session and retrieve the initial cookie
curl -c cookie.txt http://127.0.0.1:80

# Make subsequent requests using the established session and cookie
curl -c cookie.txt -b cookie.txt http://127.0.0.1:80/ 
curl -c cookie.txt -b cookie.txt http://127.0.0.1:80/ 
curl -c cookie.txt -b cookie.txt http://127.0.0.1:80/ 
curl -c cookie.txt -b cookie.txt http://127.0.0.1:80/ 
```

### Level 38 - Make multiple requests in response to stateful HTTP responses using nc

```bash
Make an HTTP request to 127.0.0.1 on port 80 to get the flag. The server requires that you make 4 stateful requests.
You must make this request using the nc command
```

```bash

```

### Level 39 - Make multiple requests in response to stateful HTTP responses using python

```bash

```

