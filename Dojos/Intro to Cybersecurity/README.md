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

path = quote('/9254b04e 1d424c80/5ee41e71 562ca7a6')

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
from urllib.parse import quote

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
from urllib.parse import quote

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