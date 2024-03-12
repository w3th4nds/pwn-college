<div align="center">
    <h1> Reverse Engineer </h1> 
</div>

### Level 1.0 - Reverse engineer this challenge to find the correct license key.

```bash
This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you
are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely
different operations on that input! You must figure out (by reverse engineering this program) what that license key is.
Providing the correct license key will net you the flag!

Ready to receive your license key!
```
Open the program in `gdb`, `disass main` and we see this: 

```gdb
   0x000055de3f58065b <+585>:   lea    rsi,[rip+0x29ae]        # 0x55de3f583010 <EXPECTED_RESULT>
   0x000055de3f580662 <+592>:   mov    rdi,rax
   0x000055de3f580665 <+595>:   call   0x55de3f5801b0 <memcmp@plt>
   0x000055de3f58066a <+600>:   test   eax,eax
   0x000055de3f58066c <+602>:   jne    0x55de3f580682 <main+624>
   0x000055de3f58066e <+604>:   mov    eax,0x0
   0x000055de3f580673 <+609>:   call   0x55de3f5802e9 <win>
```

Inspecting the address of `EXPECTED_RESULT`, we get this string:

```gdb
pwndbg> x/s &EXPECTED_RESULT 
0x55de3f583010 <EXPECTED_RESULT>:       "ubajh"
```

```bash
$ echo ubajh | /challenge/babyrev_level1.0 | grep pwn.college
```

### Level 1.1 - Reverse engineer this challenge to find the correct license key.

We open `gdb` again and stop right at the `memcmp` function to check its arguments and get the key.

```gdb
 ► 0x5567b7602554    call   memcmp@plt                <memcmp@plt>
        s1: 0x7ffeac719862 ◂— 0x7c00000a41414141 /* 'AAAA\n' */
        s2: 0x5567b7605010 ◂— 0x6a69617472 /* 'rtaij' */
        n: 0x5
```

```bash
$ echo rtaij | /challenge/babyrev_level1.1  | grep pwn
```

### Level 2.0 - Reverse engineer this challenge to find the correct license key, but your input will be modified somehow before being compared to the correct key.

```bash
This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you
are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely
different operations on that input! You must figure out (by reverse engineering this program) what that license key is.
Providing the correct license key will net you the flag!

Ready to receive your license key!
```

Same as previous levels: 

```gdb
pwndbg> x/s &EXPECTED_RESULT 
0x557de301f010 <EXPECTED_RESULT>:       "zdniz"
```
The twist here is that our input is `mangled`. 

```bash
Initial input:

        7a 64 6e 69 7a 

This challenge is now mangling your input using the `swap` mangler for indexes `2` and `3`.

This mangled your input, resulting in:

        7a 64 69 6e 7a 

The mangling is done! The resulting bytes will be used for the final comparison.

Final result of mangling input:

        7a 64 69 6e 7a 

Expected result:

        7a 64 6e 69 7a 

Checking the received license key!

Wrong! No flag for you!
```

We simply swap index 2 and 3 and get the flag.

```bash
$ echo zdinz | /challenge/babyrev_level2.0 | grep pwn
```

### Level 2.1 - Reverse engineer this challenge to find the correct license key, but your input will be modified somehow before being compared to the correct key.

We follow the same procedure every time. Now we see that after we insert "AAAA" and reach `memcmp`, we get this: 

```gdb
► 0x56329b555570    call   memcmp@plt                <memcmp@plt>
        s1: 0x7fffeb800d22 ◂— 0x96000041410a4141 /* 'AA\nAA' */
        s2: 0x56329b558010 ◂— 0x7971687768 /* 'hwhqy' */
        n: 0x5
```
Our input seems to have some `\n` in between. Also, when I try the same string, I get this: 

```gdb
 ► 0x556f631a2570    call   memcmp@plt                <memcmp@plt>
        s1: 0x7ffdad04ef72 ◂— 0xb800006871797768 /* 'hwyqh' */
        s2: 0x556f631a5010 ◂— 0x7971687768 /* 'hwhqy' */
        n: 0x5
```

We see that the 3rd and last byte are swapped. 

```bash
$ echo hwyqh | /challenge/babyrev_level2.1
```

### Level 3.0 - Reverse engineer this challenge to find the correct license key, but your input will be modified somehow before being compared to the correct key.

```gdb
pwndbg> ds &EXPECTED_RESULT 
5645ea762010 'sknje'
```
Entering this we get the debugging info: 

```bash
sknje
Initial input:

        73 6b 6e 6a 65 

This challenge is now mangling your input using the `reverse` mangler.
```
So, we reverse the string and send it to get the flag.

```bash
$ echo sknje | rev | /challenge/babyrev_level3.0 | grep pwn
```

### Level 3.1 - Reverse engineer this challenge to find the correct license key, but your input will be modified somehow before being compared to the correct key.

```gdb
 ► 0x5653e9ee15a5    call   memcmp@plt                <memcmp@plt>
        s1: 0x7ffd65a943e2 ◂— 0x800000414141410a /* '\nAAAA' */
        s2: 0x5653e9ee4010 ◂— 0x7275687369 /* 'ishur' */
        n: 0x5
```

It's exactly the same as before.

```bash
$ echo ishur | rev | /challenge/babyrev_level3.1 | grep pwn
```

### Level 4.0 - Reverse engineer this challenge to find the correct license key, but your input will be modified somehow before being compared to the correct key.

```gdb
pwndbg> ds &EXPECTED_RESULT 
55c4167fe010 'fitvx'
```

```bash
$ echo fitvx | /challenge/babyrev_level4.0 | grep pwn
```

### Level 4.1 - Reverse engineer this challenge to find the correct license key, but your input will be modified somehow before being compared to the correct key.

```gdb
 ► 0x56417af385d6    call   memcmp@plt                <memcmp@plt>
        s1: 0x7ffc051756d2 ◂— 0x210000414141410a /* '\nAAAA' */
        s2: 0x56417af3b010 ◂— 0x76726d6c61 /* 'almrv' */
        n: 0x5
```

```bash
$ echo almrv | /challenge/babyrev_level4.1 | grep pwn
```

### Level 5.0 - Reverse engineer this challenge to find the correct license key, but your input will be modified somehow before being compared to the correct key.

```gdb
Ready to receive your license key!

AAAA
Initial input:

        41 41 41 41 0a 

This challenge is now mangling your input using the `xor` mangler with key `0x64`

This mangled your input, resulting in:

        25 25 25 25 6e 

The mangling is done! The resulting bytes will be used for the final comparison.

Final result of mangling input:

        25 25 25 25 6e 

Expected result:

        0b 0e 17 12 12 
```
We need to find the correct `XORed` value. We see that the key is: `0x64`  

```python
>>> hex(ord('A') ^ 0x25)
'0x64'
```
The expected value is: `0000001212170e0b`.

```gdb
pwndbg> dq &EXPECTED_RESULT 
000055585cf73010     0000001212170e0b 0000000000000000
000055585cf73020     00007f25f2d7a6a0 0000000000000000
000055585cf73030     00007f25f2d79980 0000000000000000
000055585cf73040     0000000000000000 0000000000000000
```

```python
from pwn import *
import warnings
warnings.filterwarnings('ignore')
context.log_level = 'critical'

r = process('/challenge/babyrev_level5.0')

enc = [0x12, 0x12, 0x17, 0x0e, 0x0b]

r.sendline(bytes([i ^ 0x64 for i in enc]).decode()[::-1])

print(r.recvline_contains(b'pwn').decode())
```

### Level 5.1 - Reverse engineer this challenge to find the correct license key, but your input will be modified somehow before being compared to the correct key.

After entering `AAAA`:

```gdb
 ► 0x563405422580    call   memcmp@plt                <memcmp@plt>
        s1: 0x7ffea3bef062 ◂— 0xc30000f3b8b8b8b8
        s2: 0x563405425010 ◂— 0x8e938b8b96
        n: 0x5
```

Do the same with `BBBB` now:

```gdb
 ► 0x55c05583a580    call   memcmp@plt                <memcmp@plt>
        s1: 0x7ffee4ed6a42 ◂— 0x830000f3bbbbbbbb
        s2: 0x55c05583d010 ◂— 0x8e938b8b96
```

We can understand that the key this time is: `0xf9`

```python
>>> hex(ord('A')^0xb8)
'0xf9'
>>> hex(ord('B')^0xf9)
'0xbb'
```

```python
from pwn import *
import warnings
warnings.filterwarnings('ignore')
context.log_level = 'critical'

r = process('/challenge/babyrev_level5.1')

enc = [0x8e, 0x93, 0x8b, 0x8b, 0x96]

r.sendline(bytes([i ^ 0xf9 for i in enc]).decode()[::-1])

print(r.recvline_contains(b'pwn').decode())
```

### Level 6.0

```bash
Initial input:

        41 41 41 41 0a 00 00 00 00 00 00 00 00 00 00 00 

This challenge is now mangling your input using the `xor` mangler with key `0xbf46`

This mangled your input, resulting in:

        fe 07 fe 07 b5 46 bf 46 bf 46 bf 46 bf 46 bf 46 

This challenge is now mangling your input using the `sort` mangler.

This mangled your input, resulting in:

        07 07 46 46 46 46 46 46 b5 bf bf bf bf bf fe fe 

This challenge is now mangling your input using the `swap` mangler for indexes `0` and `9`.

This mangled your input, resulting in:

        bf 07 46 46 46 46 46 46 b5 07 bf bf bf bf fe fe 

The mangling is done! The resulting bytes will be used for the final comparison.

Final result of mangling input:

        bf 07 46 46 46 46 46 46 b5 07 bf bf bf bf fe fe 

Expected result:

        cd 20 25 27 27 28 31 35 c8 20 ce cf d1 d5 d9 dc 
```

So, we need to `xor` the string with the key `0xbf46` and then sort the string and swap 0 and 9 element.

```python
from pwn import *
import warnings
warnings.filterwarnings('ignore')
context.log_level = 'critical'

r = process('/challenge/babyrev_level6.0')

enc = [ 0x20, 0x20, 0x25, 0x27, 0x27, 
        0x28, 0x31, 0x35, 0xc8, 0xcd,
        0xce, 0xcf, 0xd1, 0xd5, 0xd9, 0xdc]

payload = ''.join(chr(i ^ (0xbf if idx % 2 == 0 else 0x46)) for idx, i in enumerate(enc))

r.sendline(payload)

print(r.recvline_contains(b'pwn').decode())
```

### Level 6.1 - Reverse engineer this challenge to find the correct license key, but your input will be modified somehow before being compared to the correct key.
