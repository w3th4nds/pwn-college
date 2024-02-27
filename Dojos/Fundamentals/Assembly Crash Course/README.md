<div align="center">
    <h1> Assembly Crash Course</h1> 
</div>

As I am not familiar with writing `asm`, I will use `pwntools` `asm` method to help me construct the payload.

### Level 1 - Set a register

Running the binary we get this:

```bash
/challenge/run 

Welcome to ASMLevel1
==================================================

To interact with any level you will send raw bytes over stdin to this program.
To efficiently solve these problems, first run it to see the challenge instructions.
Then craft, assemble, and pipe your bytes to this program.

For instance, if you write your assembly code in the file asm.S, you can assemble that to an object file:
  as -o asm.o asm.S

Then, you can copy the .text section (your code) to the file asm.bin:
  objcopy -O binary --only-section=.text asm.o asm.bin

And finally, send that to the challenge:
  cat ./asm.bin | /challenge/run

You can even run this as one command:
  as -o asm.o asm.S && objcopy -O binary --only-section=.text ./asm.o ./asm.bin && cat ./asm.bin | /challenge/run

In this level you will be working with registers. You will be asked to modify
or read from registers.



In this level you will work with registers! Please set the following:
  rdi = 0x1337

Please give me your assembly in bytes (up to 0x1000 bytes): 
```

```python
#!/usr/bin/python3
from pwn import *
import warnings
warnings.filterwarnings('ignore')

context.arch = 'amd64'
context.log_level = 'critical'

r = process('/challenge/run')

r.send(asm('mov rdi, 0x1337'))

print(r.recvline_contains('pwn.college').decode())
```

### Level 2 - Set multiple registers

```bash
In this level you will work with multiple registers. Please set the following:
  rax = 0x1337
  r12 = 0xCAFED00D1337BEEF
  rsp = 0x31337

Please give me your assembly in bytes (up to 0x1000 bytes): 
```

```python
#!/usr/bin/python3
from pwn import *
import warnings
warnings.filterwarnings('ignore')

context.arch = 'amd64'
context.log_level = 'critical'

r = process('/challenge/run')

r.send(asm('''
    mov rax, 0x1337
    mov r12, 0xCAFED00D1337BEEF
    mov rsp, 0x31337
    '''))

print(r.recvline_contains('pwn.college').decode())
```

### Level 3 - Addition

```bash
Many instructions exist in x86 that allow you to do all the normal
math operations on registers and memory.

For shorthand, when we say A += B, it really means A = A + B.

Here are some useful instructions:
  add reg1, reg2       <=>     reg1 += reg2
  sub reg1, reg2       <=>     reg1 -= reg2
  imul reg1, reg2      <=>     reg1 *= reg2

div is more complicated and we will discuss it later.
Note: all 'regX' can be replaced by a constant or memory location

Do the following:
  add 0x331337 to rdi

We will now set the following in preparation for your code:
  rdi = 0x4c5

Please give me your assembly in bytes (up to 0x1000 bytes): 
```

```python
#!/usr/bin/python3
from pwn import *
import warnings
warnings.filterwarnings('ignore')

context.arch = 'amd64'
context.log_level = 'critical'

r = process('/challenge/run')

r.send(asm('add rdi, 0x331337'))

print(r.recvline_contains('pwn.college').decode())
```

### Level 4 - Multiplication

```bash
Using your new knowledge, please compute the following:
  f(x) = mx + b, where:
    m = rdi
    x = rsi
    b = rdx

Place the result into rax.

Note: there is an important difference between mul (unsigned
multiply) and imul (signed multiply) in terms of which
registers are used. Look at the documentation on these
instructions to see the difference.

In this case, you will want to use imul.

We will now set the following in preparation for your code:
  rdi = 0x1b4d
  rsi = 0x13e4
  rdx = 0x1f6a
```

```python
#!/usr/bin/python3
from pwn import *
import warnings
warnings.filterwarnings('ignore')

context.arch = 'amd64'
context.log_level = 'critical'

r = process('/challenge/run')

r.send(asm('''
    imul rdi, rsi
    add  rdx, rdi
    mov  rax, rdx
    '''))

print(r.recvline_contains('pwn.college').decode())
```

### Level 5 - Division

```bash
Division in x86 is more special than in normal math. Math in here is
called integer math. This means every value is a whole number.

As an example: 10 / 3 = 3 in integer math.

Why?

Because 3.33 is rounded down to an integer.

The relevant instructions for this level are:
  mov rax, reg1; div reg2

Note: div is a special instruction that can divide
a 128-bit dividend by a 64-bit divisor, while
storing both the quotient and the remainder, using only one register as an operand.

How does this complex div instruction work and operate on a
128-bit dividend (which is twice as large as a register)?

For the instruction: div reg, the following happens:
  rax = rdx:rax / reg
  rdx = remainder

rdx:rax means that rdx will be the upper 64-bits of
the 128-bit dividend and rax will be the lower 64-bits of the
128-bit dividend.

You must be careful about what is in rdx and rax before you call div.

Please compute the following:
  speed = distance / time, where:
    distance = rdi
    time = rsi
    speed = rax

Note that distance will be at most a 64-bit value, so rdx should be 0 when dividing.

We will now set the following in preparation for your code:
  rdi = 0xa6c
  rsi = 0x48
```

This one here is a bit confusing so I will try to explain it with an example.

Let's say we have `10 / 3 = 3.33`.

In `assembly` we would have something like this:

```asm
rax = 10 ; divident
rcx = 3  ; divisor

xor rdx, rdx ; holds the remainder

div rcx ; divides rax with rcx, after execution rax will contain the quotient and rdx the remainder
```



