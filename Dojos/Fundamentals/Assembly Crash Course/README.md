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

So, if we move the correct registers to the ones that `div` uses, we can use the operation.

```python
#!/usr/bin/python3
from pwn import *
import warnings
warnings.filterwarnings('ignore')

context.arch = 'amd64'
context.log_level = 'critical'

r = process('/challenge/run')

r.send(asm('''
    mov rax, rdi
    mov rcx, rsi
    div rcx
    '''))

print(r.recvline_contains('pwn.college').decode())
```

### Level 6 - Modulus

```bash
Modulo in assembly is another interesting concept!

x86 allows you to get the remainder after a div operation.

For instance: 10 / 3 -> remainder = 1

The remainder is the same as modulo, which is also called the "mod" operator.

In most programming languages we refer to mod with the symbol '%'.

Please compute the following:
  rdi % rsi

Place the value in rax.

We will now set the following in preparation for your code:
  rdi = 0xe8f6c79
  rsi = 0xf
```

I demonstrated how the `div` and `mod` works.

```python
#!/usr/bin/python3
from pwn import *
import warnings
warnings.filterwarnings('ignore')

context.arch = 'amd64'
context.log_level = 'critical'

r = process('/challenge/run')

r.send(asm('''
    mov rax, rdi
    mov rcx, rsi
    div rcx
    mov rax, rdx
    '''))

print(r.recvline_contains('pwn.college').decode())
```

### Level 7 - Register sizes

```bash
Another cool concept in x86 is the ability to independently access to lower register bytes.

Each register in x86_64 is 64 bits in size, and in the previous levels we have accessed
the full register using rax, rdi or rsi.

We can also access the lower bytes of each register using different register names.

For example the lower 32 bits of rax can be accessed using eax, the lower 16 bits using ax,
the lower 8 bits using al.

MSB                                    LSB
+----------------------------------------+
|                   rax                  |
+--------------------+-------------------+
                     |        eax        |
                     +---------+---------+
                               |   ax    |
                               +----+----+
                               | ah | al |
                               +----+----+

Lower register bytes access is applicable to almost all registers.

Using only one move instruction, please set the upper 8 bits of the ax register to 0x42.

We will now set the following in preparation for your code:
  rax = 0xf3b20146548800d3
```

```python
#!/usr/bin/python3
from pwn import *
import warnings
warnings.filterwarnings('ignore')

context.arch = 'amd64'
context.log_level = 'critical'

r = process('/challenge/run')

r.send(asm('mov ah, 0x42'))

print(r.recvline_contains('pwn.college').decode())
```

### Level 8 - Register sizes for modulus

```bash
It turns out that using the div operator to compute the modulo operation is slow!

We can use a math trick to optimize the modulo operator (%). Compilers use this trick a lot.

If we have "x % y", and y is a power of 2, such as 2^n, the result will be the lower n bits of x.

Therefore, we can use the lower register byte access to efficiently implement modulo!

Using only the following instruction(s):
  mov

Please compute the following:
  rax = rdi % 256
  rbx = rsi % 65536

We will now set the following in preparation for your code:
  rdi = 0xb653
  rsi = 0xe5efc4c3
```

For this challenge, as we can see, `256` is `2^8`, meaning we have to take the lower `8` bits. On the other hand, `65536` is `2^16`.

```asm
mov al, dil   ; Copy the lower 8 bits of rdi to al
mov bx, si    ; Copy the lower 16 bits of rsi to bx
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
    mov al, dil
    mov bx, si
    '''))

print(r.recvline_contains('pwn.college').decode())
```

### Level 9 - Bitwise shift

```bash
Shifting bits around in assembly is another interesting concept!

x86 allows you to 'shift' bits around in a register.

Take, for instance, al, the lowest 8 bits of rax.

The value in al (in bits) is:
  rax = 10001010

If we shift once to the left using the shl instruction:
  shl al, 1

The new value is:
  al = 00010100

Everything shifted to the left and the highest bit fell off
while a new 0 was added to the right side.

You can use this to do special things to the bits you care about.

Shifting has the nice side affect of doing quick multiplication (by 2)
or division (by 2), and can also be used to compute modulo.

Here are the important instructions:
  shl reg1, reg2       <=>     Shift reg1 left by the amount in reg2
  shr reg1, reg2       <=>     Shift reg1 right by the amount in reg2
  Note: 'reg2' can be replaced by a constant or memory location

Using only the following instructions:
  mov, shr, shl

Please perform the following:
  Set rax to the 5th least significant byte of rdi.

For example:
  rdi = | B7 | B6 | B5 | B4 | B3 | B2 | B1 | B0 |
  Set rax to the value of B4

We will now set the following in preparation for your code:
  rdi = 0x5ad1378f6c3c359b
```

So, we know that `rdi` has the value `0x 5a d1 37 8f 6c 3c 35 9b`. We need to set `rax` with the value `0x8f`. There are many ways in doing it, but I will choose to `shl rdi, 0x3` so that the highest byte of `rdi` is `0x8f`. After that, I will `shr rdi, 7` so that `rdi` becomes `0x000000000000008f`.  Then, we `mov rax, rdi`. We need to take into consideration that it's `BIT` wise operation and not `BYTE`, so the `0x3` bytes I mentioned before is `0x3 * 0x8 = 0x18` bits. We do the same for `0x7 * 0x8 = 0x38`. 

```python
#!/usr/bin/python3
from pwn import *
import warnings
warnings.filterwarnings('ignore')

context.arch = 'amd64'
context.log_level = 'critical'

r = process('/challenge/run')

r.send(asm('''
    shl rdi, 0x18
    shr rdi, 0x38
    mov rax, rdi
    '''))

print(r.recvline_contains('pwn.college').decode())
```

### Level 10 - Bitwise and

```bash
Bitwise logic in assembly is yet another interesting concept!
x86 allows you to perform logic operations bit by bit on registers.

For the sake of this example say registers only store 8 bits.

The values in rax and rbx are:
  rax = 10101010
  rbx = 00110011

If we were to perform a bitwise AND of rax and rbx using the
"and rax, rbx" instruction, the result would be calculated by
ANDing each bit pair 1 by 1 hence why it's called a bitwise
logic.

So from left to right:
  1 AND 0 = 0
  0 AND 0 = 0
  1 AND 1 = 1
  0 AND 1 = 0
  ...

Finally we combine the results together to get:
  rax = 00100010

Here are some truth tables for reference:
      AND          OR           XOR
   A | B | X    A | B | X    A | B | X
  ---+---+---  ---+---+---  ---+---+---
   0 | 0 | 0    0 | 0 | 0    0 | 0 | 0
   0 | 1 | 0    0 | 1 | 1    0 | 1 | 1
   1 | 0 | 0    1 | 0 | 1    1 | 0 | 1
   1 | 1 | 1    1 | 1 | 1    1 | 1 | 0

Without using the following instructions:
  mov, xchg

Please perform the following:
  rax = rdi AND rsi

i.e. Set rax to the value of (rdi AND rsi)

We will now set the following in preparation for your code:
  rdi = 0x878993c0a512aff0
  rsi = 0x69f41542233630f1
```

Taking into consideration that we cannot perform `mov`, we need another way to move the result of the `and` bitwise operation. The `XOR` truth table indicates that we get `0` when the 2 values are the same. That means, if we `XOR` something with itself, we get `0`. We will `xor rax, rax` to zero out the `rax` register. After that, with the truth table of `OR`, we will manage to get our value.

```python
#!/usr/bin/python3
from pwn import *
import warnings
warnings.filterwarnings('ignore')

context.arch = 'amd64'
context.log_level = 'critical'

r = process('/challenge/run')

r.send(asm('''
    and rdi, rsi
    xor rax, rax
    or  rax, rdi
    '''))

print(r.recvline_contains('pwn.college').decode())
```

### Level 11 - Bitwise logic

```bash
In this level you will be working with bit logic and operations. This will involve heavy use of
directly interacting with bits stored in a register or memory location. You will also likely
need to make use of the logic instructions in x86: and, or, not, xor.



Using only the following instructions:
  and, or, xor

Implement the following logic:
  if x is even then
    y = 1
  else
    y = 0

where:
  x = rdi
  y = rax

We will now set the following in preparation for your code:
  rdi = 0x23652418
```

The first challenging level so far. Now, we need to understand step by step how to calculate the given `if-else`.

We need to somehow check if `x == even`. An even number is a number that when divided by 2, has 0 remainder. Well, it's unlucky that we cannot use the `div` instruction. Another easy way to find out is if the last bit is set to `0` or `1`. For example:

> 1 -> 1
> 2 -> 10
> 3 -> 101
> 4 -> 0100
> 5 -> 0101 and so on..

We notice that even numbers have the LSB set to 0 while odd numbers have 1. Let's perform `and` and `or` and `xor` operations on number `5` to see what we get.

> 0101 and 1 => 1
>
> 0101 or  1   => 1
>
> 0101 xor 1  => 0

Do not forget that bitwise operations perform on each pair of bits. That means, 1 will perform only on the LSbit and not the whole number. This way, we can take the last bit only. After the "extraction", we need to check if it is 1 or 0. We will do the same again to get the correct value.

```python
#!/usr/bin/python3
from pwn import *
import warnings
warnings.filterwarnings('ignore')

context.arch = 'amd64'
context.log_level = 'critical'

r = process('/challenge/run')

r.send(asm('''
    xor rax, rax
    and rdi, 0x1
    xor rdi, 0x1
    or rax, rdi
    '''))

print(r.recvline_contains('pwn.college').decode())
```

### Level 12 - Memory reads

```bash
In this level you will be working with memory. This will require you to read or write
to things stored linearly in memory. If you are confused, go look at the linear
addressing module in 'ike. You may also be asked to dereference things, possibly multiple
times, to things we dynamically put in memory for your use.



Up until now you have worked with registers as the only way for storing things, essentially
variables such as 'x' in math.

However, we can also store bytes into memory!

Recall that memory can be addressed, and each address contains something at that location.

Note that this is similar to addresses in real life!

As an example: the real address '699 S Mill Ave, Tempe, AZ
85281' maps to the 'ASU Brickyard'.

We would also say it points to 'ASU Brickyard'.

We can represent this like:
  ['699 S Mill Ave, Tempe, AZ 85281'] = 'ASU Brickyard'

The address is special because it is unique.

But that also does not mean other addresses can't point to the same thing (as someone can have multiple houses).

Memory is exactly the same!

For instance, the address in memory that your code is stored (when we take it from you) is 0x400000.

In x86 we can access the thing at a memory location, called dereferencing, like so:
  mov rax, [some_address]        <=>     Moves the thing at 'some_address' into rax

This also works with things in registers:
  mov rax, [rdi]         <=>     Moves the thing stored at the address of what rdi holds to rax

This works the same for writing to memory:
  mov [rax], rdi         <=>     Moves rdi to the address of what rax holds.

So if rax was 0xdeadbeef, then rdi would get stored at the address 0xdeadbeef:
  [0xdeadbeef] = rdi

Note: memory is linear, and in x86_64, it goes from 0 - 0xffffffffffffffff (yes, huge).

Please perform the following:
  Place the value stored at 0x404000 into rax

Make sure the value in rax is the original value stored at 0x404000.

We will now set the following in preparation for your code:
  [0x404000] = 0x192fd8
```

```python
#!/usr/bin/python3
from pwn import *
import warnings
warnings.filterwarnings('ignore')

context.arch = 'amd64'
context.log_level = 'critical'

r = process('/challenge/run')

r.send(asm('mov rax, [0x404000]'))

print(r.recvline_contains('pwn.college').decode())
```

### Level 13 - Memory writes

```bash
Please perform the following:
  Place the value stored in rax to 0x404000

We will now set the following in preparation for your code:
  rax = 0x18b59a
```

```python
#!/usr/bin/python3
from pwn import *
import warnings
warnings.filterwarnings('ignore')

context.arch = 'amd64'
context.log_level = 'critical'

r = process('/challenge/run')

r.send(asm('mov [0x404000], rax'))

print(r.recvline_contains('pwn.college').decode())
```

### Level 14 - Memory reads and writes

```bash
  Place the value stored at 0x404000 into rax
  Increment the value stored at the address 0x404000 by 0x1337

Make sure the value in rax is the original value stored at 0x404000 and make sure
that [0x404000] now has the incremented value.

We will now set the following in preparation for your code:
  [0x404000] = 0x188d62
```

The trick here is that we cannot directly perform the `add` operation in the `[address]`. We need to `mov` the address to a register first, perform the operation there and then move it back again.

```python
#!/usr/bin/python3
from pwn import *
import warnings
warnings.filterwarnings('ignore')

context.arch = 'amd64'
context.log_level = 'critical'

r = process('/challenge/run')

r.send(asm('''
    mov rax, [0x404000]
    mov r12, [0x404000]
    add r12, 0x1337
    mov [0x404000], r12
    '''))

print(r.recvline_contains('pwn.college').decode())
```

### Level 15 - Read one size data

```bash
Recall that registers in x86_64 are 64 bits wide, meaning they can store 64 bits.

Similarly, each memory location can be treated as a 64 bit value.

We refer to something that is 64 bits (8 bytes) as a quad word.

Here is the breakdown of the names of memory sizes:
  Quad Word   = 8 Bytes = 64 bits
  Double Word = 4 bytes = 32 bits
  Word        = 2 bytes = 16 bits
  Byte        = 1 byte  = 8 bits

In x86_64, you can access each of these sizes when dereferencing an address, just like using
bigger or smaller register accesses:
  mov al, [address]        <=>        moves the least significant byte from address to rax
  mov ax, [address]        <=>        moves the least significant word from address to rax
  mov eax, [address]       <=>        moves the least significant double word from address to rax
  mov rax, [address]       <=>        moves the full quad word from address to rax

Remember that moving into al does not fully clear the upper bytes.

Please perform the following:
  Set rax to the byte at 0x404000

We will now set the following in preparation for your code:
  [0x404000] = 0x18fabd
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
    xor rax, rax
    mov al, [0x404000]
    '''))

print(r.recvline_contains('pwn.college').decode())
```

### Level 16 - Read multiple data sizes

```bash
Recall the following:
  The breakdown of the names of memory sizes:
    Quad Word   = 8 Bytes = 64 bits
    Double Word = 4 bytes = 32 bits
    Word        = 2 bytes = 16 bits
    Byte        = 1 byte  = 8 bits

In x86_64, you can access each of these sizes when dereferencing an address, just like using
bigger or smaller register accesses:
  mov al, [address]        <=>        moves the least significant byte from address to rax
  mov ax, [address]        <=>        moves the least significant word from address to rax
  mov eax, [address]       <=>        moves the least significant double word from address to rax
  mov rax, [address]       <=>        moves the full quad word from address to rax

Please perform the following:
  Set rax to the byte at 0x404000
  Set rbx to the word at 0x404000
  Set rcx to the double word at 0x404000
  Set rdx to the quad word at 0x404000

We will now set the following in preparation for your code:
  [0x404000] = 0x8dad0d89b325f4ca
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
    xor rax, rax
    mov al,  [0x404000]
    mov bx,  [0x404000]
    mov ecx, [0x404000]
    mov rdx, [0x404000]
    '''))

print(r.recvline_contains('pwn.college').decode())
```

### Level 17 - Dynamic address memory writes

```bash
It is worth noting, as you may have noticed, that values are stored in reverse order of how we
represent them.

As an example, say:
  [0x1330] = 0x00000000deadc0de

If you examined how it actually looked in memory, you would see:
  [0x1330] = 0xde
  [0x1331] = 0xc0
  [0x1332] = 0xad
  [0x1333] = 0xde
  [0x1334] = 0x00
  [0x1335] = 0x00
  [0x1336] = 0x00
  [0x1337] = 0x00

This format of storing things in 'reverse' is intentional in x86, and its called "Little Endian".

For this challenge we will give you two addresses created dynamically each run.

The first address will be placed in rdi.
The second will be placed in rsi.

Using the earlier mentioned info, perform the following:
  Set [rdi] = 0xdeadbeef00001337
  Set [rsi] = 0xc0ffee0000

Hint: it may require some tricks to assign a big constant to a dereferenced register.
Try setting a register to the constant value then assigning that register to the dereferenced register.

We will now set the following in preparation for your code:
  [0x404548] = 0xffffffffffffffff
  [0x404e40] = 0xffffffffffffffff
  rdi = 0x404548
  rsi = 0x404e40
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
    mov r12, 0xdeadbeef00001337
    mov r13, 0xc0ffee0000
    mov [rdi], r12
    mov [rsi], r13
    '''))

print(r.recvline_contains('pwn.college').decode())
```

Another approach:

```python
#!/usr/bin/python3
from pwn import *
import warnings
warnings.filterwarnings('ignore')

context.arch = 'amd64'
context.log_level = 'critical'

r = process('/challenge/run')

r.send(asm('''
    mov r12, 0xdeadbeef00001337
    mov qword ptr [rdi], r12
    mov r13, 0xc0ffee0000
    mov qword ptr [rsi], r13
    '''))

print(r.recvline_contains('pwn.college').decode())
```

### Level 18 - Consecutive memory reads

```bash
Recall that memory is stored linearly.

What does that mean?

Say we access the quad word at 0x1337:
  [0x1337] = 0x00000000deadbeef

The real way memory is layed out is byte by byte, little endian:
  [0x1337] = 0xef
  [0x1337 + 1] = 0xbe
  [0x1337 + 2] = 0xad
  ...
  [0x1337 + 7] = 0x00

What does this do for us?

Well, it means that we can access things next to each other using offsets,
similar to what was shown above.

Say you want the 5th *byte* from an address, you can access it like:
  mov al, [address+4]

Remember, offsets start at 0.

Perform the following:
  Load two consecutive quad words from the address stored in rdi
  Calculate the sum of the previous steps quad words.
  Store the sum at the address in rsi

We will now set the following in preparation for your code:
  [0x404210] = 0xc8978
  [0x404218] = 0x344ce
  rdi = 0x404210
  rsi = 0x4046c8
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
    mov r12, qword ptr [rdi]
    mov r13, qword ptr [rdi+0x8]
    add r12, r13
    mov qword ptr [rsi], r12
    '''))

print(r.recvline_contains('pwn.college').decode())
```

### Level 19 - Stack

```bash
In these levels we are going to introduce the stack.

The stack is a region of memory that can store values for later.

To store a value on the stack we use the push instruction, and to retrieve a value we use pop.

The stack is a last in first out (LIFO) memory structure, and this means
the last value pushed in the first value popped.

Imagine unloading plates from the dishwasher let's say there are 1 red, 1 green, and 1 blue.
First we place the red one in the cabinet, then the green on top of the red, then the blue.

Our stack of plates would look like:
  Top ----> Blue
            Green
  Bottom -> Red

Now, if we wanted a plate to make a sandwich we would retrieve the top plate from the stack
which would be the blue one that was last into the cabinet, ergo the first one out.

On x86, the pop instruction will take the value from the top of the stack and put it into a register.

Similarly, the push instruction will take the value in a register and push it onto the top of the stack.

Using these instructions, take the top value of the stack, subtract rdi from it, then put it back.

We will now set the following in preparation for your code:
  rdi = 0x3e4f
  (stack) [0x7fffff1ffff8] = 0xa191dce
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
    pop rax
    sub rax, rdi
    push rax
    '''))

print(r.recvline_contains('pwn.college').decode())
```

### Level 20 - Swap register values with the stack

```bash
In this level we are going to explore the last in first out (LIFO) property of the stack.

Using only following instructions:
  push, pop

Swap values in rdi and rsi.
i.e.
If to start rdi = 2 and rsi = 5
Then to end rdi = 5 and rsi = 2

We will now set the following in preparation for your code:
  rdi = 0x32e8811e
  rsi = 0xf48b7cc
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
    push rdi
    push rsi
    pop  rdi
    pop  rsi
    '''))

print(r.recvline_contains('pwn.college').decode())
```

### Level 21 - Memory reads and writes with the stack

```bash
In the previous levels you used push and pop to store and load data from the stack.

However you can also access the stack directly using the stack pointer.

On x86, the stack pointer is stored in the special register, rsp.
rsp always stores the memory address of the top of the stack,
i.e. the memory address of the last value pushed.

Similar to the memory levels, we can use [rsp] to access the value at the memory address in rsp.

Without using pop, please calculate the average of 4 consecutive quad words stored on the stack.

Push the average on the stack.

Hint:
  RSP+0x?? Quad Word A
  RSP+0x?? Quad Word B
  RSP+0x?? Quad Word C
  RSP      Quad Word D

We will now set the following in preparation for your code:
  (stack) [0x7fffff200000:0x7fffff1fffe0] = ['0x11a3bc25', '0x1c815175', '0x239c9865', '0x2befa9db'] (list of things)
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
    mov rax, qword ptr [rsp]
    add rax, qword ptr [rsp+0x8]
    add rax, qword ptr [rsp+0x10]
    add rax, qword ptr [rsp+0x18]
    mov rdi, 4
    div rdi
    push rax 
    '''))

print(r.recvline_contains('pwn.college').decode())
```

### Level 22 - Absolute jump

```bash
In this level you will be working with control flow manipulation. This involves using instructions
to both indirectly and directly control the special register `rip`, the instruction pointer.
You will use instructions such as: jmp, call, cmp, and their alternatives to implement the requested behavior.



Earlier, you learned how to manipulate data in a pseudo-control way, but x86 gives us actual
instructions to manipulate control flow directly.

There are two major ways to manipulate control flow:
 through a jump;
 through a call.

In this level, you will work with jumps.

There are two types of jumps:
  Unconditional jumps
  Conditional jumps

Unconditional jumps always trigger and are not based on the results of earlier instructions.

As you know, memory locations can store data and instructions.

Your code will be stored at 0x4000b0 (this will change each run).

For all jumps, there are three types:
  Relative jumps: jump + or - the next instruction.
  Absolute jumps: jump to a specific address.
  Indirect jumps: jump to the memory address specified in a register.

In x86, absolute jumps (jump to a specific address) are accomplished by first putting the target address in a register reg, then doing jmp reg.

In this level we will ask you to do an absolute jump.

Perform the following:
  Jump to the absolute address 0x403000

We will now set the following in preparation for your code:
  Loading your given code at: 0x4000b0
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
    mov rax, 0x403000
    jmp rax
    '''))

print(r.recvline_contains('pwn.college').decode())
```

### Level 23 - Relative jump 

```bash
In this level we will ask you to do a relative jump.

You will need to fill space in your code with something to make this relative jump possible.

We suggest using the `nop` instruction. It's 1 byte long and very predictable.

In fact, the as assembler that we're using has a handy .rept directive that you can use to
repeat assembly instructions some number of times:
  https://ftp.gnu.org/old-gnu/Manuals/gas-2.9.1/html_chapter/as_7.html

Useful instructions for this level:
  jmp (reg1 | addr | offset) ; nop

Hint: for the relative jump, lookup how to use `labels` in x86.

Using the above knowledge, perform the following:
  Make the first instruction in your code a jmp
  Make that jmp a relative jump to 0x51 bytes from the current position
  At the code location where the relative jump will redirect control flow set rax to 0x1

We will now set the following in preparation for your code:
  Loading your given code at: 0x400072
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
    jmp w3th4nds
    .fill 0x51, 1, 0x90
    w3th4nds:
    mov rax, 0x1
    '''))

print(r.recvline_contains('pwn.college').decode())
```

### Level 24 - Control flow

```bash
In this level you will be working with control flow manipulation. This involves using instructions
to both indirectly and directly control the special register `rip`, the instruction pointer.
You will use instructions such as: jmp, call, cmp, and their alternatives to implement the requested behavior.



Now, we will combine the two prior levels and perform the following:
  Create a two jump trampoline:
    Make the first instruction in your code a jmp
    Make that jmp a relative jump to 0x51 bytes from its current position
    At 0x51 write the following code:
      Place the top value on the stack into register rdi
      jmp to the absolute address 0x403000

We will now set the following in preparation for your code:
  Loading your given code at: 0x400027
  (stack) [0x7fffff1ffff8] = 0x17
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
    jmp w3th4nds
    .fill 0x51, 1, 0x90
    w3th4nds:
    pop rdi
    mov rax, 0x403000
    jmp rax
    '''))

print(r.recvline_contains('pwn.college').decode())
```

### Level 25 - Conditional branches

```bash
We will now introduce you to conditional jumps--one of the most valuable instructions in x86.
In higher level programming languages, an if-else structure exists to do things like:
  if x is even:
    is_even = 1
  else:
   is_even = 0

This should look familiar, since it is implementable in only bit-logic, which you've done in a prior level.

In these structures, we can control the program's control flow based on dynamic values provided to the program.

Implementing the above logic with jmps can be done like so:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; assume rdi = x, rax is output
; rdx = rdi mod 2
mov rax, rdi
mov rsi, 2
div rsi
; remainder is 0 if even
cmp rdx, 0
; jump to not_even code is its not 0
jne not_even
; fall through to even code
mov rbx, 1
jmp done
; jump to this only when not_even
not_even:
mov rbx, 0
done:
mov rax, rbx
; more instructions here
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Often though, you want more than just a single 'if-else'.

Sometimes you want two if checks, followed by an else.

To do this, you need to make sure that you have control flow that 'falls-through' to the next `if` after it fails.

All must jump to the same `done` after execution to avoid the else.

There are many jump types in x86, it will help to learn how they can be used.

Nearly all of them rely on something called the ZF, the Zero Flag.

The ZF is set to 1 when a cmp is equal. 0 otherwise.

Using the above knowledge, implement the following:
  if [x] is 0x7f454c46:
    y = [x+4] + [x+8] + [x+12]
  else if [x] is 0x00005A4D:
    y = [x+4] - [x+8] - [x+12]
  else:
    y = [x+4] * [x+8] * [x+12]

where:
  x = rdi, y = rax.

Assume each dereferenced value is a signed dword.
This means the values can start as a negative value at each memory position.

A valid solution will use the following at least once:
  jmp (any variant), cmp

We will now run multiple tests on your code, here is an example run:
  (data) [0x404000] = {4 random dwords]}
  rdi = 0x404000
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
    xor eax, eax
    mov ebx, dword ptr [rdi]
    mov ecx, dword ptr [rdi+0x4]
    cmp ebx, 0x7f454c46

    jne condition_1
    add ecx, dword ptr [rdi+0x8]
    add ecx, dword ptr [rdi+0xc]
    jmp done

    condition_1:
    cmp ebx, 0x00005A4D
    jne condition_2
    sub ecx, dword ptr [rdi+0x8]
    sub ecx, dword ptr [rdi+0xc]
    jmp done
    
    condition_2:
    imul ecx, dword ptr [rdi+0x8]
    imul ecx, dword ptr [rdi+0xc]

    done:
    mov eax, ecx
    
    '''))

print(r.recvline_contains('pwn.college').decode())
```

### Level 26 - Jump tables

```bash
The last jump type is the indirect jump, which is often used for switch statements in the real world.

Switch statements are a special case of if-statements that use only numbers to determine where the control flow will go.

Here is an example:
  switch(number):
    0: jmp do_thing_0
    1: jmp do_thing_1
    2: jmp do_thing_2
    default: jmp do_default_thing

The switch in this example is working on `number`, which can either be 0, 1, or 2.

In the case that `number` is not one of those numbers, the default triggers.

You can consider this a reduced else-if type structure.

In x86, you are already used to using numbers, so it should be no suprise that you can make if statements based on something being an exact number.

In addition, if you know the range of the numbers, a switch statement works very well.

Take for instance the existence of a jump table.

A jump table is a contiguous section of memory that holds addresses of places to jump.

In the above example, the jump table could look like:
  [0x1337] = address of do_thing_0
  [0x1337+0x8] = address of do_thing_1
  [0x1337+0x10] = address of do_thing_2
  [0x1337+0x18] = address of do_default_thing

Using the jump table, we can greatly reduce the amount of cmps we use.

Now all we need to check is if `number` is greater than 2.

If it is, always do:
  jmp [0x1337+0x18]
Otherwise:
  jmp [jump_table_address + number * 8]

Using the above knowledge, implement the following logic:
  if rdi is 0:
    jmp 0x403022
  else if rdi is 1:
    jmp 0x40310d
  else if rdi is 2:
    jmp 0x4031ba
  else if rdi is 3:
    jmp 0x403286
  else:
    jmp 0x403362

Please do the above with the following constraints:
  Assume rdi will NOT be negative
  Use no more than 1 cmp instruction
  Use no more than 3 jumps (of any variant)
  We will provide you with the number to 'switch' on in rdi.
  We will provide you with a jump table base address in rsi.

Here is an example table:
  [0x404238] = 0x403022 (addrs will change)
  [0x404240] = 0x40310d
  [0x404248] = 0x4031ba
  [0x404250] = 0x403286
  [0x404258] = 0x403362
```

```python
```

