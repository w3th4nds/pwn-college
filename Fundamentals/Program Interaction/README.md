<center>
    <h1 style="color: darkgreen;">
Program Interaction
    </h1> 
</center>

For these levels, the shell always prompts us to enter the default mode. Before every execution, we run `/usr/bin/bash` to get the default shell. Each executable will need some checks to be passed in order to print the flag. From later on, I will refer to them as `TEST` lines. All runs are from `/challenge` directory.

### Level 1 - run the program

We run the `embryoio_level_1` file and get the following `FAILS`: 

```console 
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    The shell process must be running in its default, interactive mode (/bin/bash with no commandline arguments). Your commandline arguments are: ['/usr/bin/bash', '--init-file', '/usr/lib/code-server/lib/vscode/out/vs/workbench/contrib/terminal/browser/media/shellIntegration-bash.sh']
```

The shell is running a custom `bash` script instead of the default. We can simply run `/usr/bin/bash` and the re-run the program to get the flag.

```bash
$ /usr/bin/bash
$ ./embryoio_level_1 | grep pwn
```

### Level 2 - enter password

When we run the program we get this `TEST` line: 

```bash
[TEST] This program expects you to enter a simple password (specifically, wmagcvgy). Send it now!
```

We enter the given password `wmagcvgy` and get the flag.

### Level 3 - cmd args

The `TEST` line this time is:

```bash
[TEST] My argv[1] should have a value of ymvckbpwjh! Let's check...
```

We enter the argv[1] it asks and get the flag.

```bash 
$ ./embryoio_level3 ymvckbpwjh | grep pwn
```

### Level 4 - env variables

`TEST` line: 

```bash
[TEST] My 'ahrqbt' environment variable should have a value of xcejcyrqwq! Let's check...
```

We set this `env` variable `ahrqbt` to the value  `xcejcyrqwq` and get the flag.

```bash
$ export ahrqbt=xcejcyrqwq && ./embryoio_level4 | grep pwn
```

### Level 5 - file redirect stdin

`TEST` line:

```bash
[TEST] You should have redirected a file called /tmp/kbcpyf to my stdin. Checking...
```

We simply redirect the given file to our binary and get the flag.

```bash
$ touch /tmp/kbcpyf && ./embryoio_level5 < /tmp/kbcpyf  
```

After we pass that check, another `TEST` line comes up:

```bash
[GOOD] The file at the other end of my stdin looks okay!
[TEST] This program expects you to enter a simple password (specifically, dxkhnvsn). Send it now!
```

We add the password `dxkhnvsn` to the file and get the flag.

```bash
$ echo "dxkhnvsn" > /tmp/kbcpyf &&  ./embryoio_level5 < /tmp/kbcpyf | grep pwn
```

### Level 6 - file redirect stdout

`TEST` line: 

```bash
[TEST] I will now check that you redirected /tmp/wemmre to/from my stdout.
```

We simply need to redirect the output of the program to this file and then cat its content.

```bash
$ ./embryoio_level6 > /tmp/wemmre && cat /tmp/wemmre | grep pwn
```

### Level 7 - empty env variables

```bash
[TEST] You should launch me with an empty environment. Checking...
```

We need to `unset` all the `env` variables. From the `man` page of `env`:

>     -i, --ignore-environment
>         start with an empty environment

```bash
$ env -i ./embryoio_level7 | grep pwn
```

### Level 8 - bash script

```bash
[FAIL]    The shell process must be executing a shell script that you wrote like this: `bash my_script.sh`
```

We need to create a `bash` script that contains the path of the binary file and then run `bash myscript.sh`.

```bash 
$ echo "/challenge/embryoio_level8" > /tmp/my_script.sh && bash /tmp/my_script.sh | grep pwn
```

### Level 9 - bash script

Pretty much the same challenge as before. The only difference is that it asks for a password after you run the script.

```bash
- the challenge will check for a hardcoded password over stdin : rjiewmuh

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] Checking to make sure the process is a non-interactive shell script.
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    The shell process must be executing a shell script that you wrote like this: `bash my_script.sh`
```

```bash
$ echo "/challenge/embryoio_level9" > /tmp/my_script.sh && bash /tmp/my_script.sh
> rjiewmuh
```

### Level 10 - bash script

Same as before with the only difference it wants an `argv[1]` also.

```bash
- the challenge will check that argv[NUM] holds value VALUE (listed to the right as NUM:VALUE) : 1:dgfkwdrfuw
```

```bash
$ echo "/challenge/embryoio_level10 dgfkwdrfuw" > /tmp/my_script.sh && bash /tmp/my_script.sh | grep pwn
```

### Level 11 - bash script

Same as before, but this time we have to create an `env` variable with a given value.

```bash
- the challenge will check that env[KEY] holds value VALUE (listed to the right as KEY:VALUE) : caogqf:ssgxjrocni
```

```bash
$ echo "export caogqf=ssgxjrocni && /challenge/embryoio_level11" > /tmp/my_script.sh && bash /tmp/my_script.sh | grep pwn
```

### Level 12 - bash script

This time the binary asks for a specific file as input and a `hardcoded` password.

```bash
- the challenge will check that input is redirected from a specific file path : /tmp/wfdtzy
- the challenge will check for a hardcoded password over stdin : xuxrqblz
```

We create the password in the specified file, then we proceed as usual to make our script and then at the end we redirect the file to the program.

```bash
$ echo "xuxrqblz" > /tmp/wfdtzy && \
echo "/challenge/embryoio_level12" > /tmp/my_script.sh && \
bash /tmp/my_script.sh < /tmp/wfdtzy | grep pwn
```

### Level 13 - bash script

Same as `Level 9` with the difference that now it redirects the output to a specific file.

```bash
$ echo "/challenge/embryoio_level13" > /tmp/my_script.sh && bash /tmp/my_script.sh > /tmp/auiwce && cat /tmp/auiwce | grep pwn
```

### Level 14 - bash script

This is a mix of `Level 7 and 8`.

```bash
- the challenge will check that the environment is empty (except LC_CTYPE, which is impossible to get rid of in some cases)
```

```bash
$ echo "env -i /challenge/embryoio_level14" > /tmp/my_script.sh && bash /tmp/my_script.sh | grep pwn
```

### Level 15 - ipython/pwntools

We need to create an `ipython` script to run the binary. I prefer to open the binary as process with `pwntools`. 

```python
from pwn import *

context.log_level = 'critical'

r = process("/challenge/embryoio_level15")

print(r.recvline_contains(b"pwn").decode())
```

We save the file as `/tmp/w3t.py` and then we run `ipython` to enter the interpreter. After that we execute the following command to get flag.

```python
In [1]: %run w3t.py
```

### Level 16 - ipython/pwntools

Same as before with a small twist.

```bash
- the challenge will check for a hardcoded password over stdin : muqttbzp
```

```python
from pwn import *

context.log_level = 'critical'

r = process("/challenge/embryoio_level16")

r.sendline(b"muqttbzp")

print(r.recvline_contains(b"pwn").decode())
```

```python
In [1]: %run w3t.py
```

### Level 17 - ipython/pwntools

Pretty much the same.

```bash
- the challenge will check that argv[NUM] holds value VALUE (listed to the right as NUM:VALUE) : 1:muzdkobxjd
```

```python
from pwn import *

context.log_level = 'critical'

r = process(["/challenge/embryoio_level17", "muzdkobxjd"])

print(r.recvline_contains(b"pwn").decode())
```

### Level 18 - ipython/pwntools

The challenges follow a certain pattern, no need for deep analysis.

```bash
- the challenge will check that env[KEY] holds value VALUE (listed to the right as KEY:VALUE) : cnsysl:idndqtahuc
```

```python
from pwn import *

context.log_level = 'critical'

r = process(["/challenge/embryoio_level18"], env={'cnsysl': 'idndqtahuc'})

print(r.recvline_contains(b"pwn").decode())
```

### Level 19 - ipython/pwntools

```bash
- the challenge will check that input is redirected from a specific file path : /tmp/qymjzu
- the challenge will check for a hardcoded password over stdin : hrmhooxc
```

We create the file at `/tmp` with the desired value and then pass it as `stdin` to the process.

```python
from pwn import *
import os

context.log_level = 'critical'

os.system("echo hrmhooxc > /tmp/qymjzu")

with open("/tmp/qymjzu", "rb") as f:  
  r = process(["/challenge/embryoio_level19"], stdin=f)

print(r.recvline_contains(b"pwn").decode())

f.close()
```

### Level 20 - ipython/pwntools

```bash
- the challenge will check that output is redirected to a specific file path : /tmp/dkihjg
```

```python
from pwn import *

context.log_level = 'critical'

with open("/tmp/dkihjg", "rb") as f:
    r = process("/challenge/embryoio_level20", stdout=f)
    print(f.read())

f.close()
```

### Level 21 - ipython/pwntools

```python
from pwn import *

context.log_level = 'critical'

r = process(["/challenge/embryoio_level21"], env={})

print(r.recvline_contains(b"pwn").decode())
```

### Level 22 - ipython/pwntools

We need to create a `subprocess` so the parent process is `python`.

```bash
- the challenge checks for a specific parent process : python
```

```bash
python w3t.py | grep pwn
```

