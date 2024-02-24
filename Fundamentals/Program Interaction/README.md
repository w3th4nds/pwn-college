<div align="center">
    <h1> Program Interaction </h1> 
</div>

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

<div align="center">
    <h1> Bash Scripts </h1> 
</div>

### Level 8

```bash
[FAIL]    The shell process must be executing a shell script that you wrote like this: `bash my_script.sh`
```

We need to create a `bash` script that contains the path of the binary file and then run `bash myscript.sh`.

```bash 
$ echo "/challenge/embryoio_level8" > /tmp/my_script.sh && bash /tmp/my_script.sh | grep pwn
```

### Level 9

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

### Level 10

Same as before with the only difference it wants an `argv[1]` also.

```bash
- the challenge will check that argv[NUM] holds value VALUE (listed to the right as NUM:VALUE) : 1:dgfkwdrfuw
```

```bash
$ echo "/challenge/embryoio_level10 dgfkwdrfuw" > /tmp/my_script.sh && bash /tmp/my_script.sh | grep pwn
```

### Level 11

Same as before, but this time we have to create an `env` variable with a given value.

```bash
- the challenge will check that env[KEY] holds value VALUE (listed to the right as KEY:VALUE) : caogqf:ssgxjrocni
```

```bash
$ echo "export caogqf=ssgxjrocni && /challenge/embryoio_level11" > /tmp/my_script.sh && bash /tmp/my_script.sh | grep pwn
```

### Level 12

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

### Level 13

Same as `Level 9` with the difference that now it redirects the output to a specific file.

```bash
$ echo "/challenge/embryoio_level13" > /tmp/my_script.sh && bash /tmp/my_script.sh > /tmp/auiwce && cat /tmp/auiwce | grep pwn
```

### Level 14 

This is a mix of `Level 7 and 8`.

```bash
- the challenge will check that the environment is empty (except LC_CTYPE, which is impossible to get rid of in some cases)
```

```bash
$ echo "env -i /challenge/embryoio_level14" > /tmp/my_script.sh && bash /tmp/my_script.sh | grep pwn
```

<div align="center">
    <h1> pwntools - ipython </h1> 
</div>

### Level 15

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

### Level 16

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

### Level 17

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

### Level 18

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

### Level 19

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

### Level 20

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

### Level 21

```python
from pwn import *

context.log_level = 'critical'

r = process(["/challenge/embryoio_level21"], env={})

print(r.recvline_contains(b"pwn").decode())
```

<div align="center">
    <h1> subprocess </h1> 
</div>

### Level 22

We need to create a `subprocess` so the parent process is `python`.

```bash
- the challenge checks for a specific parent process : python
```

```python
import subprocess

subprocess.run(["/challenge/embryoio_level21"])
```

```bash
$ python w3t.py | grep pwn
```

### Level 23

Same but with `hardcoded` password.

```python
import subprocess

print(subprocess.run(["/challenge/embryoio_level23"], input="nnwzvnjf\n", capture_output=True, text=True))
```

```bash
$ python w3t.py | grep pwn
```

### Level 24

```bash
- the challenge will check that argv[NUM] holds value VALUE (listed to the right as NUM:VALUE) : 1:hvcwkmqhxb
```

Similar to previous challenges.

```python
import subprocess

print(subprocess.run(["/challenge/embryoio_level24", "hvcwkmqhxb"]))
```

```bash
$ python w3t.py | grep pwn
```

### Level 25

```bash
- the challenge will check that env[KEY] holds value VALUE (listed to the right as KEY:VALUE) : qpvtwc:eghdabuygy
```

```python
import subprocess

print(subprocess.run(["/challenge/embryoio_level25"], env={"qpvtwc": "eghdabuygy"}))
```

```bash
$ python w3t.py | grep pwn
```

### Level 26

```bash
- the challenge will check that input is redirected from a specific file path : /tmp/isodpx
- the challenge will check for a hardcoded password over stdin : gkbdahrs
```

```python
import subprocess
import os

os.system("echo gkbdahrs > /tmp/isodpx")

with open("/tmp/isodpx", "rb") as f:  
  print(subprocess.run(["/challenge/embryoio_level26"], stdin=f))

f.close()
```

```bash
$ python w3t.py | grep pwn
```

### Level 27

```bash
- the challenge will check that output is redirected to a specific file path : /tmp/ewcmrr
```

```python
import subprocess
import os

with open("/tmp/ewcmrr", "wb") as f:  
  print(subprocess.run(["/challenge/embryoio_level27"], stdout=f))

f.close()
```

```bash
$ python lel.py && cat /tmp/ewcmrr | grep pwn
```

### Level 28

```bash
- the challenge will check that the environment is empty (except LC_CTYPE, which is impossible to get rid of in some cases)
```

```python
import subprocess

print(subprocess.run(["/challenge/embryoio_level28"], env={}))
```

```bash
$ python w3t.py | grep pwn
```

<div align="center">
    <h1> Binary - fork </h1> 
</div>


### Level 29

New set of challenges (hopefully).

```bash
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : binary

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] Checking to make sure that the process is a custom binary that you created by compiling a C program
[TEST] that you wrote. Make sure your C program has a function called 'pwncollege' in it --- otherwise,
[TEST] it won't pass the checks.
[HINT] If this is a check for the *parent* process, keep in mind that the exec() family of system calls
[HINT] does NOT result in a parent-child relationship. The exec()ed process simply replaces the exec()ing
[HINT] process. Parent-child relationships are created when a process fork()s off a child-copy of itself,
[HINT] and the child-copy can then execve() a process that will be the new child. If we're checking for a
[HINT] parent process, that's how you make that relationship.
[INFO] The executable that we are checking is: /usr/bin/bash.
[HINT] One frequent cause of the executable unexpectedly being a shell or docker-init is that your
[HINT] parent process terminated before this check was run. This happens when your parent process launches
[HINT] the child but does not wait on it! Look into the waitpid() system call to wait on the child!

[HINT] Another frequent cause is the use of system() or popen() to execute the challenge. Both will actually
[HINT] execute a shell that will then execute the challenge, so the parent of the challenge will be that
[HINT] shell, rather than your program. You must use fork() and one of the exec family of functions (execve(),
[HINT] execl(), etc).
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    The process must be your own program in your own home directory.
```

For this set of challenges we should always create a `pwncollege()` inside our `C` code. Then, with `fork()`, we create a child process and execute `execl` to run our program.

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>

void main() {
    // Create a child process
    pid_t pid = fork();

    if (pid < 0) {
        // Fork failed
        perror("Fork failed");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        // Child process
        execl("/challenge/embryoio_level29", "/challenge/embryoio_level29", NULL);
        // Child process exits after executing the function
        _exit(0);
    } else {
        // Parent process
        // Wait for the child process to finish
        waitpid(pid, NULL, 0);
    }
}

__attribute__((constructor))
void pwncollege() {}
```

```bash
gcc w3t.c -o w3t && ./w3t | grep pwn.college
```

### Level 30

Same but with hardcoded password from `stdin`.

```bash
- the challenge will check for a hardcoded password over stdin : yjgngclz
```

We take the exact program from before and we pass it the password.

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>

void main() {
    // Create a child process
    pid_t pid = fork();

    if (pid < 0) {
        // Fork failed
        perror("Fork failed");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        // Child process
        execl("/challenge/embryoio_level30", "/challenge/embryoio_level30", NULL);
        // Child process exits after executing the function
        _exit(0);
    } else {
        // Parent process
        // Wait for the child process to finish
        waitpid(pid, NULL, 0);
    }
}

__attribute__((constructor))
void pwncollege() {}
```

```bash
$ gcc w3t.c -o w3t &&  echo 'yjgngclz' | ./w3t | grep pwn.college
```

### Level 31

```bash
- the challenge will check that argv[NUM] holds value VALUE (listed to the right as NUM:VALUE) : 1:nlhrekavwx
```

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>

void main() {
    // Create a child process
    pid_t pid = fork();

    if (pid < 0) {
        // Fork failed
        perror("Fork failed");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        // Child process
        execl("/challenge/embryoio_level31", "/challenge/embryoio_level31", "nlhrekavwx", NULL);
        // Child process exits after executing the function
        _exit(0);
    } else {
        // Parent process
        // Wait for the child process to finish
        waitpid(pid, NULL, 0);
    }
}

__attribute__((constructor))
void pwncollege() {}
```

```bash
$ gcc w3t.c -o w3t && ./w3t | grep pwn.college
```

### Level 32

```bash
- the challenge will check that env[KEY] holds value VALUE (listed to the right as KEY:VALUE) : abhhly:fjrkpncrkn
```

We will use the `setenv` function to set the variables.

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>

void main() {
    // Set environment variable
    if (setenv("abhhly", "fjrkpncrkn", 1) != 0) {
        perror("setenv failed");
        exit(EXIT_FAILURE);
    }
    // Create a child process
    pid_t pid = fork();

    if (pid < 0) {
        // Fork failed
        perror("Fork failed");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        // Child process
        execl("/challenge/embryoio_level32", "/challenge/embryoio_level32", "nlhrekavwx", NULL);
        // Child process exits after executing the function
        _exit(0);
    } else {
        // Parent process
        // Wait for the child process to finish
        waitpid(pid, NULL, 0);
    }
}

__attribute__((constructor))
void pwncollege() {}
```

```bash
$ gcc w3t.c -o w3t && ./w3t | grep pwn.college
```

### Level 33

```bash
- the challenge will check that input is redirected from a specific file path : /tmp/pempyr
- the challenge will check for a hardcoded password over stdin : zyorkqoc
```

We will use the `freopen` function to redirect the input to a specific file path.

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>

void main() {
    // Check if input is redirected from the specific file path
    if (!freopen("/tmp/pempyr", "r", stdin)) {
        perror("freopen failed");
        exit(EXIT_FAILURE);
    }
    // Create a child process
    pid_t pid = fork();

    if (pid < 0) {
        // Fork failed
        perror("Fork failed");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        // Child process
        execl("/challenge/embryoio_level33", "/challenge/embryoio_level33", NULL);
        // Child process exits after executing the function
        _exit(0);
    } else {
        // Parent process
        // Wait for the child process to finish
        waitpid(pid, NULL, 0);
    }
}

__attribute__((constructor))
void pwncollege() {}
```

```bash
$ echo zyorkqoc > /tmp/pempyr && gcc w3t.c -o w3t && ./w3t | grep pwn.college
```

### Level 34

```bash
- the challenge will check that output is redirected to a specific file path : /tmp/vugval
```

We will use the `freopen` function to redirect the input to a specific file path.

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>

void main() {
    // Check if input is redirected from the specific file path
    if (!freopen("/tmp/vugval", "w", stdout)) {
        perror("freopen failed");
        exit(EXIT_FAILURE);
    }
    // Create a child process
    pid_t pid = fork();

    if (pid < 0) {
        // Fork failed
        perror("Fork failed");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        // Child process
        execl("/challenge/embryoio_level34", "/challenge/embryoio_level34", NULL);
        // Child process exits after executing the function
        _exit(0);
    } else {
        // Parent process
        // Wait for the child process to finish
        waitpid(pid, NULL, 0);
    }
}

__attribute__((constructor))
void pwncollege() {}
```

```bash
$ gcc w3t.c -o w3t && ./w3t; cat /tmp/vugval | grep pwn.college
```

### Level 35

```bash
- the challenge will check that the environment is empty (except LC_CTYPE, which is impossible to get rid of in some cases)
```

We will use `    clearenv();` to clear the `env` variables.

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>

void main() {
    // Clear the environment
    clearenv();
    
    // Create a child process
    pid_t pid = fork();

    if (pid < 0) {
        // Fork failed
        perror("Fork failed");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        // Child process
        execl("/challenge/embryoio_level35", "/challenge/embryoio_level35", NULL);
        // Child process exits after executing the function
        _exit(0);
    } else {
        // Parent process
        // Wait for the child process to finish
        waitpid(pid, NULL, 0);
    }

__attribute__((constructor))
void pwncollege() {}
```

```bash
$ gcc w3t.c -o w3t && ./w3t | grep pwn.college
```

<div align="center">
    <h1> Pipes </h1> 
</div>

### Level 36

In this set of challenges, we need to run `/usr/bin/bash` again before we start our exploitation.

```bash
- the challenge checks for a specific parent process : bash
- the challenge checks for a specific process at the other end of stdout : cat    
```

```bash
$ /challenge/embryoio_level36 | cat | grep pwn.college
```

### Level 37

```bash
- the challenge checks for a specific process at the other end of stdout : grep
```

This is what we have been doing for the rest of the challenges so far.

```bash
$ /challenge/embryoio_level37 | grep pwn.college
```

### Level 38

```bash
- the challenge checks for a specific process at the other end of stdout : sed
```

```bash
$ /challenge/embryoio_level38 | sed -n '/pwn\.college/p'
```

### Level 39

```bash
- the challenge checks for a specific process at the other end of stdout : rev
```

We need to `rev` the string and then `rev` it again to get the actual flag.

```bash
$ /challenge/embryoio_level39 | rev | rev | grep pwn.college
```

### Level 40

```bash
- the challenge checks for a specific process at the other end of stdin : cat
- the challenge will check for a hardcoded password over stdin : xrilatyr
```

```bash
$ cat | /challenge/embryoio_level40 
```

After that we enter the password to get the flag.

### Level 41 BROOOOOOOOOOOKEN

```bash
- the challenge checks for a specific process at the other end of stdin : rev
- the challenge will check for a hardcoded password over stdin : akpebwrt
```



```bash
$ rev | /challenge/embryoio_level41	# add this if it manages to read it -> trwbepka
```

<div align="center">
    <h1>
Shellscript
    </h1> 
</div>

### Level 42

In this set of challenges we need to write some simple `bash` scripts or `shellscripts`. To run them, we need to make them executable with `chmod +x w3t.sh`.

```bash
- the challenge checks for a specific parent process : shellscript
- the challenge checks for a specific process at the other end of stdout : cat
```

```bash
#!/usr/bin/bash

/challenge/embryoio_level42 | cat | grep pwn.college
```

### Level 43

```bash
- the challenge checks for a specific process at the other end of stdout : grep
```

```bash
#!/usr/bin/bash

/challenge/embryoio_level43 | grep pwn.college
```

### Level 44

```bash
- the challenge checks for a specific process at the other end of stdout : sed
```

```bash
#!/usr/bin/bash

/challenge/embryoio_level44 | sed -n '/pwn\.college/p'
```

### Level 45

```bash
- the challenge checks for a specific process at the other end of stdout : rev
```

```bash
#!/usr/bin/bash

/challenge/embryoio_level45 | rev | rev | grep pwn.college
```

### Level 46

```bash
- the challenge checks for a specific process at the other end of stdin : cat
- the challenge will check for a hardcoded password over stdin : qisfmbwz
```

```bash
#!/usr/bin/bash

cat | /challenge/embryoio_level46
```

After than, enter the password.

### Level 47 BROOOOOOOOOOOOOOOOOOOOOOOOOken

```bash
- the challenge checks for a specific process at the other end of stdin : rev
- the challenge will check for a hardcoded password over stdin : mrgnhwlh
```

<div align="center">
    <h1> ipython </h1> 
</div>

### Level 48

This was a bit harsh, I needed to search a lot to find about `Popen`. 

```bash
- the challenge checks for a specific parent process : ipython
- the challenge checks for a specific process at the other end of stdout : cat
```



```bash
#!/usr/bin/python
import subprocess

p1 = subprocess.Popen(['/challenge/embryoio_level48'], stdout=subprocess.PIPE)
p2 = subprocess.Popen(['/usr/bin/cat'], stdin=p1.stdout, stdout=subprocess.PIPE)

print(p2.communicate())
```

After that, we open `ipython` and execute the program.

```ipython
%run w3t.py
```

### Level 49

```bash
- the challenge checks for a specific parent process : ipython
- the challenge checks for a specific process at the other end of stdout : grep
```





