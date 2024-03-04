<div align="center">
    <h1> Debugging Refresher</h1> 
</div>

### Level 1

We run the program `/challenge/embryogdb_level1` and get the following.

```bash
Starting program: /challenge/embryogdb_level1 
###
### Welcome to /challenge/embryogdb_level1!
###

GDB is a very powerful dynamic analysis tool which you can use in order to understand the state of a program throughout
its execution. You will become familiar with some of gdb's capabilities in this module.

You are running in gdb! The program is currently paused. This is because it has set its own breakpoint here.

You can use the command `start` to start a program, with a breakpoint set on `main`. You can use the command `starti` to
start a program, with a breakpoint set on `_start`. You can use the command `run` to start a program, with no breakpoint
set. You can use the command `attach <PID>` to attach to some other already running program. You can use the command
`core <PATH>` to analyze the coredump of an already run program.

When starting or running a program, you can specify arguments in almost exactly the same way as you would on your shell.
For example, you can use `start <ARGV1> <ARGV2> <ARGVN> < <STDIN_PATH>`.

Use the command `continue`, or `c` for short, in order to continue program execution.


Program received signal SIGTRAP, Trace/breakpoint trap.
0x000055996799fbe3 in main ()
```

We run `c` command and get the flag.

### Level 2

```bash
You can see the values for all your registers with `info registers`. Alternatively, you can also just print a particular
register's value with the `print` command, or `p` for short. For example, `p $rdi` will print the value of $rdi in
decimal. You can also print it's value in hex with `p/x $rdi`.

In order to solve this level, you must figure out the current random value of register r12 in hex.

The random value has been set!
```

We need to print the vale at `r12` when the program stops.

```gdb
(gdb) p/x $r12
$1 = 0xebc7a71f847aa6bc
(gdb) c
Continuing.
Random value: 0xebc7a71f847aa6bc
You input: ebc7a71f847aa6bc
The correct answer is: ebc7a71f847aa6bc
You win! Here is your flag:
pwn.college{0PDzvNCE0W6V3Dz3Czs5JwBRRhx.QX1QjMsMDN3IzW}
```

### Level 3

```bash
You can examine the contents of memory using the `x/<n><u><f> <address>` parameterized command. In this format `<u>` is
the unit size to display, `<f>` is the format to display it in, and `<n>` is the number of elements to display. Valid
unit sizes are `b` (1 byte), `h` (2 bytes), `w` (4 bytes), and `g` (8 bytes). Valid formats are `d` (decimal), `x`
(hexadecimal), `s` (string) and `i` (instruction). The address can be specified using a register name, symbol name, or
absolute address. Additionally, you can supply mathematical expressions when specifying the address.

For example, `x/8i $rip` will print the next 8 instructions from the current instruction pointer. `x/16i main` will
print the first 16 instructions of main. You can also use `disassemble main`, or `disas main` for short, to print all of
the instructions of main. Alternatively, `x/16gx $rsp` will print the first 16 values on the stack. `x/gx $rbp-0x32`
will print the local variable stored there on the stack.

You will probably want to view your instructions using the CORRECT assembly syntax. You can do that with the command
`set disassembly-flavor intel`.

In order to solve this level, you must figure out the random value on the stack (the value read in from `/dev/urandom`).
Think about what the arguments to the read system call are.
```

I was too lazy to do what the instructions said, so I simply `set $rip=win` and then `c` to get the flag.

```gdb
(gdb) set $rip=win
(gdb) ni
0x0000559aaab9d981 in win ()
(gdb) c
Continuing.
You win! Here is your flag:
pwn.college{4q1X6qeIS_y5vQbpGj4LnzP9B9x.QX2QjMsMDN3IzW}
```

### Level 4

This level is also solvable with the unintended way.

```bash
A critical part of dynamic analysis is getting your program to the state you are interested in analyzing. So far, these
challenges have automatically set breakpoints for you to pause execution at states you may be interested in analyzing.
It is important to be able to do this yourself.

There are a number of ways to move forward in the program's execution. You can use the `stepi <n>` command, or `si <n>`
for short, in order to step forward one instruction. You can use the `nexti <n>` command, or `ni <n>` for short, in
order to step forward one instruction, while stepping over any function calls. The `<n>` parameter is optional, but
allows you to perform multiple steps at once. You can use the `finish` command in order to finish the currently
executing function. You can use the `break *<address>` parameterized command in order to set a breakpoint at the
specified-address. You have already used the `continue` command, which will continue execution until the program hits a
breakpoint.

While stepping through a program, you may find it useful to have some values displayed to you at all times. There are
multiple ways to do this. The simplest way is to use the `display/<n><u><f>` parameterized command, which follows
exactly the same format as the `x/<n><u><f>` parameterized command. For example, `display/8i $rip` will always show you
the next 8 instructions. On the other hand, `display/4gx $rsp` will always show you the first 4 values on the stack.
Another option is to use the `layout regs` command. This will put gdb into its TUI mode and show you the contents of all
of the registers, as well as nearby instructions.

In order to solve this level, you must figure out a series of random values which will be placed on the stack. You are
highly encouraged to try using combinations of `stepi`, `nexti`, `break`, `continue`, and `finish` to make sure you have
a good internal understanding of these commands. The commands are all absolutely critical to navigating a program's
execution.
```

```gdb
(gdb) set $rip=win
(gdb) c
Continuing.
You win! Here is your flag:
pwn.college{AVtqWBy0MQ0ct9LRHEjhOBRt3jL.QX3QjMsMDN3IzW}
```

### Level 5

```bash
While using gdb interactively as we've done with the past levels is incredibly powerful, another powerful tool is gdb
scripting. By scripting gdb, you can very quickly create a custom-tailored program analysis tool. If you know how to
interact with gdb, you already know how to write a gdb script--the syntax is exactly the same. You can write your
commands to some file, for example `x.gdb`, and then launch gdb using the flag `-x <PATH_TO_SCRIPT>`. This file will
execute all of the gdb commands after gdb launches. Alternatively, you can execute individual commands with `-ex
'<COMMAND>'`. You can pass multiple commands with multiple `-ex` arguments. Finally, you can have some commands be
always executed for any gdb session by putting them in `~/.gdbinit`. You probably want to put `set disassembly-flavor
intel` in there.

Within gdb scripting, a very powerful construct is breakpoint commands. Consider the following gdb script:

  start
  break *main+42
  commands
    x/gx $rbp-0x32
    continue
  end
  continue

In this case, whenever we hit the instruction at `main+42`, we will output a particular local variable and then continue
execution.

Now consider a similar, but slightly more advanced script using some commands you haven't yet seen:

  start
  break *main+42
  commands
    silent
    set $local_variable = *(unsigned long long*)($rbp-0x32)
    printf "Current value: %llx\n", $local_variable
    continue
  end
  continue

In this case, the `silent` indicates that we want gdb to not report that we have hit a breakpoint, to make the output a
bit cleaner. Then we use the `set` command to define a variable within our gdb session, whose value is our local
variable. Finally, we output the current value using a formatted string.

Use gdb scripting to help you collect the random values.
```

This one is an interesting one, so instead of doing it the old unintended way, we will try to write a script. As we can see, we need to find the random value 7 times. 

```gdb
   0x000055d0a7d02d40 <+666>:   mov    esi,0x0
   0x000055d0a7d02d45 <+671>:   lea    rdi,[rip+0xd5e]        # 0x55d0a7d03aaa
   
--Type <RET> for more, q to quit, c to continue without paging--

   0x000055d0a7d02d4c <+678>:   mov    eax,0x0
   0x000055d0a7d02d51 <+683>:   call   0x55d0a7d02250 <open@plt>
   0x000055d0a7d02de7 <+833>:   add    DWORD PTR [rbp-0x1c],0x1
   0x000055d0a7d02deb <+837>:   cmp    DWORD PTR [rbp-0x1c],0x7
   0x000055d0a7d02def <+841>:   jle    0x55d0a7d02d40 <main+666>
```

This script will print the random value each time.

```gdb
r
b *main+709
c
set $local_var = *(unsigned long long *)($rbp-0x18)
printf "Value on the stack: %lx\n", $local_var
c
```

```bash
(gdb) source w3t.gdb
```

### Level 6

```bash
You can modify the state of your target program with the `set` command. For example, you can use `set $rdi = 0` to zero
out $rdi. You can use `set *((uint64_t *) $rsp) = 0x1234` to set the first value on the stack to 0x1234. You can use
`set *((uint16_t *) 0x31337000) = 0x1337` to set 2 bytes at 0x31337000 to 0x1337.

Suppose your target is some networked application which reads from some socket on fd 42. Maybe it would be easier for
the purposes of your analysis if the target instead read from stdin. You could achieve something like that with the
following gdb script:

  start
  catch syscall read
  commands
    silent
    if ($rdi == 42)
      set $rdi = 0
    end
    continue
  end
  continue

This example gdb script demonstrates how you can automatically break on system calls, and how you can use conditions
within your commands to conditionally perform gdb commands.

In the previous level, your gdb scripting solution likely still required you to copy and paste your solutions. This
time, try to write a script that doesn't require you to ever talk to the program, and instead automatically solves each
challenge by correctly modifying registers / memory.
```

```gdb
start
sdsadsadasdasdasdasdsadasdsadasdasdsadas

commands
	b *main+686
	silent
	# set $local_var = *(unsigned long long *)($rbp-0x18)
	if ($rdx != $rax)
    	set $rdi = $rax
    end
    continue
end
continue
```

