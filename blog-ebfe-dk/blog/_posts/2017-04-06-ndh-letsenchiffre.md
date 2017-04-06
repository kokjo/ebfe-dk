---
layout: post
title: Nuit du Hack Quals 2017 - Lets Enchiffre
comments: false
category: ctf
tags: ctf, ndh, pwnable, racecondition, protobuf, fedora
---

This is a write-up of the Lets Enchiffre challenge from Nuit du Hack CTF Quals 2017.

Apparently I was the only one to solve this challenge during the CTF.


## The Challenge

It is a 32-bit x86 binary compiled on some RedHat system and it exposes a LetsEncrypt-like service,
which can create SSL certificates upon request. It is linked against `libzxcvbn.so.0`, and as evident
from the output of `readelf`:
{% highlight bash %}
$ readelf -d LetsEnchiffre
...
 0x0000000f (RPATH)                      Library rpath: [/home/n.chatelain/Sysdream/NDH2017/Quals/quals-letsenchiffre/zxcvbn-c]
...
{% endhighlight %}
it is likely to be used with `https://github.com/tsyrogit/zxcvbn-c.git`.


## Creating a test setup

After a bit of trail-and-error and fiddling around with Fedora and CentOS docker images,
I was able to create the following `Dockerfile`:

{% gist b57addb2a9a29111f2ab4548ba05da9f %}

in which I was able to run the binary.


## Reverse engineering

The challenge uses Protobuf and zxcvbn, it is an accept-loop based server, and for each connect it spawns a thread.

### Race condition

The use of threading hints at a possible race condition bug and sure enough we have multiple reader and writers for the global variable stored at `0x08056450`.
This variable is used to store a pointer to an password either supplied by a user or generated automatically.

When recviving the password this happens:

```c
google::protobuf::MessageLite::ParseFromArray(&pbuf_msg, buf, v18);
password_1 = protobuf_get_password_field(pbuf_msg);
password_g = std::__cxx11::basic_string::c_str(password_1);
password_2 = protobuf_get_password_field(pbuf_msg);
password_is_short_enough = 0;
if ( *std::basic_string::c_str(password_2) )
{
  password_3 = protobuf_get_password_field(pbuf_msg);
  password_3_cstr = std::basic_string::c_str(password_3);
  if ( strlen(password_3_cstr) <= 99 )
    password_is_short_enough = 1;
}
```

So we set the global variable `password_g` and then checks if it is shorter than 100 bytes,
thus we can always override the `password_g` variable which might be used in another thread.

### Buffer overflow

Next we take a look at the password strength check function at `0x0804b32b`:

```c
  snprintf(foo, 0x400u, "%s%s", "letsenchiffre", password_g);
  v7 = ZxcvbnMatch(foo, 0, &v6);
  if ( v7 >= 70.0 ) { ... } else { ... }
```

The variable `foo` is located on the stack and is only 114 bytes long. This is clearly bad.

## Exploitation

The challenge does have `execstack` so we just need to put our shellcode in memory and jump to it, and running `ROPgadget` on the binary we get:

```text
0x0804b490 : pop esp ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret

```

So if we can point `esp` to just a few pops below `password_g` we would start executing at the start of out payload, so we can exploit the binary with

{% gist aeb50dda6fc9dcbbceee14af5961adf7 %}

and if we are lucky we will hit the race condition just right and get a connect back on `ebfe.dk:4243`.

### Flag
`NDH{df297855f5038ffd0b7f8ad86ed155c3d3643d18eb2a2f1a22e107039bad7cd0}`

