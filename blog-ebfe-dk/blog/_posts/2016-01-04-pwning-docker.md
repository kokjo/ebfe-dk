---
layout: post
title: 32c3 Docker
comments: true
category: ctf
tags: ctf, 32c3, docker, containers
---

This is a write-up of the docker challenge from the 32c3 CTF.


## The Challenge

We were given ssh access is a box as the user `eve`,
and we needed to read a flag(`/home/adam/flag`) that the user `adam` had read-only rights to.

`adam` had a binary(`/home/adam/docker`) which did:
{% highlight bash %}
/usr/bin/docker run -it --privileged=false -u 1337:65534 --cap-drop=ALL --net=host ubuntu /bin/bash
{% endhighlight %}

Which means that we had a bash shell inside a docker container running as `adam`
but was using the same network stack as the host.


## The Solution

As we were running as `adam` inside the container the logical step would be to break out of the container,
and because the docker container was running with `--net=host` it was natural to think that it was a network related issue.

Thus the obvious choice is *unix doman sockets*, which are files that behaves as sockets but have some interesting features such as the ability to transfer *file descriptors*.

So digging though man pages we found something called *abstract unix domain*, which are *unix domain sockets* but not files.
All this information can be found in `man unix`, along with information describing how to transfer *file descriptors* over *unix domain sockets*

After researching all this arcane magic we came up with:
{% gist 75cec0f466fc34fa2922 %}
Which should be run outside of the docker as `eve` like:

`./sendfd foobar /`

{% gist 5878dff28a26a09f5805 %}
And this should be run side of the docker as `adam` like:

`./recvfd foobar /bin/bash`


## The twist

All of this was running inside a chroot, and `adam`'s flag was a false flag,
The real flag was at `/flag` and `adam`'s was at `/chroot/home/adam/flag`.

But when your current working directory is already unreachable from the root you can break out of any chroot your are in. So this was not a problem.


## Conclusion

This is not a bug in docker. Everything is working as intended. `--net=host` is harmful for your sandboxing.
