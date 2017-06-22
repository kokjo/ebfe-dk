---
layout: post
title: Google CTF Rubik
comments: true
category: ctf
tags: ctf, gctf2017, crypto
---

This is a write-up of the Rubik challenge from the Google CTF Qualification round 2017


## The challenge
The challenge uses Stickel's Key exchange over the rubik's cube group.

When connecting to the challenge on `rubik.ctfcompetition.com:1337` we are greeted with the following menu:

```text
Welcome to the Rubik's cube authentication server!

You have the following options:
1) Public key service
2) Register
3) Login
q) Quit
```

1. The public key service lets us compute a rubik's cube state from a private key consisting of two numbers.
2. Allows us to register a user with a specified public key.
3. Gives us a challenge to verify that we have the private corresponding to a user's public key.

A private key is pair of numbers (a,b) and the way a public key is computed is applying the group operation (U x') a times, and then applying the group operation (L y') b times.
Thus public key for a given private key is

a * (U x') + b * (L y')

## Bruteforcing all keys

From the Wikipedia article of the Rubik cube group the order of the group operations (U x') and (L y') have order 1260, thus there exists only 1260*1260 = 1587600 different keys pairs.
So we can make the server compute every possible private/public key using simple bruteforce.

```python
from pwn import *
import pickle

r = remote("rubik.ctfcompetition.com", 1337)

them_keys = {}
for a in range(1260):
    r = remote("rubik.ctfcompetition.com", 1337)

    # ask for all public keys corresponting to every possible b for each fixed a
    for b in range(1260):
        r.sendline("1")
        r.sendline(str(a))
        r.sendline(str(b))

    # receive the public keys
    for b in range(1260):
        r.recvuntil("==\n")
        cube = r.recvline().strip()
        them_keys[cube] = (a,b)

    r.close()

    print a, len(them_keys)

# dump all the keys to the file "them_keys"
with open("them_keys", "w") as f:
    pickle.dump(them_keys, f)
```

So we now have a lookup table of all the private key for every possible public key.

## Logging in

When trying to login using menu option 2 we are presented with the following challenge

```text
My public key is:
WOOBWGWWOBYGRRBYYGWYRYGWORGRBBOORGGGRWOBBYRWOYBWOYRYGB

Please give me the result of:
mykey.handshake(yourkey, "882af203cb894828".from_hex().unwrap()).to_hex()
```

Thus if we choose a solved rubik cube as our public key, we can simply apply the handshake function of the server's publickey to get a valid response to the challenge.

Now lets consider what the handshake function does:

```rust
pub fn handshake(&self, key: PublicKey, salt: &[u8]) -> [u8; 16] {
    let pa = Permutation::parse("U x'").unwrap();
    let pb = Permutation::parse("L y'").unwrap();
    let cube = Cube::default().apply(self.a * pa + key.key + self.b * pb);
    let mut out = [0; 16];
    Blake2b::blake2b(&mut out, &cube.serialize().as_bytes(), salt);
    out
}
```

So in our case, with a solve rubik cube as a public key, we see that we must simply responde with a hash of the servers public key.

Now we can log in as a user using the following script:

```python
from pwn import *
from pyblake2 import blake2b

r = remote("rubik.ctfcompetition.com", 1337)

# create a user with a solved Rubik's cube as publickey
r.sendline("2")
r.sendline("hackerman")
r.sendline("WWWWWWWWWGGGRRRBBBOOOGGGRRRBBBOOOGGGRRRBBBOOOYYYYYYYYY")

# login as that user
r.sendline("3")
r.sendline("hackerman")
r.recvuntil("key is:\n")
server_pub = r.recvline().strip()
r.recvuntil("mykey.handshake(yourkey, \"")
salt = r.recvn(16)
r.recvline()
hsh = blake2b(server_pub, key=salt.decode("hex"), digest_size=16).digest()
r.sendline(hsh.encode("hex"))

r.interactive()
```

And this gives us access to the following menu:

```text
You have the following options:
1) Public key service
2) Register
3) Login
4) List users
q) Quit
```

## Logging in as admin

So we are now able to list which users already exists. So lets do that:

```text
List of registered users:
Username: hackerman
Key: WWWWWWWWWGGGRRRBBBOOOGGGRRRBBBOOOGGGRRRBBBOOOYYYYYYYYY

Username: admin
Key: GBBRBWRWBWBBWBRYROWYRGOGYWYRRBOYOYGWGWYBOYOOROGORGYGWG
```

Woo! So there is a admin user and we know his public key, so we can simply find his private key using our lookup table:

```text
Traceback (most recent call last):
  File "doit.py", line 27, in <module>
    print them_keys[admin_public_key]
KeyError: 'GBBRBWRWBWBBWBRYROWYRGOGYWYRRBOYOYGWGWYBOYOOROGORGYGWG'
```

This is very odd, as our lookup table contains every possible key pair. So we can conclude that the admin must have a public key which does not correspond to any private key.

So we need a different approach we need to know the servers private key to calcualte the shared secret

1. Find a sequence of moves which solve the admins public key, call this sequence M
2. Look up the server private key, and call this (a, b)
3. Calcucate: a * (U x') + M' + b * (L y')

```python
from rubik.cube import Cube
from rubik.solve import Solver

admin_cube = Cube(admin_public_key)
admin_solver = Solver(admin_cube)
admin_solver.solve()

admin_moves = []
for move in admin_solver.moves[::-1]:
    admin_moves += [move]*3 # invert every move

a, b = them_keys[server_public_key]

moves = ["U", "Xi"]*a + admin_moves + ["L", "Yi"]*b

# apply operations on a solved cube.
win_cube = Cube("WWWWWWWWWGGGRRRBBBOOOGGGRRRBBBOOOGGGRRRBBBOOOYYYYYYYYY")
for move in moves: getattr(win_cube, move)()

# hash
winning = str(win_cube).replace(" ", "").replace("\n", "")
hsh = blake2b(winning, key=salt.decode("hex"), digest_size=16).digest()

r.sendline(hsh.encode("hex"))

r.interactive()
```

This only works 1 in 24 times because the solver libary we found does not preserve the orientation of the cube.

So we just run our script until we get the flag:

```text
Your are now logged in!
Here is the flag: CTF{StickelsKeyExchangeByHand}
```

## References

- [Stickel's key exchange protocol](https://en.wikipedia.org/wiki/Non-commutative_cryptography#Stickel.E2.80.99s_key_exchange_protocol)
- [Rubik's cube group](https://en.wikipedia.org/wiki/Rubik%27s_Cube_group)
- [https://github.com/pglass/cube](https://github.com/pglass/cube)
