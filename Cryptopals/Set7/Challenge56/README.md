# [RC4 Single-Byte Biases](http://cryptopals.com/sets/7/challenges/56/)
RC4 is popular stream cipher notable for its usage in protocols like TLS, WPA, RDP, &c.

It's also susceptible to significant single-byte biases, especially early in the keystream. What does this mean?

Simply: for a given position in the keystream, certain bytes are more (or less) likely to pop up than others. Given enough encryptions of a given plaintext, an attacker can use these biases to recover the entire plaintext.

Now, search online for ["On the Security of RC4 in TLS and WPA".](http://lmgtfy.com/?q=On+the+Security+of+RC4+in+TLS+and+WPA) This site is your one-stop shop for RC4 information.

Click through to "RC4 biases" on the right.

These are graphs of each single-byte bias (one per page). Notice in particular the monster spikes on z16, z32, z48, etc. (Note: these are one-indexed, so z16 = keystream[15].)

How useful are these biases?

Click through to the research paper and scroll down to the simulation results. (Incidentally, the whole paper is a good read if you have some spare time.) We start out with clear spikes at 2^26 iterations, but our chances for recovering each of the first 256 bytes approaches 1 as we get up towards 2^32.

There are two ways to take advantage of these biases. The first method is really simple:

1. Gain exhaustive knowledge of the keystream biases.
2. Encrypt the unknown plaintext 2^30+ times under different keys.
3. Compare the ciphertext biases against the keystream biases.

Doing this requires deep knowledge of the biases for each byte of the keystream. But it turns out we can do pretty well with just a few useful biases - if we have some control over the plaintext.

How? By using knowledge of a single bias as a peephole into the plaintext.

Decode this secret:
```
QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F
```
And call it a cookie. No peeking!

Now use it to build this encryption oracle:
```
RC4(your-request || cookie, random-key)
```
Use a fresh 128-bit key on every invocation.

Picture this scenario: you want to steal a user's secure cookie. You can spawn arbitrary requests (from a malicious plugin or somesuch) and monitor network traffic. (Ok, this is unrealistic - the cookie wouldn't be right at the beginning of the request like that - this is just an example!)

You can control the position of the cookie by requesting "/", "/A", "/AA", and so on.

Build bias maps for a couple chosen indices (z16 and z32 are good) and decrypt the cookie.

MD4 is a 128-bit cryptographic hash function, meaning it should take a work factor of roughly 2^64 to find collisions.

It turns out we can do much better.

The paper ["Cryptanalysis of the Hash Functions MD4 and RIPEMD"](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=1&ved=0CCAQFjAA&url=http%3A%2F%2Fwww.infosec.sdu.edu.cn%2Fuploadfile%2Fpapers%2FCryptanalysis%2520of%2520the%2520Hash%2520Functions%2520MD4%2520and%2520RIPEMD.pdf&ei=kb8IVPGQNajksATw1YLoCA&usg=AFQjCNHSIOZ1uUKTO3N5Hi33D3ZeoOyTUg&sig2=-C-5Woy1HJtk7KJJwLLp-A&bvm=bv.74649129,d.cWc) by Wang et al details a cryptanalytic attack that lets us find collisions in 2^8 or less.

Given a message block M, Wang outlines a strategy for finding a sister message block M', differing only in a few bits, that will collide with it. Just so long as a short set of conditions holds true for M.

What sort of conditions? Simple bitwise equalities within the intermediate hash function state, e.g. a[1][6] = b[0][6]. This should be read as: "the sixth bit (zero-indexed) of a[1] (i.e. the first update to 'a') should equal the sixth bit of b[0] (i.e. the initial value of 'b')".

It turns out that a lot of these conditions are trivial to enforce. To see why, take a look at the first (of three) rounds in the MD4 compression function. In this round, we iterate over each word in the message block sequentially and mix it into the state. So we can make sure all our first-round conditions hold by doing this:
```
# calculate the new value for a[1] in the normal fashion
a[1] = (a[0] + f(b[0], c[0], d[0]) + m[0]).lrot(3)

# correct the erroneous bit
a[1] ^= ((a[1][6] ^ b[0][6]) << 6)

# use algebra to correct the first message block
m[0] = a[1].rrot(3) - a[0] - f(b[0], c[0], d[0])
```
Simply ensuring all the first round conditions puts us well within the range to generate collisions, but we can do better by correcting some additional conditions in the second round. This is a bit trickier, as we need to take care not to stomp on any of the first-round conditions.

Once you've adequately massaged M, you can simply generate M' by flipping a few bits and test for a collision. A collision is not guaranteed as we didn't ensure every condition. But hopefully we got enough that we can find a suitable (M, M') pair without too much effort.

Implement Wang's attack.