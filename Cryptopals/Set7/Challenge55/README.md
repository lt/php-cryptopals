# [MD4 Collisions](http://cryptopals.com/sets/7/challenges/55/)
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