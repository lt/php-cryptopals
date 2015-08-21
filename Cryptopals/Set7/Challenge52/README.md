# [Iterated Hash Function Multicollisions](http://cryptopals.com/sets/7/challenges/52/)
While we're on the topic of hash functions...

The major feature you want in your hash function is collision-resistance. That is, it should be hard to generate collisions, and it should be *really* hard to generate a collision for a given hash (*aka* preimage).

Iterated hash functions have a problem: the effort to generate *lots* of collisions scales sublinearly.

What's an iterated hash function? For all intents and purposes, we're talking about the Merkle-Damgard construction. It looks like this:
```
function MD(M, H, C):
  for M[i] in pad(M):
    H := C(M[i], H)
  return H
```
For message M, initial state H, and compression function C.

This should look really familiar, because SHA-1 and MD4 are both in this category. What's cool is you can use this formula to build a makeshift hash function out of some spare crypto primitives you have lying around (e.g. C = AES-128).

Back on task: the cost of collisions scales sublinearly. What does that mean? If it's feasible to find one collision, it's probably feasible to find a lot.

How? For a given state H, find two blocks that collide. Now take the resulting hash from this collision as your new H and repeat. Recognize that with each iteration you can actually double your collisions by subbing in either of the two blocks for that slot.

This means that if finding two colliding messages takes 2^(b/2) work (where b is the bit-size of the hash function), then finding 2^n colliding messages only takes n*2^(b/2) work.

Let's test it. First, build your own MD hash function. We're going to be generating a LOT of collisions, so don't knock yourself out. In fact, go out of your way to make it bad. Here's one way:

1. Take a fast block cipher and use it as C.
2. Make H pretty small. I won't look down on you if it's only 16 bits. Pick some initial H.
3. H is going to be the input key and the output block from C. That means you'll need to pad it on the way in and drop bits on the way out.

Now write the function f(n) that will generate 2^n collisions in this hash function.

Why does this matter? Well, one reason is that people have tried to strengthen hash functions by cascading them together. Here's what I mean:

1. Take hash functions f and g.
2. Build h such that h(x) = f(x) || g(x).

The idea is that if collisions in f cost 2^(b1/2) and collisions in g cost 2^(b2/2), collisions in h should come to the princely sum of 2^((b1+b2)/2).

But now we know that's not true!

Here's the idea:

1. Pick the "cheaper" hash function. Suppose it's f.
2. Generate 2^(b2/2) colliding messages in f.
3. There's a good chance your message pool has a collision in g.
4. Find it.

And if it doesn't, keep generating cheap collisions until you find it.

Prove this out by building a more expensive (but not *too* expensive) hash function to pair with the one you just used. Find a pair of messages that collide under both functions. Measure the total number of calls to the collision function.