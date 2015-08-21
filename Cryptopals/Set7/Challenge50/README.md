# [Hashing with CBC-MAC](http://cryptopals.com/sets/7/challenges/50/)
Sometimes people try to use CBC-MAC as a hash function.

This is a bad idea. Matt Green explains:

> To make a long story short: cryptographic hash functions are public functions (i.e., no secret key) that have the property of collision-resistance (it's hard to find two messages with the same hash). MACs are keyed functions that (typically) provide message unforgeability -- a very different property. Moreover, they guarantee this only when the key is secret.
Let's try a simple exercise.

Hash functions are often used for code verification. This snippet of JavaScript (with newline):
```
alert('MZA who was that?');
```
Hashes to *296b8d7cb78a243dda4d0a61d33bbdd1* under CBC-MAC with a key of *"YELLOW SUBMARINE"* and a 0 IV.

Forge a valid snippet of JavaScript that alerts "Ayo, the Wu is back!" and hashes to the same value. Ensure that it runs in a browser.

Extra Credit |
------------ |
Write JavaScript code that downloads your file, checks its CBC-MAC, and inserts it into the DOM iff it matches the expected hash. |