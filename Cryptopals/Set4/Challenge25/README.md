# [Break "random access read/write" AES CTR](http://cryptopals.com/sets/4/challenges/25/)
Back to CTR. Encrypt the recovered plaintext from [this file](25.txt) (the ECB exercise) under CTR with a random key (for this exercise the key should be unknown to you, but hold on to it).

Now, write the code that allows you to "seek" into the ciphertext, decrypt, and re-encrypt with different plaintext. Expose this as a function, like, *"edit(ciphertext, key, offet, newtext)"*.

Imagine the "edit" function was exposed to attackers by means of an API call that didn't reveal the key or the original plaintext; the attacker has the ciphertext and controls the offset and "new text".

Recover the original plaintext.

Food for thought.
A folkloric supposed benefit of CTR mode is the ability to easily "seek forward" into the ciphertext; to access byte N of the ciphertext, all you need to be able to do is generate byte N of the keystream. Imagine if you'd relied on that advice to, say, encrypt a disk.