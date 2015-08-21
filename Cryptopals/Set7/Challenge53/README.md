# [Kelsey and Schneier's Expandable Messages](http://cryptopals.com/sets/7/challenges/53/)
One of the basic yardsticks we use to judge a cryptographic hash function is its resistance to second preimage attacks. That means that if I give you x and y such that H(x) = y, you should have a tough time finding x' such that H(x') = H(x) = y.

How tough? Brute-force tough. For a 2^b hash function, we want second preimage attacks to cost 2^b operations.

This turns out not to be the case for very long messages.

Consider the problem we're trying to solve: we want to find a message that will collide with H(x) in the very last block. But there are a ton of intermediate blocks, each with its own intermediate hash state.

What if we could collide into one of those? We could then append all the following blocks from the original message to produce the original H(x). Almost.

We can't do this exactly because the padding will mess things up.

What we need are *expandable messages.*

In the last problem we used multicollisions to produce 2^n colliding messages for n\*2^(b/2) effort. We can use the same principles to produce a set of messages of length (k, k + 2^k - 1) for a given k.

Here's how:

* Starting from the hash function's initial state, find a collision between a single-block message and a message of 2^(k-1)+1 blocks. DO NOT hash the entire long message each time. Choose 2^(k-1) dummy blocks, hash those, then focus on the last block.
* Take the output state from the first step. Use this as your new initial state and find another collision between a single-block message and a message of 2^(k-2)+1 blocks.
* Repeat this process k total times. Your last collision should be between a single-block message and a message of 2^0+1 = 2 blocks.

Now you can make a message of any length in (k, k + 2^k - 1) blocks by choosing the appropriate message (short or long) from each pair.

Now we're ready to attack a long message M of 2^k blocks.

1. Generate an expandable message of length (k, k + 2^k - 1) using the strategy outlined above.
2. Hash M and generate a map of intermediate hash states to the block indices that they correspond to.
3. From your expandable message's final state, find a single-block "bridge" to intermediate state in your map. Note the index i it maps to.
4. Use your expandable message to generate a prefix of the right length such that *len(prefix || bridge || M[i..]) = len(M)*.

The padding in the final block should now be correct, and your forgery should hash to the same value as M.