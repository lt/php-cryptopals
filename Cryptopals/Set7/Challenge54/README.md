# [Kelsey and Kohno's Nostradamus Attack](http://cryptopals.com/sets/7/challenges/54/)
Hash functions are sometimes used as proof of a secret prediction.

For example, suppose you wanted to predict the score of every Major League Baseball game in a season. (2,430 in all.) You might be concerned that publishing your predictions would affect the outcomes.

So instead you write down all the scores, hash the document, and publish the hash. Once the season is over, you publish the document. Everyone can then hash the document to verify your soothsaying prowess.

But what if you can't accurately predict the scores of 2.4k baseball games? Have no fear - forging a prediction under this scheme reduces to another second preimage attack.

We could apply the long message attack from the previous problem, but it would look pretty shady. Would you trust someone whose predicted message turned out to be 2^50 bytes long?

It turns out we can run a successful attack with a much shorter suffix. Check the method:

1. Generate a large number of initial hash states. Say, 2^k.
2. Pair them up and generate single-block collisions. Now you have 2^k hash states that collide into 2^(k-1) states.
3. Repeat the process. Pair up the 2^(k-1) states and generate collisions. Now you have 2^(k-2) states.
4. Keep doing this until you have one state. This is your prediction.
5. Well, sort of. You need to commit to some length to encode in the padding. Make sure it's long enough to accommodate your actual message, this suffix, and a little bit of glue to join them up. Hash this padding block using the state from step 4 - THIS is your prediction.

What did you just build? It's basically a funnel mapping many initial states into a common final state. What's critical is we now have a big field of 2^k states we can try to collide into, but the actual suffix will only be k+1 blocks long.

The rest is trivial:

1. Wait for the end of the baseball season. (This may take some time.)
2. Write down the game results. Or, you know, anything else. I'm not too particular.
3. Generate enough glue blocks to get your message length right. The last block should collide into one of the leaves in your tree.
4. Follow the path from the leaf all the way up to the root node and build your suffix using the message blocks along the way.

The difficulty here will be around 2^(b-k). By increasing or decreasing k in the tree generation phase, you can tune the difficulty of this step. It probably makes sense to do more work up-front, since people will be waiting on you to supply your message once the event passes. Happy prognosticating!