# [CBC-MAC Message Forgery](http://cryptopals.com/sets/7/challenges/49/)
Let's talk about CBC-MAC.

CBC-MAC is like this:

1. Take the plaintext P.
2. Encrypt P under CBC with key K, yielding ciphertext C.
3. Chuck all of C but the last block C[n].
4. C[n] is the MAC.

Suppose there's an online banking application, and it carries out user requests by talking to an API server over the network. Each request looks like this:
```
message || IV || MAC
```
The message looks like this:
```
from=#{from_id}&to=#{to_id}&amount=#{amount}
```
Now, write an API server and a web frontend for it. (NOTE: No need to get ambitious and write actual servers and web apps. Totally fine to go lo-fi on this one.) The client and server should share a secret key K to sign and verify messages.

The API server should accept messages, verify signatures, and carry out each transaction if the MAC is valid. It's also publicly exposed - the attacker can submit messages freely assuming he can forge the right MAC.

The web client should allow the attacker to generate valid messages for accounts he controls. (Feel free to sanitize params if you're feeling anal-retentive.) Assume the attacker is in a position to capture and inspect messages from the client to the API server.

One thing we haven't discussed is the IV. Assume the client generates a per-message IV and sends it along with the MAC. That's how CBC works, right?

Wrong.

For messages signed under CBC-MAC, an attacker-controlled IV is a liability. Why? Because it yields full control over the first block of the message.

Use this fact to generate a message transferring 1M spacebucks from a target victim's account into your account.

I'll wait. Just let me know when you're done.

... waiting

... waiting

... waiting

All done? Great - I knew you could do it!

Now let's tune up that protocol a little bit.

As we now know, you're supposed to use a fixed IV with CBC-MAC, so let's do that. We'll set ours at 0 for simplicity. This means the IV comes out of the protocol:
```
message || MAC
```
Pretty simple, but we'll also adjust the message. For the purposes of efficiency, the bank wants to be able to process multiple transactions in a single request. So the message now looks like this:
```
from=#{from_id}&tx_list=#{transactions}
```
With the transaction list formatted like:
```
to:amount(;to:amount)*
```
There's still a weakness here: the MAC is vulnerable to length extension attacks. How?

Well, the output of CBC-MAC is a valid IV for a new message.

*"But we don't control the IV anymore!"*

With sufficient mastery of CBC, we can fake it.

Your mission: capture a valid message from your target user. Use length extension to add a transaction paying the attacker's account 1M spacebucks.

Hint! |
----- |
This would be a lot easier if you had full control over the first block of your message, huh? Maybe you can simulate that. |

Food for thought: *How would you modify the protocol to prevent this?*