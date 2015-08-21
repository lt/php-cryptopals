# [Compression Ratio Side-Channel Attacks](http://cryptopals.com/sets/7/challenges/51/)
Internet traffic is often compressed to save bandwidth. Until recently, this included HTTPS headers, and it still includes the contents of responses.

Why does that matter?

Well, if you're an attacker with:

1. Partial plaintext knowledge *and*
2. Partial plaintext control *and*
3. Access to a compression oracle

You've got a pretty good chance to recover any additional unknown plaintext.

What's a compression oracle? You give it some input and it tells you how well the full message compresses, i.e. the length of the resultant output.

This is somewhat similar to the timing attacks we did way back in set 4 in that we're taking advantage of incidental side channels rather than attacking the cryptographic mechanisms themselves.

Scenario: you are running a MITM attack with an eye towards stealing secure session cookies. You've injected malicious content allowing you to spawn arbitrary requests and observe them in flight. (The particulars aren't terribly important, just roll with it.)

So! Write this oracle:
```
oracle(P) -> length(encrypt(compress(format_request(P))))
```
Format the request like this:
```
POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=
Content-Length: ((len(P)))
((P))
```
(Pretend you can't see that session id. You're the attacker.)

Compress using zlib or whatever.

Encryption... is actually kind of irrelevant for our purposes, but be a sport. Just use some stream cipher. Dealer's choice. Random key/IV on every call to the oracle.

And then just return the length in bytes.

Now, the idea here is to leak information using the compression library. A payload of "sessionid=T" should compress just a little bit better than, say, "sessionid=S".

There is one complicating factor. The DEFLATE algorithm operates in terms of individual bits, but the final message length will be in bytes. Even if you do find a better compression, the difference may not cross a byte boundary. So that's a problem.

You may also get some incidental false positives.

But don't worry! I have full confidence in you.

Use the compression oracle to recover the session id.

I'll wait.

Got it? Great.

Now swap out your stream cipher for CBC and do it again.