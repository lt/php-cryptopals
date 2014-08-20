<?php

/*
 * http://cryptopals.com/sets/4/challenges/29/
 *
 * Break a SHA-1 keyed MAC using length extension
 *
 * Secret-prefix SHA-1 MACs are trivially breakable.
 *
 * The attack on secret-prefix SHA1 relies on the fact that you can take the ouput of SHA-1 and use it as a new starting point for SHA-1, thus taking an arbitrary SHA-1 hash and "feeding it more data".
 *
 * Since the key precedes the data in secret-prefix, any additional data you feed the SHA-1 hash in this fashion will appear to have been hashed with the secret key.
 *
 * To carry out the attack, you'll need to account for the fact that SHA-1 is "padded" with the bit-length of the message; your forged message will need to include that padding. We call this "glue padding". The final message you actually forge will be:
 * SHA1(key || original-message || glue-padding || new-message)
 *
 * (where the final padding on the whole constructed message is implied)
 *
 * Note that to generate the glue padding, you'll need to know the original bit length of the message; the message itself is known to the attacker, but the secret key isn't, so you'll need to guess at it.
 *
 * This sounds more complicated than it is in practice.
 *
 * To implement the attack, first write the function that computes the MD padding of an arbitrary message and verify that you're generating the same padding that your SHA-1 implementation is using. This should take you 5-10 minutes.
 *
 * Now, take the SHA-1 secret-prefix MAC of the message you want to forge --- this is just a SHA-1 hash --- and break it into 32 bit SHA-1 registers (SHA-1 calls them "a", "b", "c", &c).
 *
 * Modify your SHA-1 implementation so that callers can pass in new values for "a", "b", "c" &c (they normally start at magic numbers). With the registers "fixated", hash the additional data you want to forge.
 *
 * Using this attack, generate a secret-prefix MAC under a secret key (choose a random word from /usr/share/dict/words or something) of the string:
 * "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
 *
 * Forge a variant of this message that ends with ";admin=true".
 *
 * This is a very useful attack.
 * For instance: Thai Duong and Juliano Rizzo, who got to this attack before we did, used it to break the Flickr API.
 */

require_once '../utils/random-bytes.php';
require_once '28-implement-a-sha-1-keyed-mac.php';

class pretendAPI
{
    private $key;

    function __construct()
    {
        $this->key = getRandomBytes(rand(8, 32));
    }

    function sign($message)
    {
        return sha1KeyedMAC($this->key, $message);
    }

    function verify($message, $hash)
    {
        return $this->sign($message) === $hash;
    }
}

$api = new pretendAPI();
$message = 'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon';
$mac = $api->sign($message);

// attacker has access to message and mac, but not key

print "Message: $message\n";
print "Old MAC: " . bin2hex($mac) . "\n\n";

function getGlue($message, $offset = 0)
{
    $messageLen = strlen($message) + $offset;
    $padLen = 64 - ($messageLen % 64);

    if ($padLen < 9) {
        $padLen += 64;
    }

    return "\x80" . str_repeat("\0", $padLen - 5) . pack('N', $messageLen << 3);
}

$s = new SHA1();
$c = new SHA1Context();
$digest = array_values(unpack('N5', $mac));
$messageLen = strlen($message);
$suffix = ';admin=true';

$keyLen = 0;
while ($keyLen < 33) {
    $glue = getGlue($message, $keyLen);

    $s->reset($c);

    $c->messageDigest = $digest;
    $c->lengthLow = ($messageLen + $keyLen + strlen($glue)) << 3;

    $s->input($c, $suffix);
    $s->result($c);

    $newMac = pack('N5', $c->messageDigest[0], $c->messageDigest[1], $c->messageDigest[2], $c->messageDigest[3], $c->messageDigest[4]);

    if ($api->verify($message . $glue . $suffix, $newMac)) {
        print "Key len: $keyLen\n\n";
        print "Message: $message$glue$suffix\n";
        print "New MAC: " . bin2hex($newMac) . "\n\n";
        break;
    }

    $keyLen ++;
}


