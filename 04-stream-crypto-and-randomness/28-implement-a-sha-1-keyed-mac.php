<?php

/*
 * http://cryptopals.com/sets/4/challenges/28/
 *
 * Implement a SHA-1 keyed MAC
 *
 * Find a SHA-1 implementation in the language you code in.
 *
 * Don't cheat. It won't work.
 * Do not use the SHA-1 implementation your language already provides (for instance, don't use the "Digest" library in Ruby, or call OpenSSL; in Ruby, you'd want a pure-Ruby SHA-1).
 *
 * Write a function to authenticate a message under a secret key by using a secret-prefix MAC, which is simply:
 * SHA1(key || message)
 *
 * Verify that you cannot tamper with the message without breaking the MAC you've produced, and that you can't produce a new MAC without knowing the secret key.
 */

if (PHP_INT_SIZE < 8) {
    throw new Exception('64 bit PHP required!');
}

// ported from C code from http://www.packetizer.com/security/sha1/

class SHA1Context
{
    public $messageDigest = [
        0x67452301,
        0xefcdab89,
        0x98badcfe,
        0x10325476,
        0xc3d2e1f0
    ];

    public $lengthLow = 0;
    public $lengthHigh = 0;

    public $messageBlock = [];
    public $messageBlockIndex = 0;

    public $computed = 0;
    public $corrupted = 0;
}

class SHA1
{
    function circularShift($bits, $word)
    {
        return (($word << $bits) & 0xffffffff) | ($word >> (32 - $bits));
    }

    function reset(SHA1Context $context)
    {
        $context->lengthLow = 0;
        $context->lengthHigh = 0;
        $context->messageBlockIndex = 0;

        $context->messageDigest = [
            0x67452301,
            0xefcdab89,
            0x98badcfe,
            0x10325476,
            0xc3d2e1f0
        ];

        $context->computed = 0;
        $context->corrupted = 0;
    }

    function result(SHA1Context $context)
    {
        if ($context->corrupted) {
            return 0;
        }

        if (!$context->computed) {
            $this->pad($context);
            $context->computed = 1;
        }

        return 1;
    }

    function input(SHA1Context $context, array $message)
    {
        if (!$message) {
            return;
        }

        if ($context->computed || $context->corrupted) {
            $context->corrupted = 1;
            return;
        }

        foreach ($message as $octet) {
            $context->messageBlock[$context->messageBlockIndex++] = $octet & 0xff;

            $context->lengthLow += 8;
            $context->lengthLow &= 0xffffffff;

            if ($context->lengthLow === 0) {
                $context->lengthHigh++;
                $context->lengthHigh &= 0xffffffff;

                if ($context->lengthHigh === 0) {
                    $context->corrupted = 1;
                }
            }

            if ($context->messageBlockIndex === 64) {
                $this->processMessageBlock($context);
            }
        }
    }

    function processMessageBlock($context)
    {
        $K = [
            0x5a827999,
            0x6ed9eba1,
            0x8f1bbcdc,
            0xca62c1d6
        ];

        $W = [];

        for ($t = 0; $t < 16; $t++) {
            $i = $t << 2;
            $W[$t]  = $context->messageBlock[$i] << 24;
            $W[$t] |= $context->messageBlock[$i + 1] << 16;
            $W[$t] |= $context->messageBlock[$i + 2] << 8;
            $W[$t] = ($W[$t] | $context->messageBlock[$i + 3]);
        }

        for (; $t < 80; $t++) {
            $W[$t] = $this->circularShift(1, $W[$t-3] ^ $W[$t-8] ^ $W[$t-14] ^ $W[$t-16]);
        }

        $A = $context->messageDigest[0];
        $B = $context->messageDigest[1];
        $C = $context->messageDigest[2];
        $D = $context->messageDigest[3];
        $E = $context->messageDigest[4];

        for($t = 0; $t < 20; $t++) {
            $temp = $this->circularShift(5, $A) +
                (($B & $C) | ((~$B) & $D)) + $E + $W[$t] + $K[0];
            $temp &= 0xffffffff;
            $E = $D;
            $D = $C;
            $C = $this->circularShift(30, $B);
            $B = $A;
            $A = $temp;
        }

        for(; $t < 40; $t++)
        {
            $temp = $this->circularShift(5, $A) +
                ($B ^ $C ^ $D) + $E + $W[$t] + $K[1];
            $temp &= 0xffffffff;
            $E = $D;
            $D = $C;
            $C = $this->circularShift(30, $B);
            $B = $A;
            $A = $temp;
        }

        for(; $t < 60; $t++)
        {
            $temp = $this->circularShift(5, $A) +
                (($B & $C) | ($B & $D) | ($C & $D)) + $E + $W[$t] + $K[2];
            $temp &= 0xffffffff;
            $E = $D;
            $D = $C;
            $C = $this->circularShift(30, $B);
            $B = $A;
            $A = $temp;
        }

        for(; $t < 80; $t++)
        {
            $temp = $this->circularShift(5, $A) +
                ($B ^ $C ^ $D) + $E + $W[$t] + $K[3];
            $temp &= 0xffffffff;
            $E = $D;
            $D = $C;
            $C = $this->circularShift(30, $B);
            $B = $A;
            $A = $temp;
        }

        $context->messageDigest = [
            ($context->messageDigest[0] + $A) & 0xffffffff,
            ($context->messageDigest[1] + $B) & 0xffffffff,
            ($context->messageDigest[2] + $C) & 0xffffffff,
            ($context->messageDigest[3] + $D) & 0xffffffff,
            ($context->messageDigest[4] + $E) & 0xffffffff
        ];

        $context->messageBlockIndex = 0;
    }

    function pad(SHA1Context $context)
    {
        $context->messageBlock[$context->messageBlockIndex++] = 0x80;

        if ($context->messageBlockIndex > 55) {
            while ($context->messageBlockIndex < 64) {
                $context->messageBlock[$context->messageBlockIndex++] = 0;
            }
            $this->processMessageBlock($context);
        }
        while ($context->messageBlockIndex < 56)
        {
            $context->messageBlock[$context->messageBlockIndex++] = 0;
        }

        $context->messageBlock[56] = ($context->lengthHigh >> 24) & 0xff;
        $context->messageBlock[57] = ($context->lengthHigh >> 16) & 0xff;
        $context->messageBlock[58] = ($context->lengthHigh >> 8) & 0xff;
        $context->messageBlock[59] = ($context->lengthHigh) & 0xff;
        $context->messageBlock[60] = ($context->lengthLow >> 24) & 0xff;
        $context->messageBlock[61] = ($context->lengthLow >> 16) & 0xff;
        $context->messageBlock[62] = ($context->lengthLow >> 8) & 0xff;
        $context->messageBlock[63] = ($context->lengthLow) & 0xff;

        $this->processMessageBlock($context);
    }
}

function sha1KeyedMAC($key, $message)
{
    $c = new SHA1Context();

    $s = new SHA1();
    $s->reset($c);
    $s->input($c, array_map('ord', str_split($key . $message)));
    $s->result($c);

    return pack('N5', $c->messageDigest[0], $c->messageDigest[1], $c->messageDigest[2], $c->messageDigest[3], $c->messageDigest[4]);
}

if (!debug_backtrace()) {
    print "Expected: A9993E364706816ABA3E25717850C26C9CD0D89D\n";
    print "Homebrew: " . bin2hex(sha1KeyedMAC('', 'abc')) . "\n";

    print "Expected: 84983E441C3BD26EBAAE4AA1F95129E5E54670F1\n";
    print "Homebrew: " . bin2hex(sha1KeyedMAC('', 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')) . "\n";

    print "Expected: 34AA973CD4C4DAA4F61EEB2BDBAD27316534016F\n";
    print "Homebrew: " . bin2hex(sha1KeyedMAC('', str_repeat('a', 1000000))) . "\n";

}