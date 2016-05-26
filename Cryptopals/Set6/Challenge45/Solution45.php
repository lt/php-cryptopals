<?php declare(strict_types = 1);

namespace Cryptopals\Set6\Challenge45;

use Cryptopals\Solution;

class Solution45 implements Solution
{
    protected $dsa;

    function __construct(WeakDSA $dsa)
    {
        $this->dsa = $dsa;
    }

    function execute(): bool
    {
        $message1 = 'Hello, world';
        $message2 = 'Goodbye, world';

        $publicKey = gmp_init('0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17');
        $privateKey = gmp_init('0xf1b733db159c66bce071d21e044a48b0e4c1665a');
        $subKey = gmp_init('0x51ffac4835ccfda57356a86ebd57fbf9');

        $this->dsa->g = 0;
        $signature1 = $this->dsa->sign($message1, $privateKey, $subKey);
        $signature2 = $this->dsa->sign($message2, $privateKey, $subKey);

        print "g=0\n";
        print "Signing m1: '{$message1}':\n";
        print "  r: {$signature1[0]}\n";
        print "  s: {$signature1[1]}\n";
        print "Signing m2: '{$message2}':\n";
        print "  r: {$signature2[0]}\n";
        print "  s: {$signature2[1]}\n\n";

        print 'Verifying m1 with s2: ' . ($this->dsa->verify($message1, $signature2, $publicKey) ? "OK\n" : "FAIL\n");
        print 'Verifying m2 with s1: ' . ($this->dsa->verify($message1, $signature2, $publicKey) ? "OK\n\n" : "FAIL\n\n");

        $this->dsa->g = $this->dsa->p + 1;
        $signature1 = $this->dsa->sign($message1, $privateKey, $subKey);
        $signature2 = $this->dsa->sign($message2, $privateKey, $subKey);
        print "g=p+1\n";
        print "Signing '{$message1}':\n";
        print "  r: {$signature1[0]}\n";
        print "  s: {$signature1[1]}\n";
        print "Signing '{$message2}':\n";
        print "  r: {$signature2[0]}\n";
        print "  s: {$signature2[1]}\n\n";

        print 'Verifying m1 with s2: ' . ($this->dsa->verify($message1, $signature2, $publicKey) ? "OK\n" : "FAIL\n");
        print 'Verifying m2 with s1: ' . ($this->dsa->verify($message1, $signature2, $publicKey) ? "OK\n\n" : "FAIL\n\n");

        for ($z = 2; $z < 16; $z <<= 1) {
            $r = gmp_powm($publicKey, $z, $this->dsa->p) % $this->dsa->q;
            $s = ($r * gmp_invert($z, $this->dsa->q)) % $this->dsa->q;

            $magicSig = [$r, $s];

            print "Magic signature (z = {$z}):\n";
            print "  r: {$r}\n";
            print "  s: {$s}\n";
            print "Verifying m1 with magic: " . ($this->dsa->verify($message1, $magicSig, $publicKey) ? "OK\n" : "FAIL\n");
            print "Verifying m2 with magic: " . ($this->dsa->verify($message1, $magicSig, $publicKey) ? "OK\n\n" : "FAIL\n\n");
        }

        return true;
    }
}
