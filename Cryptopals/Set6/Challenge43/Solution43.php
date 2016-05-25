<?php declare(strict_types = 1);

namespace Cryptopals\Set6\Challenge43;

use Cryptopals\Solution;

class Solution43 implements Solution
{
    protected $dsa;
    
    function __construct(DSA $dsa)
    {
        $this->dsa = $dsa;
    }

    function execute(): bool
    {
        $message = "For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n";

        $expectedHash = hex2bin('d2d0714f014a9784047eaeccf956520045c45265');
        $actualHash = sha1($message, true);

        if ($expectedHash !== $actualHash) {
            print "Bad hash\n";
            return false;
        }
        print "Hash match.\n";

        $y = gmp_init('0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17');
        $r = gmp_init('548099063082341131477253921760299949438196259240');
        $s = gmp_init('857042759984254168557880549501802188789837994940');
        $signature = [$r, $s];

        if (!$this->dsa->verify($message, $signature, $y)) {
            print "Signature does not verify\n";
            return false;
        }
        print "Signature verifies.\n";

        $h = gmp_import($actualHash);
        $privKeyHash = hex2bin('0954edd5e0afe5542a4adf012611a91912a3ec16');

        for ($subKey = 0; $subKey < 65535; $subKey++) {
/*
              (s * k) - H(msg)
          x = ----------------  mod q
                      r

Divide by r % q === Multiply by invmod(r, q)
 */
            $privateKey = (gmp_invert($r, $this->dsa->q) * ($subKey * $s - $h)) % $this->dsa->q;
            $privKeyStr = bin2hex(gmp_export($privateKey));
            // Check $y is the public key associated with $privateKey, and hashes match
            if (gmp_powm($this->dsa->g, $privateKey, $this->dsa->p) == $y && sha1($privKeyStr, true) === $privKeyHash) {
                print "Private key: 0x{$privKeyStr}\n";
                print 'Sub-key: 0x' . dechex($subKey) . "\n";
                return true;
            }
        }

        return false;
    }
}
