<?php declare(strict_types = 1);

namespace Cryptopals\Set6\Challenge44;

use Cryptopals\Set6\Challenge43\DSA;
use Cryptopals\Solution;

class Solution44 implements Solution
{
    protected $dsa;

    function __construct(DSA $dsa)
    {
        $this->dsa = $dsa;
    }

    function execute(): bool
    {
        $privKeyHash = hex2bin('ca8f6f7c66fa362d40760d135b763eb8527d3d52');

        preg_match_all('~msg: ([^\n]+)\ns: ([^\n]+)\nr: ([^\n]+)\nm: ([^\n]+)\n~m', file_get_contents(__DIR__ . '/44.txt'), $matches, PREG_SET_ORDER);

        $messageCount = count($matches);
        for ($i = 0; $i < $messageCount - 1; $i++) {
            for ($j = $i + 1; $j < $messageCount; $j++) {
                $s1 = gmp_init($matches[$i][2]);
                $s2 = gmp_init($matches[$j][2]);
                $r1 = gmp_init($matches[$i][3]);
                $r2 = gmp_init($matches[$j][3]);
                $m1 = gmp_init($matches[$i][4], 16);
                $m2 = gmp_init($matches[$j][4], 16);

/*
         (m1 - m2)
     k = --------- mod q
         (s1 - s2)

Divide by (s1 - s2) % q === Multiply by invmod(s1 - s2, q)
*/
                $k = (gmp_invert($s1 - $s2, $this->dsa->q) * ($m1 - $m2)) % $this->dsa->q;
                // Same as challenge 43
                $private1 = (gmp_invert($r1, $this->dsa->q) * ($k * $s1 - $m1)) % $this->dsa->q;
                $private2 = (gmp_invert($r2, $this->dsa->q) * ($k * $s2 - $m2)) % $this->dsa->q;

                if ($private1 == $private2) {
                    $private1Str = bin2hex(gmp_export($private1));
                    $private2Str = bin2hex(gmp_export($private2));

                    if (sha1($private1Str, true) === $privKeyHash && sha1($private2Str, true) === $privKeyHash) {
                        print "Message pair: {$i} and {$j}\n";
                        print "Private key: 0x{$private1Str}\n";
                        print 'Sub-key: 0x' . bin2hex(gmp_export($k)) . "\n";
                    }
                }
            }
        }

        return true;
    }
}
