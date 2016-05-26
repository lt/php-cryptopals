<?php declare(strict_types = 1);

/*
 * n = 17
 * pt = 6
 *
 * 6 * 2 % 17 = 12 -> bit = 0 -> upper = 17 - 9 = 8
 * 12 * 2 % 17 = 7 -> bit = 1 -> lower = 0 + 4 = 4
 * 7 * 2 % 17 = 14 -> bit = 0 -> upper = 8 - 2 = 6
 * 14 * 2 % 17 = 11 -> bit = 1 -> lower = 4 + 1 = 5
 * 11 * 2 % 17 = 5 -> bit = 1 -> lower = 5 + 1 = 6
 *
 */

namespace Cryptopals\Set6\Challenge46;

use Cryptopals\Solution;

class Solution46 implements Solution
{
    protected $parityOracle;
    
    function __construct(ParityOracle $parityOracle)
    {
        $this->parityOracle = $parityOracle;
    }

    function execute(): bool
    {
        list($e, $n) = $this->parityOracle->publicKey();
        $ciphertext = $this->parityOracle->ciphertext();
        
        $double = gmp_powm(2, $e, $n) ;
        $multiplier = gmp_init(1);

        for ($i = 1; $i <= 1024; $i++) {
            $ciphertext = ($ciphertext * $double) % $n;
            $multiplier <<= 1;

            if (!$this->parityOracle->oracle($ciphertext)) {
                $multiplier--;
            }

            $recovered = ($multiplier * $n) >> $i;
            print gmp_export($recovered) . "\n";
        }

        return true;
    }
}
