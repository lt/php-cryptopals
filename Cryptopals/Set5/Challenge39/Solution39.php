<?php declare(strict_types = 1);

namespace Cryptopals\Set5\Challenge39;

use Cryptopals\Solution;

class Solution39 extends Solution
{
    protected function generatePQND(int $bits, \GMP $e): array
    {
        do {
            $p = gmp_nextprime(gmp_random_bits($bits));
            $q = gmp_nextprime(gmp_random_bits($bits));

            $d = gmp_invert($e, ($p - 1) * ($q - 1));
        } while (
            $d === false ||
            gmp_gcd($p, $e) != 1 ||
            gmp_gcd($q, $e) != 1
        );

        return [$p, $q, $p * $q, $d];
    }

    protected function encrypt(\GMP $message, \GMP $e, \GMP $n): \GMP
    {
        return gmp_powm($message, $e, $n);
    }

    protected function decrypt(\GMP $message, \GMP $d, \GMP $n): \GMP
    {
        return gmp_powm($message, $d, $n);
    }

    protected function execute(): bool
    {
        $e = gmp_init(3);

        list($p, $q, $n, $d) = $this->generatePQND(256, $e);

        /*
        $public = [$e, $n];
        $private = [$d, $n];
        */

        $c = $this->encrypt(gmp_init(0xbabe), $e, $n);
        $m = $this->decrypt($c, $d, $n);

        return $m == 0xbabe;
    }
}
