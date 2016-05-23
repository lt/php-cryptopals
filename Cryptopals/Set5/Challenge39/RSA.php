<?php declare(strict_types = 1);

namespace Cryptopals\Set5\Challenge39;

class RSA
{
    static function generatePQND(int $bits, \GMP $e): array
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

    static function encrypt(\GMP $message, \GMP $e, \GMP $n): \GMP
    {
        return gmp_powm($message, $e, $n);
    }

    static function decrypt(\GMP $message, \GMP $d, \GMP $n): \GMP
    {
        return gmp_powm($message, $d, $n);
    }

}
