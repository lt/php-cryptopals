<?php declare(strict_types = 1);

/*
 * PHP can natively XOR two strings using the `^` operator. The length of the
 * output is the same as the length of the shortest string. I will use this
 * operator in future solutions, but for this solution I will perform the XOR
 * "the hard way"
 */

namespace Cryptopals\Set1\Challenge2;

use Cryptopals\Solution;

class Solution2 extends Solution
{
    protected function fixedXOR(string $a, string $b): string
    {
        $output = '';
        $limit = min(strlen($a), strlen($b));

        for ($i = 0; $i < $limit; $i++) {
            // It is possible to XOR characters (more precisely single character
            // strings) directly, but being verbose for the sake of this solution
            $output .= chr(ord($a[$i]) ^ ord($b [$i]));
        }

        return $output;
    }

    protected function execute(): bool
    {
        $inputOne = hex2bin('1c0111001f010100061a024b53535009181c');
        $inputTwo = hex2bin('686974207468652062756c6c277320657965');
        $expected = '746865206b696420646f6e277420706c6179';

        $output = $this->fixedXOR($inputOne, $inputTwo);
        $output = bin2hex($output);

        print 'Expected: ' . $expected . "\n";
        print 'Actual:   ' . $output . "\n";

        return $output === $expected;
    }
}
