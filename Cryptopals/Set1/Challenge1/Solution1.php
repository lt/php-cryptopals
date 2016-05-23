<?php declare(strict_types = 1);

/*
 * PHP has the built-in functions `hex2bin()` and `base64_encode()` however
 * using these for this solution does not demonstrate an understanding of the
 * process. I will use them for future solutions though.
 *
 * The conversion process is simple.
 *
 * Each hexadecimal character represents 4 bits of binary.
 * Each base64 character represents 6 bits of binary.
 *
 * The conversion function pushes 4 bits at a time into a buffer, and when the
 * buffer contains 6 or more bits, those bits are consumed to produce an
 * output character.
 */

namespace Cryptopals\Set1\Challenge1;

use Cryptopals\Solution;

class Solution1 implements Solution
{
    const BASE16_CHARSET = '0123456789abcdef';
    const BASE64_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

    protected function hexToBase64(string $input): string
    {
        $inputLen = strlen($input);

        if ($inputLen % 2) {
            throw new \InvalidArgumentException('Length of input must be a multiple of two.');
        }

        $input = strtolower($input);
        $buffer = 0;
        $bufferedBits = 0;
        $output = '';

        for ($i = 0; $i < $inputLen; $i++) {
            $charPos = strpos(self::BASE16_CHARSET, $input[$i]);
            if ($charPos === false) {
                throw new \DomainException('Invalid character at offset: ' . $i);
            }

            $buffer = ($buffer << 4) | $charPos;
            $bufferedBits += 4;
            if ($bufferedBits >= 6) {
                $bufferedBits -= 6;
                $output .= self::BASE64_CHARSET[($buffer >> $bufferedBits) & 63];
            }
        }

        // Add padding if any bits remain in the buffer.
        if ($bufferedBits) {
            $output .= self::BASE64_CHARSET[($buffer << (6 - $bufferedBits))  & 63] . str_repeat('=', $inputLen % 3);
        }

        return $output;
    }

    function execute(): bool
    {
        $input = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d';
        $expected = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t';
        $output = $this->hexToBase64($input);

        print 'Expected: ' . $expected . "\n";
        print 'Actual:   ' . $output . "\n";

        return $output === $expected;
    }
}
