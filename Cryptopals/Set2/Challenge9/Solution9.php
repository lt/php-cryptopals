<?php declare(strict_types = 1);

namespace Cryptopals\Set2\Challenge9;

use Cryptopals\Solution;

class Solution9 implements Solution
{
    function execute(): bool
    {
        $testCases = [
            ['YELLOW SUBMARINE', 20, "\x04\x04\x04\x04"],
            ['YELLOW SUBMARINE', 10, "\x04\x04\x04\x04"],
            ['YELLOW SUBMARINE',  6, "\x02\x02"],
            // make sure a full block of padding is added when the data length is a multiple of the pad length
            ['YELLOW SUBMARINE',  8, "\x08\x08\x08\x08\x08\x08\x08\x08"],
            ['',                  4, "\x04\x04\x04\x04"]
        ];

        $success = true;

        foreach ($testCases as list($message, $padLen, $expectedPadding)) {
            print "Padding for '{$message}' padded to {$padLen}: ";
            $padding = PKCS7::getPadding($message, $padLen);
            
            print bin2hex($padding) . ' - ';
            $result = $padding === $expectedPadding;
            
            print $result ? "OK\n" : "FAIL\n";
            $success = $success && $result;
        }

        return $success;
    }
}
