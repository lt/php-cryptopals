<?php

function hexToBase64($hex)
{
    $base16Chars = array_flip(str_split('0123456789abcdef'));
    $base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

    // sanitise for our charset
    $hex = strtolower($hex);

    $hexLen = strlen($hex);
    $buffer = 0;
    $bufferedBits = 0;
    $base64 = '';

    for ($i = 0; $i < $hexLen; $i++) {
        $buffer = ($buffer << 4) | $base16Chars[$hex[$i]];
        $bufferedBits += 4;

        if ($bufferedBits >= 6) {
            $bufferedBits -= 6;
            $base64 .= $base64Chars[($buffer >> $bufferedBits) & 63];
            $buffer &= (1 << $bufferedBits) - 1;
        }
    }

    // finished consuming hex but less than 6 bits buffered
    if ($bufferedBits) {
        $base64 .= $base64Chars[$buffer << (6 - $bufferedBits)];
    }

    // because base64
    $base64 .= str_repeat('=', $hexLen % 3);

    return $base64;
}

// don't output if we include this file into another script
if (!debug_backtrace()) {
    $base16 = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d';
    $base64 = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t';

    print "Sanity checking using built-in functions\n";
    $sanity = base64_encode(hex2bin($base16)) === $base64;
    print $sanity ? "Success!\n\n" : "Failure :(\n\n";

    print "Converting hex to base64 with homebrew function\n";
    $homebrew = hexToBase64($base16);
    $homebrewSane = $homebrew === $base64;
    print $homebrewSane ? "Success!\n\n" : "Failure :(\n\n";

    $decodedHomebrew = base64_decode($homebrew);
    print "Decoded string was:\n$decodedHomebrew\n";
}
