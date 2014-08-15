<?php

/*
 * http://cryptopals.com/sets/1/challenges/2/
 *
 * Fixed XOR
 *
 * Write a function that takes two equal-length buffers and produces their XOR combination.
 *
 * If your function works properly, then when you feed it the string:
 * 1c0111001f010100061a024b53535009181c
 *
 * ... after hex decoding, and when XOR'd against:
 * 686974207468652062756c6c277320657965
 *
 * ... should produce:
 * 746865206b696420646f6e277420706c6179
 */

function fixedXOR($one, $two)
{
    $output = '';
    $limit = min(strlen($one), strlen($two));

    for ($i = 0; $i < $limit; $i++) {
        $output .= $one[$i] ^ $two [$i];
    }

    return $output;
}

// Don't output if we're included into another script.
if (!debug_backtrace()) {
    $inputOne = hex2bin('1c0111001f010100061a024b53535009181c');
    $inputTwo = hex2bin('686974207468652062756c6c277320657965');
    $output = hex2bin('746865206b696420646f6e277420706c6179');

    print "Sanity checking using built-in functionality\n";
    $sanity = ($inputOne ^ $inputTwo) === $output;
    print $sanity ? "Success!\n\n" : "Failure :(\n\n";

    print "Performing string XOR with homebrew function\n";
    $homebrew = fixedXOR($inputOne, $inputTwo);
    $homebrewSane = $homebrew === $output;
    print $homebrewSane ? "Success!\n\n" : "Failure :(\n\n";

    print "XORed string was:\n$homebrew\n";
}
