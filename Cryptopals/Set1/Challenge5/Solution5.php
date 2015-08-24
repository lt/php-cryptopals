<?php

/*
 * http://cryptopals.com/sets/1/challenges/5/
 *
 * Implement repeating-key XOR
 *
 * Here is the opening stanza of an important work of the English language:
 * Burning 'em, if you ain't quick and nimble
 * I go crazy when I hear a cymbal
 *
 * Encrypt it, under the key "ICE", using repeating-key XOR.
 *
 * In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.
 *
 * It should come out to:
 * 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
 *
 * Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this.
 */

function repeatingKeyXOR($data, $key)
{
    $dataLen = strlen($data);
    $keyLen = strlen($key);

    for ($i = 0; $i < $dataLen; $i++) {
        $data[$i] = $data[$i] ^ $key[$i % $keyLen];
    }

    return $data;
}

// don't output if we're included into another script.
if (!debug_backtrace()) {
    $data = <<<EOF
Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal
EOF;

    $key = 'ICE';

    $expected = hex2bin('0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f');

    print "Sanity checking using one-time pad\n";
    $sanity = ($data ^ str_repeat($key, ceil(strlen($data) / strlen($key)))) === $expected;
    print $sanity ? "Success!\n\n" : "Failure :(\n\n";

    print "Performing repeating key XOR with homebrew function\n";
    $homebrew = repeatingKeyXOR($data, $key);
    $homebrewSane = $homebrew === $expected;
    print $homebrewSane ? "Success!\n\n" : "Failure :(\n\n";
}
