<?php

/*
 * http://cryptopals.com/sets/2/challenges/10/
 *
 * Implement CBC mode
 *
 * CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the fact that a block cipher natively only transforms individual blocks.
 *
 * In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.
 *
 * The first plaintext block, which has no associated previous ciphertext block, is added to a "fake 0th ciphertext block" called the initialization vector, or IV.
 *
 * Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test), and using your XOR function from the previous exercise to combine them.
 *
 * The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)
 *
 * Don't cheat.
 * Do not use OpenSSL's CBC code to do CBC mode, even to verify your results. What's the point of even doing this stuff if you aren't going to learn from it?
 */

// pull in previous functions to do single blocks of AES
require_once '../01-basics/07-aes-in-ecb-mode.php';

function encryptAES128CBC($data, $key, $iv = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")
{
    $dataLen = strlen($data);
    $blocks = [];
    for ($i = 0; $i < $dataLen; $i += 16) {
        $block = substr($data, $i, 16) ^ $iv;
        $iv = encryptAES128ECB($block, $key);
        $blocks[] = $iv;
    }
    return implode($blocks);
}

function decryptAES128CBC($data, $key, $iv = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")
{
    $dataLen = strlen($data);
    $blocks = [];
    for ($i = 0; $i < $dataLen; $i += 16) {
        $block = substr($data, $i, 16);
        $blocks[] = $iv ^ decryptAES128ECB($block, $key);
        $iv = $block;
    }
    return implode($blocks);
}

// don't output if we're included into another script.
if (!debug_backtrace()) {
    $encrypted = base64_decode(file_get_contents('10-data.txt'));
    $key = 'YELLOW SUBMARINE';

    $decrypted = decryptAES128CBC($encrypted, $key);
    $homebrewEncrypted = encryptAES128CBC($decrypted, $key);

    print "Sanity check:\n";
    $sanity = $encrypted === $homebrewEncrypted;
    print $sanity ? "Success!\n\n" : "Failure :(\n\n";

    print "Decrypted data:\n";
    print "$decrypted\n";
}
