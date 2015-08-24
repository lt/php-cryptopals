<?php

/*
 * http://cryptopals.com/sets/3/challenges/17/
 *
 * The CBC padding oracle
 *
 * This is the best-known attack on modern block-cipher cryptography.
 *
 * Combine your padding code and your CBC code to write two functions.
 *
 * The first function should select at random one of the following 10 strings:
 * MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
 * MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
 * MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
 * MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
 * MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
 * MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
 * MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
 * MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
 * MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
 * MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
 *
 * ... generate a random AES key (which it should save for all future encryptions), pad the string out to the 16-byte AES block size and CBC-encrypt it under that key, providing the caller the ciphertext and IV.
 *
 * The second function should consume the ciphertext produced by the first function, decrypt it, check its padding, and return true or false depending on whether the padding is valid.
 *
 * What you're doing here.
 * This pair of functions approximates AES-CBC encryption as its deployed serverside in web applications; the second function models the server's consumption of an encrypted session token, as if it was a cookie.
 *
 * It turns out that it's possible to decrypt the ciphertexts provided by the first function.
 *
 * The decryption here depends on a side-channel leak by the decryption function. The leak is the error message that the padding is valid or not.
 *
 * You can find 100 web pages on how this attack works, so I won't re-explain it. What I'll say is this:
 *
 * The fundamental insight behind this attack is that the byte 01h is valid padding, and occur in 1/256 trials of "randomized" plaintexts produced by decrypting a tampered ciphertext.
 *
 * 02h in isolation is not valid padding.
 *
 * 02h 02h is valid padding, but is much less likely to occur randomly than 01h.
 *
 * 03h 03h 03h is even less likely.
 *
 * So you can assume that if you corrupt a decryption AND it had valid padding, you know what that padding byte is.
 *
 * It is easy to get tripped up on the fact that CBC plaintexts are "padded". Padding oracles have nothing to do with the actual padding on a CBC plaintext. It's an attack that targets a specific bit of code that handles decryption. You can mount a padding oracle on any CBC block, whether it's padded or not.
 */

require_once '../utils/random-bytes.php';
require_once '../02-block-crypto/10-implement-cbc-mode.php';
require_once '../02-block-crypto/15-pkcs7-padding-validation.php';

function getRandomCiphertext($key, $iv)
{
    $texts = [
        'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
        'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
        'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
        'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
        'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
        'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
        'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
        'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
        'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
        'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
    ];

    $texts = array_map('base64_decode', $texts);
    $text = $texts[rand(0,9)];

    // our implementation automatically PKCS7 pads
    return encryptAES128CBC($text, $key, $iv);
}

function validPadding($ciphertext, $key, $iv)
{
    try {
        decryptAES128CBC($ciphertext, $key, $iv, true);
        return true;
    }
    catch (Exception $e) {
        return false;
    }
}

function crackBlock($block, $key, $iv)
{
    $fauxBlock = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    $realBlock = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    for ($attackPosition = 15; $attackPosition >= 0; $attackPosition--) {
        for ($trialByte = 0; $trialByte < 256; $trialByte++) {
            $fauxBlock[$attackPosition] = $trialByte;

            // wishlist: pack_array(format, array)
            if (validPadding($block, $key, implode(array_map('chr', $fauxBlock)))) {
                // 1 in 65536 chance that we got 0x02 0x02 rather than 0x?? 0x01 - I'll take that risk!

                $currentPadding = 16 - $attackPosition;
                $realBlock[$attackPosition] = $currentPadding ^ $trialByte ^ ord($iv[$attackPosition]);

                if ($attackPosition === 0) {
                    break 2;
                }

                for ($j = 15; $j >= $attackPosition; $j--) {
                    $fauxBlock[$j] = ($currentPadding + 1) ^ $realBlock[$j] ^ ord($iv[$j]);
                }

                break;
            }
        }
    }

    return implode(array_map('chr', $realBlock));
}

// don't output if we're included into another script.
if (!debug_backtrace()) {
    print "Cracking 10 randomly selected ciphertexts:\n";
    for ($j = 0; $j < 10; $j++) {
        $key = getRandomBytes(16);
        $iv = getRandomBytes(16);

        $ciphertext = getRandomCiphertext($key, $iv);

        $blocks = str_split($ciphertext, 16);
        array_unshift($blocks, $iv);
        $blockNum = count($blocks) - 1;

        for ($i = $blockNum; $i > 0; $i--) {
            $blocks[$i] = crackBlock($blocks[$i], $key, $blocks[$i - 1]);
        }

        array_shift($blocks);

        print "$j: " . removePKCS7Padding(implode($blocks)) . "\n";
    }
}
