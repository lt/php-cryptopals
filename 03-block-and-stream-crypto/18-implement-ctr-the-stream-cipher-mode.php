<?php

/*
 * http://cryptopals.com/sets/3/challenges/18/
 *
 * Implement CTR, the stream cipher mode
 *
 * The string:
 * L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==
 *
 * ... decrypts to something approximating English in CTR mode, which is an AES block cipher mode that turns AES into a stream cipher, with the following parameters:
 *      key=YELLOW SUBMARINE
 *      nonce=0
 *      format=64 bit unsigned little endian nonce,
 *             64 bit little endian block count (byte count / 16)
 *
 * CTR mode is very simple.
 *
 * Instead of encrypting the plaintext, CTR mode encrypts a running counter, producing a 16 byte block of keystream, which is XOR'd against the plaintext.
 *
 * For instance, for the first 16 bytes of a message with these parameters:
 * keystream = AES("YELLOW SUBMARINE",
 *                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
 *
 * ... for the next 16 bytes:
 * keystream = AES("YELLOW SUBMARINE",
 *                "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00")
 *
 * ... and then:
 * keystream = AES("YELLOW SUBMARINE",
 *                "\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00")
 *
 * CTR mode does not require padding; when you run out of plaintext, you just stop XOR'ing keystream and stop generating keystream.
 *
 * Decryption is identical to encryption. Generate the same keystream, XOR, and recover the plaintext.
 *
 * Decrypt the string at the top of this function, then use your CTR function to encrypt and decrypt other things.
 *
 * This is the only block cipher mode that matters in good code.
 * Most modern cryptography relies on CTR mode to adapt block ciphers into stream ciphers, because most of what we want to encrypt is better described as a stream than as a sequence of blocks. Daniel Bernstein once quipped to Phil Rogaway that good cryptosystems don't need the "decrypt" transforms. Constructions like CTR are what he was talking about.
 */

if (PHP_INT_SIZE < 8) {
    throw new Exception('64 bit PHP required!');
}

// pull in previous functions to do single blocks of AES
require_once '../01-basics/07-aes-in-ecb-mode.php';

function encryptAES128CTR($data, $key, $nonce = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")
{
    $blocks = str_split($data, 16);

    $counter = unpack('V4', $nonce);

    foreach ($blocks as &$block) {
        $block ^= _encryptAES128ECB(
            pack('V4', $counter[1], $counter[2], $counter[3], $counter[4]),
            $key
        );

        // Because we don't have unsigned 64 bit numbers in PHP...
        $counter[3] = ($carry = $counter[3] + 1) & 0xffffffff;
        $counter[4] = (($carry >> 32) + $counter[4]) & 0xffffffff;
    }

    return implode($blocks);
}

// don't output if we're included into another script.
if (!debug_backtrace()) {
    $ciphertext = base64_decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==');
    $key = 'YELLOW SUBMARINE';

    $plaintext = encryptAES128CTR($ciphertext, $key);
    $homebrewCipher = encryptAES128CTR($plaintext, $key);

    print "Sanity check:\n";
    $sanity = $ciphertext === $homebrewCipher;
    print $sanity ? "Success!\n\n" : "Failure :(\n\n";

    print "Decrypted data:\n";
    print "$plaintext\n";
}
