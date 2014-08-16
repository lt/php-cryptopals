<?php

/*
 * http://cryptopals.com/sets/2/challenges/11/
 *
 * An ECB/CBC detection oracle
 *
 * Now that you have ECB and CBC working:
 *
 * Write a function to generate a random AES key; that's just 16 random bytes.
 *
 * Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it.
 *
 * The function should look like:
 * encryption_oracle(your-input)
 * => [MEANINGLESS JIBBER JABBER]
 *
 * Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.
 *
 * Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.
 *
 * Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.
 */

require_once '../utils/random-bytes.php';
require_once '../01-basics/07-aes-in-ecb-mode.php';
require_once '10-implement-cbc-mode.php';

function randomlyEncryptECBorCBC($data)
{
    $key = getRandomBytes(16);
    $pad1 = getRandomBytes(rand(5, 10));
    $pad2 = getRandomBytes(rand(5, 10));

    if (rand(0, 1)) {
        return encryptAES128CBC("$pad1$data$pad2", $key, getRandomBytes(16));
    }

    return encryptAES128ECB("$pad1$data$pad2", $key);
}


// don't output if we're included into another script.
if (!debug_backtrace()) {
    require_once '../01-basics/08-detect-aes-in-ecb-mode.php';

    // so the trick is to feed the black box something that will trigger ECBs weakness regardless of padding
    // this means we need at least 3 blocks of repeated data (with padding this reduces to 2 blocks)
    $plaintext = str_repeat('a', 48);

    print "Running 5000 samples\n";
    $ecb = 0;
    for ($i = 0; $i < 5000; $i++) {
        $ciphertext = randomlyEncryptECBorCBC($plaintext);
        if (repeatedBlockCount($ciphertext)) {
            $ecb++;
        }
    }
    print "$ecb samples detected as ECB mode\n";
    print $ecb && round(5000 / $ecb) === 2.0 ? "Success!\n\n" : "Failure :(\n\n";
}

