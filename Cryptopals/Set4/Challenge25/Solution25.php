<?php

/*
 * http://cryptopals.com/sets/4/challenges/25/
 *
 * Break "random access read/write" AES CTR
 *
 * Back to CTR. Encrypt the recovered plaintext from this file (the ECB exercise) under CTR with a random key (for this exercise the key should be unknown to you, but hold on to it).
 *
 * Now, write the code that allows you to "seek" into the ciphertext, decrypt, and re-encrypt with different plaintext. Expose this as a function, like, "edit(ciphertext, key, offet, newtext)".
 *
 * Imagine the "edit" function was exposed to attackers by means of an API call that didn't reveal the key or the original plaintext; the attacker has the ciphertext and controls the offset and "new text".
 *
 * Recover the original plaintext.
 *
 * Food for thought.
 * A folkloric supposed benefit of CTR mode is the ability to easily "seek forward" into the ciphertext; to access byte N of the ciphertext, all you need to be able to do is generate byte N of the keystream. Imagine if you'd relied on that advice to, say, encrypt a disk.
 */

require_once '../utils/random-bytes.php';
require_once '../03-block-and-stream-crypto/18-implement-ctr-the-stream-cipher-mode.php';

function editAES128CTR($ciphertext, $key, $nonce = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", $offset, $newtext)
{
    $newLen = strlen($newtext);

    // really dirty - I could calculate block specific keys, but I don't really have to for this.
    $plaintext = encryptAES128CTR($ciphertext, $key, $nonce);
    $plainLen = strlen($plaintext);

    $newPlaintext = '';
    if ($offset > 0) {
        $newPlaintext = substr($plaintext, 0, $offset);
    }

    $newPlaintext .= $newtext;

    if ($newLen + $offset < $plainLen) {
        $newPlaintext .= substr($plaintext, $newLen + $offset);
    }

    return encryptAES128CTR($newPlaintext, $key, $nonce);
}

// don't output if we're included into another script.
if (!debug_backtrace()) {
    $key = random_bytes(16);
    $nonce = random_bytes(16);

    $ciphertext = encryptAES128CTR(
        decryptAES128ECB(
            base64_decode(file_get_contents('25-data.txt')),
            'YELLOW SUBMARINE'
        ),
        $key,
        $nonce
    );

    $editedCiphertext = editAES128CTR($ciphertext, $key, $nonce, 0, str_repeat("\0", strlen($ciphertext)));

    print "Recovered plaintext:\n";
    print $ciphertext ^ $editedCiphertext . "\n\n";
}
