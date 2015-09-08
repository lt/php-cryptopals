<?php

/*
 * http://cryptopals.com/sets/3/challenges/24/
 *
 * Create the MT19937 stream cipher and break it
 *
 * You can create a trivial stream cipher out of any PRNG; use it to generate a sequence of 8 bit outputs and call those outputs a keystream. XOR each byte of plaintext with each successive byte of keystream.
 *
 * Write the function that does this for MT19937 using a 16-bit seed. Verify that you can encrypt and decrypt properly. This code should look similar to your CTR code.
 *
 * Use your function to encrypt a known plaintext (say, 14 consecutive 'A' characters) prefixed by a random number of random characters.
 *
 * From the ciphertext, recover the "key" (the 16 bit seed).
 *
 * Use the same idea to generate a random "password reset token" using MT19937 seeded from the current time.
 *
 * Write a function to check if any given password token is actually the product of an MT19937 PRNG seeded with the current time.
 */

require_once '../utils/random-bytes.php';
require_once '21-implement-the-mt19937-mersenne-twister-rng.php';

function encryptMT19937($data, $seed = 0)
{
    $seed &= 0xffff;

    $mt = new MT19937();
    $mt->init($seed);

    $dataLen = strlen($data);

    for ($i = 0; $i < $dataLen; $i++) {
        $data[$i] = chr(ord($data[$i]) ^ ($mt->int32() & 0xff));
    }

    return $data;
}

function encryptWithRandomPad($data, $seed = 0)
{
    return encryptMT19937(random_bytes(rand(1,20)) . $data, $seed);
}


// don't output if we're included into another script.
if (!debug_backtrace()) {
    $plaintext = 'the matasano crypto challenges';

    print "Sanity check:\n";
    $sanity = encryptMT19937(encryptMT19937($plaintext)) === $plaintext;
    print $sanity ? "Success!\n\n" : "Failure :(\n\n";

    $secretSeed = rand(0, 0xffff);
    $plaintext = str_repeat('A', 14);
    $ciphertext = encryptWithRandomPad($plaintext, $secretSeed);

    $cipherLen = strlen($ciphertext);
    $padLen = $cipherLen - strlen($plaintext);
    // stupid unpack indexing array from 1...
    $keyStream = array_values(unpack('C*', substr($ciphertext, $padLen) ^ $plaintext));

    $mt = new MT19937();
    for ($i = 0; $i < 0xffff; $i++) {
        $mt->init($i);
        $thisSequence = [];
        for ($j = 0; $j < $padLen; $j++) {
            $mt->int32();
        }
        for (; $j < $cipherLen; $j++) {
            $thisSequence[] = $mt->int32() & 0xff;
        }
        if ($thisSequence === $keyStream) {
            print "Seed was: $i\n\n";
            break;
        }
    }
}
