<?php

/*
 * http://cryptopals.com/sets/1/challenges/8/
 *
 * Detect AES in ECB mode
 *
 * In this file are a bunch of hex-encoded ciphertexts.
 *
 * One of them has been encrypted with ECB.
 *
 * Detect it.
 *
 * Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
 */

function repeatedBlockCount($data)
{
    $dataLen = strlen($data);
    $repetitions = 0;

    for ($i = 0; $i < $dataLen; $i += 16) {
        $block = substr($data, $i, 16);
        $repetition = strpos($data, $block, $i + 16);

        if ($repetition && $repetition % 16 === 0) {
            $repetitions++;
        }
    }

    return $repetitions;
}

// don't output if we're included into another script.
if (!debug_backtrace()) {
    $data = array_map('hex2bin', file('08-data.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));

    foreach ($data as $k => $encrypted) {
        $repetitions = repeatedBlockCount($encrypted);

        if ($repetitions) {
            $line = $k + 1;
            print "String at on line $line has repeated blocks (probable ECB)\n";
        }
    }
}
