<?php

/*
 * http://cryptopals.com/sets/2/challenges/9/
 *
 * Implement PKCS#7 padding
 *
 * A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized messages.
 *
 * One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize. The most popular padding scheme is called PKCS#7.
 *
 * So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block. For instance,
 * "YELLOW SUBMARINE"
 *
 * ... padded to 20 bytes would be:
 * "YELLOW SUBMARINE\x04\x04\x04\x04"
 */

function addPKCS7Padding($data, $padTo = 16)
{
    $dataLen = strlen($data);
    $padLen = $padTo - ($dataLen % $padTo);

    return $data . str_repeat(chr($padLen), $padLen);
}

// don't output if we're included into another script.
if (!debug_backtrace()) {
    $success = true;

    $success &= addPKCS7Padding('YELLOW SUBMARINE', 20) === "YELLOW SUBMARINE\x04\x04\x04\x04";
    $success &= addPKCS7Padding('YELLOW SUBMARINE', 10) === "YELLOW SUBMARINE\x04\x04\x04\x04";
    $success &= addPKCS7Padding('YELLOW SUBMARINE', 6) === "YELLOW SUBMARINE\x02\x02";
    // make sure a full block of padding is added when the data length is a multiple of the pad length
    $success &= addPKCS7Padding('YELLOW SUBMARINE', 8) === "YELLOW SUBMARINE\x08\x08\x08\x08\x08\x08\x08\x08";
    $success &= addPKCS7Padding('', 4) === "\x04\x04\x04\x04";

    print $success ? "Success!\n\n" : "Failure :(\n\n";
}

