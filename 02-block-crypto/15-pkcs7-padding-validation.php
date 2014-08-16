<?php

/*
 * http://cryptopals.com/sets/2/challenges/15/
 *
 * PKCS#7 padding validation
 *
 * Write a function that takes a plaintext, determines if it has valid PKCS#7 padding, and strips the padding off.
 *
 * The string:
 * "ICE ICE BABY\x04\x04\x04\x04"
 *
 * ... has valid padding, and produces the result "ICE ICE BABY".
 *
 * The string:
 * "ICE ICE BABY\x05\x05\x05\x05"
 *
 * ... does not have valid padding, nor does:
 * "ICE ICE BABY\x01\x02\x03\x04"
 *
 * If you are writing in a language with exceptions, like Python or Ruby, make your function throw an exception on bad padding.
 *
 * Crypto nerds know where we're going with this. Bear with us.
 */

function validPKCS7Padding($data)
{
    $dataLen = strlen($data);
    $padChar = $data[$dataLen - 1];
    $padLen = ord($padChar);
    for ($i = $dataLen - $padLen; $i < $dataLen; $i++) {
        if ($data[$i] !== $padChar) {
            throw new Exception('Invalid padding');
        }
    }

    return $padLen;
}

function removePKCS7Padding($data)
{
    $padLen = validPKCS7Padding($data);
    if ($padLen) {
        return substr($data, 0, -$padLen);
    }
    return $data;
}

// don't output if we're included into another script.
if (!debug_backtrace()) {
    $success = true;

    try {
        $success &= (validPKCS7Padding("ICE ICE BABY\x04\x04\x04\x04") === 4);
    }
    catch (Exception $e) {
        $success &= false;
    }

    try {
        validPKCS7Padding("ICE ICE BABY\x05\x05\x05\x05");
        $success &= false;
    }
    catch (Exception $e) {
        $success &= true;
    }

    try {
        validPKCS7Padding("ICE ICE BABY\x01\x02\x03\x04");
        $success &= false;
    }
    catch (Exception $e) {
        $success &= true;
    }

    print $success ? "Success!\n\n" : "Failure :(\n\n";
}

