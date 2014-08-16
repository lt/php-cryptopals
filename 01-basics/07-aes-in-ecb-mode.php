<?php

/*
 * http://cryptopals.com/sets/1/challenges/7/
 *
 * AES in ECB mode
 *
 * The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key
 * "YELLOW SUBMARINE".
 * (case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).
 *
 * Decrypt it. You know the key, after all.
 *
 * Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
 *
 * Do this with code.
 * You can obviously decrypt this using the OpenSSL command-line tool, but we're having you get ECB working in code for a reason. You'll need it a lot later on, and not just for attacking ECB.
 */

if (extension_loaded('openssl')) {
    function encryptAES128ECB($data, $key)
    {
        return openssl_encrypt($data, 'aes-128-ecb', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
    }

    function decryptAES128ECB($data, $key)
    {
        return openssl_decrypt($data, 'aes-128-ecb', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
    }
}
else if (extension_loaded('mcrypt')) {
    function encryptAES128ECB($data, $key)
    {
        return mcrypt_encrypt('rijndael-128', $key, $data, 'ecb');
    }

    function decryptAES128ECB($data, $key)
    {
        return mcrypt_decrypt('rijndael-128', $key, $data, 'ecb');
    }
}
else {
    throw new RuntimeException('You need either the OpenSSL or MCrypt extensions installed for this one');
}

/*
 * So, AES is a block cipher, we make it into a stream cipher by adding magic to sequential blocks
 * ECB means "don't do a fucking thing" which just results in a bunch of AES blocks glued together. Fail.
 *
 * Lets go!
 */

function encryptAES128ECBOneBlockAtATime($data, $key)
{
    $dataLen = strlen($data);
    $blocks = [];
    for ($i = 0; $i < $dataLen; $i += 16) {
        $block = substr($data, $i * 16, 16);
        $blocks[] = encryptAES128ECB($block, $key);
    }
    return implode($blocks);
}

function decryptAES128ECBOneBlockAtATime($data, $key)
{
    $dataLen = strlen($data);
    $blocks = [];
    for ($i = 0; $i < $dataLen; $i += 16) {
        $block = substr($data, $i, 16);
        $blocks[] = decryptAES128ECB($block, $key);
    }
    return implode($blocks);
}

// don't output if we're included into another script.
if (!debug_backtrace()) {
    $encrypted = base64_decode(file_get_contents('07-data.txt'));
    $key = 'YELLOW SUBMARINE';

    $decryptedSane = decryptAES128ECB($encrypted, $key);

    $decrypted = decryptAES128ECBOneBlockAtATime($encrypted, $key);

    print "Sanity check:\n";
    $sanity = $decryptedSane === $decrypted;
    print $sanity ? "Success!\n\n" : "Failure :(\n\n";

    print "Decrypted data:\n";
    print "$decrypted\n";
}
