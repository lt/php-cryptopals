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

require_once '../02-block-crypto/09-implement-pkcs7-padding.php';
require_once '../02-block-crypto/15-pkcs7-padding-validation.php';

if (extension_loaded('openssl')) {
    function _encryptAES128ECB($data, $key)
    {
        return openssl_encrypt($data, 'aes-128-ecb', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
    }

    function _decryptAES128ECB($data, $key)
    {
        return openssl_decrypt($data, 'aes-128-ecb', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
    }
}
else if (extension_loaded('mcrypt')) {
    function _encryptAES128ECB($data, $key)
    {
        return mcrypt_encrypt('rijndael-128', $key, $data, 'ecb');
    }

    function _decryptAES128ECB($data, $key)
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

function encryptAES128ECB($data, $key)
{
    $dataLen = strlen($data);
    $blocks = [];

    for ($i = 0; $i < $dataLen; $i += 16) {
        $block = substr($data, $i, 16);
        if (strlen($block) < 16) {
            $block = addPKCS7Padding($block, 16);
        }
        $blocks[] = _encryptAES128ECB($block, $key);
    }

    return implode($blocks);
}

function decryptAES128ECB($data, $key)
{
    $dataLen = strlen($data);
    $blocks = [];

    for ($i = 0; $i < $dataLen; $i += 16) {
        $block = substr($data, $i, 16);
        $blocks[] = _decryptAES128ECB($block, $key);
    }

    $plaintext = implode($blocks);

    try {
        return removePKCS7Padding($plaintext);
    }
    catch (Exception $e) {
        return $plaintext;
    }
}

// don't output if we're included into another script.
if (!debug_backtrace()) {
    $encrypted = base64_decode(file_get_contents('07-data.txt'));
    $key = 'YELLOW SUBMARINE';

    $decryptedSane = removePKCS7Padding(_decryptAES128ECB($encrypted, $key));
    $decrypted = decryptAES128ECB($encrypted, $key);

    print "Sanity check:\n";
    $sanity = $decryptedSane === $decrypted;
    print $sanity ? "Success!\n\n" : "Failure :(\n\n";

    print "Homebrew sanity check:\n";
    $test = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    $sanity = decryptAES128ECB(encryptAES128ECB($test, $key), $key) === $test;
    print $sanity ? "Success!\n\n" : "Failure :(\n\n";

    print "Decrypted data:\n";
    print "$decrypted\n";
}
