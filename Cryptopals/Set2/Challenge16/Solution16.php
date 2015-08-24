<?php

/*
 * CBC bitflipping attacks
 *
 * Generate a random AES key.
 *
 * Combine your padding code and CBC code to write two functions.
 *
 * The first function should take an arbitrary input string, prepend the string:
 * "comment1=cooking%20MCs;userdata="
 *
 * .. and append the string:
 * ";comment2=%20like%20a%20pound%20of%20bacon"
 *
 * The function should quote out the ";" and "=" characters.
 *
 * The function should then pad out the input to the 16-byte AES block length and encrypt it under the random AES key.
 *
 * The second function should decrypt the string and look for the characters ";admin=true;" (or, equivalently, decrypt, split the string on ";", convert each resulting string into 2-tuples, and look for the "admin" tuple).
 *
 * Return true or false based on whether the string exists.
 *
 * If you've written the first function properly, it should not be possible to provide user input to it that will generate the string the second function is looking for. We'll have to break the crypto to do that.
 *
 * Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.
 *
 * You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:
 * - Completely scrambles the block the error occurs in
 * - Produces the identical 1-bit error(/edit) in the next ciphertext block.
 *
 * Stop and think for a second.
 *
 * Before you implement this attack, answer this question: why does CBC mode have this property?
 */

require_once '../utils/random-bytes.php';
require_once '10-implement-cbc-mode.php';

function getQuery($userData, $key, $iv)
{
    $data = http_build_query(
        [
            'comment1' => 'cooking MCs',
            'userdata' => $userData,
            'comment2' => ' lke a pound of bacon'
        ],
        null, ';', PHP_QUERY_RFC3986
    );

    return encryptAES128CBC($data, $key, $iv);
}

function isAdmin($query, $key, $iv)
{
    $data = decryptAES128CBC($query, $key, $iv);

    return strpos($data, ';admin=true;') !== false;
}

// don't output if we're included into another script.
if (!debug_backtrace()) {
    $key = getRandomBytes(16);
    $iv = getRandomBytes(16);

// 0..............f|0..............f|0..............f|0..............f|0..............f
// comment1=cooking|%20MCs;userdata=
//                 |                |aaaaaaaaaaaaaaaa|bbbb;admin=true |
//                                                                   ;comment2=%20like%20a%20pound%20of%20bacon

    $badData = 'aaaaaaaaaaaaaaaabbbb;admin=true';
    $goodData = 'aaaaaaaaaaaaaaaabbbbbbbbbbbbbbb';
    $bitMask = substr($badData ^ $goodData, 16);

    $query = getQuery($goodData, $key, $iv);

    for ($i = 32; $i < 47; $i++) {
        $query[$i] = $query[$i] ^ $bitMask[$i - 32];
    }

    print "Querystring has admin=true:\n";
    print isAdmin($query, $key, $iv) ? "Yes\n\n" : "No :(";
}