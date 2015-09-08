<?php

/*
 * http://cryptopals.com/sets/4/challenges/27/
 *
 * Recover the key from CBC with IV=Key
 *
 * Take your code from the CBC exercise and modify it so that it repurposes the key for CBC encryption as the IV.
 *
 * Applications sometimes use the key as an IV on the auspices that both the sender and the receiver have to know the key already, and can save some space by using it as both a key and an IV.
 *
 * Using the key as an IV is insecure; an attacker that can modify ciphertext in flight can get the receiver to decrypt a value that will reveal the key.
 *
 * The CBC code from exercise 16 encrypts a URL string. Verify each byte of the plaintext for ASCII compliance (ie, look for high-ASCII values). Noncompliant messages should raise an exception or return an error that includes the decrypted plaintext (this happens all the time in real systems, for what it's worth).
 *
 * Use your code to encrypt a message that is at least 3 blocks long:
 * AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3
 *
 * Modify the message (you are now the attacker):
 * C_1, C_2, C_3 -> C_1, 0, C_1
 *
 * Decrypt the message (you are now the receiver) and raise the appropriate error if high-ASCII is found.
 *
 * As the attacker, recovering the plaintext from the error, extract the key:
 * P'_1 XOR P'_3
 */


require_once '../utils/random-bytes.php';
require_once '../02-block-crypto/10-implement-cbc-mode.php';

function getQuery($userData, $key)
{
    $data = http_build_query(
        [
            'comment1' => 'cooking MCs',
            'userdata' => $userData,
            'comment2' => ' lke a pound of bacon'
        ],
        null, ';', PHP_QUERY_RFC3986
    );

    return encryptAES128CBC($data, $key, $key);
}

function isAdmin($query, $key)
{
    $data = decryptAES128CBC($query, $key, $key);

    if (preg_match('/^[\x{21}-\x{7E}]*$/', $data)) {
        return strpos($data, ';admin=true;') !== false;
    }

    throw new Exception($data);
}

// don't output if we're included into another script.
if (!debug_backtrace()) {
    $key = random_bytes(16);

// 0..............f|0..............f|0..............f|0..............f
// comment1=cooking|%20MCs;userdata=
//                 |                |userdata
//                                           ;comment|2=%20like%20a%20pound%20of%20bacon


    $query = getQuery('userdata', $key);

    $brokenQuery = substr($query, 0, 16) .
        str_repeat("\0", 16) .
        substr($query, 0, 16);

    try {
        isAdmin($brokenQuery, $key);
    }
    catch (Exception $e)
    {
        $error = $e->getMessage();
        $recoveredKey = substr($error, 0, 16) ^ substr($error, 32);

        print "Keys match:\n";
        print $key === $recoveredKey ? "Yes\n\n" : "No :(\n\n";

        $query = encryptAES128CBC('comment1=cooking%20MCs;userdata=x;admin=true;comment2=%20like%20a%20pound%20of%20bacon', $recoveredKey, $recoveredKey);
    }

    print "Querystring has admin=true:\n";
    print isAdmin($query, $key) ? "Yes\n\n" : "No :(\n\n";
}
