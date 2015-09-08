<?php

/*
 * http://cryptopals.com/sets/4/challenges/26/
 *
 * CTR bitflipping
 *
 * There are people in the world that believe that CTR resists bit flipping attacks of the kind to which CBC mode is susceptible.
 *
 * Re-implement the CBC bitflipping exercise from earlier to use CTR mode instead of CBC mode. Inject an "admin=true" token.
 */


require_once '../utils/random-bytes.php';
require_once '../03-block-and-stream-crypto/18-implement-ctr-the-stream-cipher-mode.php';

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

    return encryptAES128CTR($data, $key, $iv);
}

function isAdmin($query, $key, $iv)
{
    $data = encryptAES128CTR($query, $key, $iv);

    return strpos($data, ';admin=true;') !== false;
}

// don't output if we're included into another script.
if (!debug_backtrace()) {
    $key = random_bytes(16);
    $iv = random_bytes(16);

// 0..............f|0..............f|0..............f|0..............f|0..............f
// comment1=cooking|%20MCs;userdata=
//                 |                |bbbb;admin=true |
//                                                  ;|comment2=%20like%20a%20pound%20of%20bacon

    $badData = 'bbbb;admin=true';
    $goodData = 'bbbbbbbbbbbbbbb';
    $bitMask = $badData ^ $goodData;

    $query = getQuery($goodData, $key, $iv);

    for ($i = 32; $i < 47; $i++) {
        $query[$i] = $query[$i] ^ $bitMask[$i - 32];
    }

    print "Querystring has admin=true:\n";
    print isAdmin($query, $key, $iv) ? "Yes\n\n" : "No :(";
}
