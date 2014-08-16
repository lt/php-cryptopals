<?php

/*
 * http://cryptopals.com/sets/2/challenges/13/
 *
 * ECB cut-and-paste
 *
 * Write a k=v parsing routine, as if for a structured cookie. The routine should take:
 * foo=bar&baz=qux&zap=zazzle
 *
 * ... and produce:
 * {
 *   foo: 'bar',
 *   baz: 'qux',
 *   zap: 'zazzle'
 * }
 *
 * (you know, the object; I don't care if you convert it to JSON).
 *
 * Now write a function that encodes a user profile in that format, given an email address. You should have something like:
 * profile_for("foo@bar.com")
 *
 * ... and it should produce:
 * {
 *   email: 'foo@bar.com',
 *   uid: 10,
 *   role: 'user'
 * }
 *
 * ... encoded as:
 * email=foo@bar.com&uid=10&role=user
 *
 * Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote them, whatever you want to do, but don't let people set their email address to "foo@bar.com&role=admin".
 *
 * Now, two more easy functions. Generate a random AES key, then:
 * A. Encrypt the encoded user profile under the key; "provide" that to the "attacker".
 * B. Decrypt the encoded user profile and parse it.
 *
 * Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a role=admin profile.
 */

require_once '../utils/random-bytes.php';
require_once '../01-basics/07-aes-in-ecb-mode.php';

function profileFor($email)
{
    return http_build_query([
        'email' => $email,
        'uid' => 10,
        'role' => 'user'
    ]);
}

function encryptedProfileFor($email, $key)
{
    return encryptAES128ECB(profileFor($email), $key);
}

function decryptedProfile($ciphertext, $key)
{
    parse_str(decryptAES128ECB($ciphertext, $key), $profile);
    return $profile;
}

$key = getRandomBytes(16);

// assuming we know the structure is email=&uid=&role=
// 0..............f|0............
// email=aaaaaaaaaa|admin&uid=...

$padToAlignEmail = 16 - strlen('email=');

// pad until we cause a block count increase, then add 3 so we can chop off "user"
// ....f|0......
// role=|user...

$lastLen = strlen(encryptedProfileFor('a', $key));
for ($i = 2; $i <= 16; $i++) {
    if ($lastLen !== strlen(encryptedProfileFor(str_repeat('a', $i), $key))) {
        break;
    }
}
$padToChopRole = $i + 4;

print "Padding to chop role: $padToChopRole\n";
print "Padding to align admin: $padToAlignEmail\n";

$adminInBlock2 = encryptedProfileFor(str_repeat('a', $padToAlignEmail) . 'admin', $key);
$roleInBlock3 = encryptedProfileFor(str_repeat('a', $padToChopRole), $key);

// cut and paste
// 0..............f|0..............f|0..............f
// <------------- this ------------>|
// email=aaaaaaaaaa|aaa&uid=10&role=|user
//                 |                |<-- and this -->
//                 |email=aaaaaaaaaa|admin&uid=10&rol
//                 |                |
// email=aaaaaaaaaa|aaa&uid=10&role=|admin&uid=10&rol

$bakedAuth = substr($roleInBlock3, 0, 32) . substr($adminInBlock2, 16, 16);
$decryptedProfile = decryptedProfile($bakedAuth, $key);

print "Decrypted profile:\n";
var_dump($decryptedProfile);
