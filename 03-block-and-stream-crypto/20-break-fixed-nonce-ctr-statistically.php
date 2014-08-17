<?php

/*
 * http://cryptopals.com/sets/3/challenges/20/
 *
 * Break fixed-nonce CTR statistically
 *
 * In this file find a similar set of Base64'd plaintext. Do with them exactly what you did with the first, but solve the problem differently.
 *
 * Instead of making spot guesses at to known plaintext, treat the collection of ciphertexts the same way you would repeating-key XOR.
 *
 * Obviously, CTR encryption appears different from repeated-key XOR, but with a fixed nonce they are effectively the same thing.
 *
 * To exploit this: take your collection of ciphertexts and truncate them to a common length (the length of the smallest ciphertext will work).
 *
 * Solve the resulting concatenation of ciphertexts as if for repeating- key XOR, with a key size of the length of the ciphertext you XOR'd.
 */

require_once '../utils/random-bytes.php';
require_once '../01-basics/06-break-repeating-key-xor.php';
require_once '18-implement-ctr-the-stream-cipher-mode.php';

$plaintexts = array_map('base64_decode', file('20-data.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));
$key = getRandomBytes(16);
$ciphertexts = array_map('encryptAES128CTR', $plaintexts, array_fill(0, count($plaintexts), $key));

$cipherLens = array_map('strlen', $ciphertexts);

// challenge text says use a common length, but we can recover more if we don't
// this is because after transposition there's still enough data to statistically recover more
/*
$minLength = min($cipherLens);
$truncated = array_map('str_split', $ciphertexts, array_fill(0, count($plaintexts), $minLength));
$truncated = array_column($truncated, 0);
*/
$truncated = $ciphertexts;

// some copy/paste/tweak from challenge 6

print "\nSolving keys based on English Language scoring:\n";

$blocks = transposeBlocks($ciphertexts);

$englishLanguageWeights['/'] = 0;
list($topScores, $topChars) = scoreSingleByteXORStrings($blocks, $englishLanguageWeights, 20);

$potentialKey = implode(array_map('chr', $topChars));

foreach ($truncated as $k => $ciphertext) {
    $recovered = $ciphertext ^ $potentialKey;
    print "$k: $recovered\n";
}

print "\n\nSome texts will not be fully recovered.\nThis is expected for simple automatic statistical recovery.\n\n\n";

foreach ($truncated as $k => $ciphertext) {
    $recovered = $ciphertext ^ $potentialKey;
    if ($recovered !== $plaintexts[$k]) {
        print "Cracked : $recovered\nOriginal: {$plaintexts[$k]}\n\n";
    }
}