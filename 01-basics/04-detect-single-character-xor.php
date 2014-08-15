<?php

/*
 * http://cryptopals.com/sets/1/challenges/4/
 *
 * Detect single-character XOR
 *
 * One of the 60-character strings in this file has been encrypted by single-character XOR.
 *
 * Find it.
 *
 * (Your code from #3 should help.)
 */

require_once '03-single-byte-xor-cipher.php';

function scoreSingleByteXORStrings(array $strings, array $weights, $penalty = 0)
{
    $topScores = [];
    $topChars = [];

    foreach ($strings as $pos => $string) {
        $scores = scoreSingleByteXOR($string, $weights, $penalty);
        $score = reset($scores);
        $topScores[$pos] = $score;
        $topChars[$pos] = key($scores);
    }

    arsort($topScores);
    return [$topScores, $topChars];
}


// don't output if we're included into another script.
if (!debug_backtrace()) {
    $encrypted = array_map('hex2bin', file('04-data.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));

    list($topScores, $topChars) = scoreSingleByteXORStrings($encrypted, $englishLanguageWeights);

    print "Highest scoring strings indexes and characters:\n";

    $i = 0;
    foreach ($topScores as $k => $v) {
        $c = $topChars[$k];
        print "$k - $c - $v\n";

        if (++$i === 3) {
            break;
        }
    }

    print "\nDecrypted strings:\n";

    $i = 0;
    foreach ($topScores as $k => $v) {
        $encryptedLen = strlen($encrypted[$k]);
        $decypted = $encrypted[$k] ^ str_repeat(chr($topChars[$k]), $encryptedLen);
        print  "$k: $decypted\n\n";

        if (++$i === 3) {
            break;
        }
    }
}

