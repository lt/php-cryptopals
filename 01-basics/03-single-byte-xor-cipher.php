<?php

/*
 * http://cryptopals.com/sets/1/challenges/3/
 *
 * Single-byte XOR cipher
 *
 * The hex encoded string:
 * 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
 *
 * ... has been XOR'd against a single character. Find the key, decrypt the message.
 *
 * You can do this by hand. But don't: write code to do it for you.
 *
 * How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.
 *
 * Achievement Unlocked
 * You now have our permission to make "ETAOIN SHRDLU" jokes on Twitter.
 */

// from https://en.wikipedia.org/wiki/Letter_frequency
$englishLanguageWeights = [
    'e' => 13.0001,
    't' => 9.056,
    'a' => 8.167,
    'o' => 7.507,
    'i' => 6.966,
    'n' => 6.749,
    's' => 6.327,
    'h' => 6.094,
    'r' => 5.987,
    'd' => 4.253,
    'l' => 4.025,
    'c' => 2.782,
    'u' => 2.758,
    'm' => 2.406,
    'w' => 2.360,
    'f' => 2.228,
    'g' => 2.015,
    'y' => 1.974,
    'p' => 1.929,
    'b' => 1.492,
    'v' => 0.978,
    'k' => 0.772,
    'j' => 0.153,
    'x' => 0.150,
    'q' => 0.095,
    'z' => 0.074,
];

/*
 * more from https://en.wikipedia.org/wiki/Letter_frequency
 *
 * "In English, the space is slightly more frequent than the top letter (e)
 * and the non-alphabetic characters (digits, punctuation, etc.) collectively
 * occupy the fourth position, between t and a."
 */

$englishLanguageWeights += [
    ' ' => 13.1,
    '0' => 8.4,
    '1' => 8.4,
    '2' => 8.4,
    '3' => 8.4,
    '4' => 8.4,
    '5' => 8.4,
    '6' => 8.4,
    '7' => 8.4,
    '8' => 8.4,
    '9' => 8.4,
    '\'' => 8.4,
    '"' => 8.4,
    '.' => 8.4,
    ',' => 8.4,
    '!' => 8.4,
    '?' => 8.4,
];

function scoreSingleByteXOR($encrypted, array $weights, $penalty = 0)
{
    $encryptedLen = strlen($encrypted);

    $scores = [];

    for ($i = 0; $i < 256; $i++) {
        $score = 0;
        $trial = $encrypted ^ str_repeat(chr($i), $encryptedLen);

        for ($j = 0; $j < $encryptedLen; $j++) {
            $char = $trial[$j];
            if (isset($weights[$char])) {
                $score += $weights[$char];
            }
            else {
                $score -= $penalty;
            }
        }

        $scores[$i] = $score;
    }

    arsort($scores);
    return $scores;
}

// don't output if we're included into another script.
if (!debug_backtrace()) {
    $encrypted = hex2bin('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736');
    $encryptedLen = strlen($encrypted);

    $scores = scoreSingleByteXOR($encrypted, $englishLanguageWeights);

    print "Highest scoring character codes:\n";

    $i = 0;
    foreach ($scores as $k => $v) {
        print "$k - $v\n";

        if (++$i === 3) {
            break;
        }
    }

    print "\nDecrypted strings:\n";

    $i = 0;
    foreach ($scores as $k => $v) {
        $decypted = $encrypted ^ str_repeat(chr($k), $encryptedLen);
        print  "$k: $decypted\n";

        if (++$i === 3) {
            break;
        }
    }

}
