<?php

/*
 * http://cryptopals.com/sets/1/challenges/6/
 *
 * Break repeating-key XOR
 *
 * It is officially on, now.
 * This challenge isn't conceptually hard, but it involves actual error-prone coding. The other challenges in this set are there to bring you up to speed. This one is there to qualify you. If you can do this one, you're probably just fine up to Set 6.
 *
 * There's a file here. It's been base64'd after being encrypted with repeating-key XOR.
 *
 * Decrypt it.
 *
 * Here's how:
 *
 * 1. Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
 *
 * 2. Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:
 * this is a test
 * and
 * wokka wokka!!!
 * is 37. Make sure your code agrees before you proceed.
 *
 * 3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
 *
 * 4. The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
 *
 * 5. Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
 *
 * 6. Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
 *
 * 7. Solve each block as if it was single-character XOR. You already have code to do this.
 *
 * 8. For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.
 *
 * This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing. But more people "know how" to break it than can actually break it, and a similar technique breaks something much more important.
 *
 * No, that's not a mistake.
 * We get more tech support questions for this challenge than any of the other ones. We promise, there aren't any blatant errors in this text. In particular: the "wokka wokka!!!" edit distance really is 37.
 */

require_once '04-detect-single-character-xor.php';

// popcount the diff (xor) bits between two strings
function hammingDistance($one, $two)
{
    // easier to popcount strings if we convert them into ints
    $diffs = unpack('S*', $one ^ $two);
    $count = 0;

    foreach ($diffs as $diff) {
        while ($diff) {
            $diff &= $diff - 1;
            $count++;
        }
    }

    return $count;
}

function scoreHammedKeySizeRange($data, $lowKeySize, $highKeySize, $sampleLimit = 0)
{
    $dataLen = strlen($data);
    $scores = [];

    for($keyLen = $lowKeySize; $keyLen <= $highKeySize; $keyLen++) {
        $maxBlocks = (int)($dataLen / $keyLen);

        $samples = 0;
        $score = 0;
        for ($sampleOneIndex = 0; $sampleOneIndex < $maxBlocks; $sampleOneIndex++) {
            for ($sampleTwoIndex = 0; $sampleTwoIndex < $maxBlocks; $sampleTwoIndex++) {
                if ($sampleOneIndex !== $sampleTwoIndex) {
                    $one = substr($data, $sampleOneIndex * $keyLen, $keyLen);
                    $two = substr($data, $sampleTwoIndex * $keyLen, $keyLen);
                    $score += hammingDistance($one, $two);
                    $samples++;
                    if ($sampleLimit && $samples === $sampleLimit) {
                        break 2;
                    }
                }
            }
        }
        $scores[$keyLen] = $score / $keyLen / $samples;
    }

    asort($scores);
    return $scores;
}

function transposeBlocks(array $blocks)
{
    $blockLens = array_map('strlen', $blocks);
    $blocks = array_map('str_split', $blocks);
    $iterations = max($blockLens);
    $newBlocks = [];

    for ($i = 0; $i < $iterations; $i++) {
        $newBlocks[] = array_column($blocks, $i);
    }

    return array_map('implode', $newBlocks);
}

// don't output if we're included into another script.
if (!debug_backtrace()) {
    $data = base64_decode(file_get_contents('06-data.txt'));
    $dataLen = strlen($data);

    print "Sanity check hamming function\n";
    $sanity = hammingDistance('this is a test', 'wokka wokka!!!') === 37;
    print $sanity ? "Success!\n\n" : "Failure :(\n\n";

    print "This will take a while. Hold on!\n\n";
    $scores = scoreHammedKeySizeRange($data, 2, 40, 10000); // 10k sample limit to reduce time taken

    print "Top scoring key sizes:\n";
    $i = 0;
    foreach ($scores as $k => $v) {
        print "$k - $v\n";

        if (++$i === 3) {
            break;
        }
    }

    $potentialKeys = [];

    print "\nSolving keys based on English Language scoring:\n";
    $i = 0;
    foreach ($scores as $k => $v) {
        $blocks = str_split($data, $k);
        $blocks = transposeBlocks($blocks);

        list($topScores, $topChars) = scoreSingleByteXORStrings($blocks, $englishLanguageWeights);

        $potentialKeys[$k] = implode(array_map('chr', $topChars));
        print "$k: {$potentialKeys[$k]}\n";

        if (++$i === 3) {
            break;
        }
    }

    print "\nDecrypted data with solved keys:\n";
    $i = 0;
    foreach ($scores as $k => $v) {
        $decrypted = $data ^ str_repeat($potentialKeys[$k], ceil($dataLen / strlen($potentialKeys[$k])));

        print "$k: $decrypted\n\n\n";

        if (++$i === 3) {
            break;
        }
    }
}
