<?php

/*
 * http://cryptopals.com/sets/2/challenges/12/
 *
 * Byte-at-a-time ECB decryption (Harder)
 *
 * Take your oracle function from #12. Now generate a random count of random bytes and prepend this string to every plaintext. You are now doing:
 * AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
 *
 * Same goal: decrypt the target-bytes.
 *
 * Stop and think for a second.
 * What's harder than challenge #12 about doing this? How would you overcome that obstacle? The hint is: you're using all the tools you already have; no crazy math is required.
 * Think "STIMULUS" and "RESPONSE".
 */

/*
 * My thoughts on what makes the challenge harder and how to overcome this:
 *
 * The random length prefix means you don't know where your chosen plaintext resides, and it may not be block aligned.
 * To overcome this I am using a sentinel value exploiting the weakness of ECB.
 *
 * A a sentinel plaintext repeated 5 times, and the same block ciphertext detected 5 times in a row gives you a marker.
 * Prepending a single sentinel plaintext to your chosen prefix will tell you when your prefix is block aligned, and
 * where abouts in the ciphertext it resides.
 *
 * All non-aligned results can be discarded and then solved the same as challenge 12 by chopping off the
 * superfluous blocks at the start.
 */

require_once '../utils/random-bytes.php';
require_once '../01-basics/07-aes-in-ecb-mode.php';
require_once '../01-basics/08-detect-aes-in-ecb-mode.php';

$lastX = 0;
function unknownStringThing($myString, $key)
{
    $unknownString = base64_decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK');
    $x = rand(1, 128);
    global $lastX;
    $lastX = $x;
    $prefix = getRandomBytes($x);
    return encryptAES128ECB($prefix . $myString . $unknownString, $key);
}

function detectBlockSize()
{
    $samples = [];

    for ($i = 0; $i < 1000; $i++) {
        $sampleLen = strlen(unknownStringThing('a', '0123456789abcdef'));

        if (isset($samples[$sampleLen])) {
            $samples[$sampleLen]++;
        }
        else {
            $samples[$sampleLen] = 1;
        }
    }

    ksort($samples);
    $one = key($samples);
    next($samples);
    $two = key($samples);

    return $two - $one;
}

function buildDictionary($prefix, $key, $blockSize, $sentinelBlock)
{
    $sentinel = implode(range("\x00", chr($blockSize - 1)));
    $allInOneGo = $sentinel . $prefix . implode($prefix, range("\x00", "\xff"));

    $trial = unknownStringThing($allInOneGo, $key);

    while (($sentinelPos = strpos($trial, $sentinelBlock)) === false && ($sentinelPos % $blockSize === 0)) {
        $trial = unknownStringThing($allInOneGo, $key);
    }

    return array_flip(
        str_split(
            substr($trial, $sentinelPos + $blockSize, $blockSize * 256),
            $blockSize
        )
    );
}

function findSentinelBlock($key, $blockSize)
{
    do {
        $ciphertext = unknownStringThing(str_repeat(implode(range("\x00", chr($blockSize - 1))), 5), $key);
        $cipherLen = strlen($ciphertext);

        $repetitions = [];

        for ($i = 0; $i < $cipherLen; $i += $blockSize) {
            $block = substr($ciphertext, $i, $blockSize);
            $repetition = strpos($ciphertext, $block, $i + $blockSize);

            if ($repetition && $repetition % $blockSize === 0) {
                if (isset($repetitions[$block])) {
                    $repetitions[$block]++;
                }
                else {
                    $repetitions[$block] = 1;
                }
            }
        }
    }
    while (max($repetitions) !== 4);

    asort($repetitions);
    return key($repetitions);
}

function crackBlock($prefix, $key, $blockSize, $blockIndex, $sentinelBlock)
{
    $plaintext = '';
    $sentinel = implode(range("\x00", chr($blockSize - 1)));

    for ($i = 1; $i <= $blockSize; $i++) {
        $prefix = substr($prefix, 1);

        $dict = buildDictionary($prefix . $plaintext, $key, $blockSize, $sentinelBlock);
        $trial = unknownStringThing($sentinel . $prefix, $key);

        while (($sentinelPos = strpos($trial, $sentinelBlock)) === false && (($sentinelPos % $blockSize) === 0)) {
            $trial = unknownStringThing($sentinel . $prefix, $key);
        }

        $lookup = substr($trial, ($sentinelPos + $blockSize) + ($blockIndex * $blockSize), $blockSize);

        if (!isset($dict[$lookup])) {
            return $plaintext;
        }

        $char = chr($dict[$lookup]);
        $plaintext .= $char;
        print $char;

    }
    return $plaintext;
}

// don't output if we're included into another script.
if (!debug_backtrace()) {
    $key = getRandomBytes(16);

    $blockSize = detectBlockSize();
    print "Block size:\n$blockSize\n\n";

    $ecb = repeatedBlockCount(unknownStringThing(str_repeat('a', 100), '0123456789abcdef')) > 0;
    print "ECB mode:\n";
    print $ecb ? "Yes\n\n" : "No...\n\n";

    $sentinelBlock = findSentinelBlock($key, $blockSize);
    print "Sentinel:\n";
    print bin2hex($sentinelBlock) . "\n\n";

    $lastBlock = str_repeat('A', $blockSize);
    $i = 0;
    while ($lastBlock) {
        $lastBlock = crackBlock($lastBlock, $key, $blockSize, $i++, $sentinelBlock);
    }
}
