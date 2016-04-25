<?php declare(strict_types = 1);

/*
 * My thoughts on what makes the challenge harder and how to overcome this:
 *
 * The random length prefix means you don't know where your chosen plaintext resides, and it may not be block aligned.
 * To overcome this I am using a sentinel value exploiting the weakness of ECB.
 *
 * A a sentinel plaintext repeated 4 times, and the same block of ciphertext detected 2+ times in a row gives a marker.
 * Prepending a single sentinel plaintext to your chosen prefix will tell you when your prefix is block aligned, and
 * where abouts in the ciphertext it resides.
 *
 * All non-aligned results can be discarded and then solved the same as challenge 12 by chopping off the
 * superfluous blocks at the start.
 */

namespace Cryptopals\Set2\Challenge14;

use AES\ECB;
use AES\Key;
use Cryptopals\Set2\Challenge13\Solution13;
use Cryptopals\Set2\Challenge9\PKCS7;

class Solution14 extends Solution13
{
    protected $ecb;
    protected $key;
    protected $pkcs7;

    protected function setUp(): bool
    {
        $this->ecb = new ECB;
        $this->key = new Key(random_bytes(16));
        $this->pkcs7 = new PKCS7;

        return true;
    }

    protected function oracle(string $myString): string
    {
        $unknownString = base64_decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK');

        $prefix = random_bytes(mt_rand(1, 128));
        $message = $prefix . $myString . $unknownString;

        return $this->ecb->encrypt($this->key, $this->pkcs7->pad($message));
    }

    protected function detectBlockSize(): int
    {
        $samples = [];

        for ($i = 0; $i < 1000; $i++) {
            $sampleLen = strlen($this->oracle(''));

            if (isset($samples[$sampleLen])) {
                $samples[$sampleLen]++;
            }
            else {
                $samples[$sampleLen] = 1;
            }
        }
        
        // Highest block length minus second highest block length
        ksort($samples);
        $one = key($samples);
        next($samples);
        $two = key($samples);

        return $two - $one;
    }

    protected function buildDictionary(string $prefix, int $blockSize, string $sentinelBlock): array
    {
        $sentinel = implode(range("\x00", chr($blockSize - 1)));
        $allInOneGo = $sentinel . $prefix . implode($prefix, range("\x00", "\xff"));

        $trial = $this->oracle($allInOneGo);

        while (($sentinelPos = strpos($trial, $sentinelBlock)) === false && ($sentinelPos % $blockSize === 0)) {
            $trial = $this->oracle($allInOneGo);
        }

        return array_flip(
            str_split(
                substr($trial, $sentinelPos + $blockSize, $blockSize * 256),
                $blockSize
            )
        );
    }

    protected function findSentinelBlock(int $blockSize): string
    {
        do {
            $ciphertext = $this->oracle(str_repeat(implode(range("\x00", chr($blockSize - 1))), 4));
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
        while (max($repetitions) !== 3);

        asort($repetitions);
        return key($repetitions);
    }

    protected function crackBlock(string $prefix, int $blockSize, int $blockIndex, string $sentinelBlock): string
    {
        $plaintext = '';
        $sentinel = implode(range("\x00", chr($blockSize - 1)));

        for ($i = 1; $i <= $blockSize; $i++) {
            $prefix = substr($prefix, 1);

            $dict = $this->buildDictionary($prefix . $plaintext, $blockSize, $sentinelBlock);
            $trial = $this->oracle($sentinel . $prefix);

            while (($sentinelPos = strpos($trial, $sentinelBlock)) === false && (($sentinelPos % $blockSize) === 0)) {
                $trial = $this->oracle($sentinel . $prefix);
            }

            $lookup = substr($trial, ($sentinelPos + $blockSize) + ($blockIndex * $blockSize), $blockSize);

            if (!isset($dict[$lookup])) {
                return $plaintext;
            }

            $char = chr($dict[$lookup]);
            $plaintext .= $char;
        }

        return $plaintext;
    }

    protected function execute(): bool
    {
        $blockSize = $this->detectBlockSize();
        print "Block size:\n$blockSize\n\n";

        $ecb = $this->repeatedBlockCount($this->oracle(str_repeat('a', 100))) > 0;
        print "ECB mode:\n";
        print ($ecb ? "Yes\n\n" : "No...\n\n");

        $sentinelBlock = $this->findSentinelBlock($blockSize);
        print "Sentinel:\n";
        print bin2hex($sentinelBlock) . "\n\n";

        $lastBlock = str_repeat('A', $blockSize);
        $i = 0;
        while ($lastBlock) {
            $lastBlock = $this->crackBlock($lastBlock, $blockSize, $i++, $sentinelBlock);
            print $lastBlock;
        }
        print "\n";

        return true;
    }
}
