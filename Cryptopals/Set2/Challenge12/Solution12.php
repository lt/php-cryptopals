<?php declare(strict_types = 1);

namespace Cryptopals\Set2\Challenge12;

use AES\ECB;
use Cryptopals\Set1\Challenge7\RandomKey;
use Cryptopals\Set1\Challenge8\DetectECB;
use Cryptopals\Set2\Challenge9\PKCS7;
use Cryptopals\Solution;

class Solution12 implements Solution
{
    protected $ecb;
    protected $key;
    
    function __construct(ECB $ecb, RandomKey $key)
    {
        $this->ecb = $ecb;
        $this->key = $key;
    }

    protected function oracle(string $myString): string
    {
        $unknownString = base64_decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK');
        $message = $myString . $unknownString;

        return $this->ecb->encrypt($this->key, PKCS7::pad($message));
    }

    protected function detectBlockSize(): int
    {
        $firstLen = strlen($this->oracle('a'));

        $i = 1;
        do {
            $currentLen = strlen($this->oracle(str_repeat('a', ++$i)));
        }
        while ($firstLen === $currentLen);

        return $currentLen - $firstLen;
    }

    protected function buildDictionary(string $prefix, int $blockSize): array
    {
        $allInOneGo = $prefix . implode($prefix, range("\x00", "\xff"));

        return array_flip(
            str_split(
                substr($this->oracle($allInOneGo), 0, $blockSize * 256),
                $blockSize
            )
        );
    }

    protected function crackBlock(string $prefix, int $blockSize, int $blockIndex): string
    {
        $plaintext = '';

        for ($i = 1; $i <= $blockSize; $i++) {
            $prefix = substr($prefix, 1);
            $dict = $this->buildDictionary($prefix . $plaintext, $blockSize);
            $lookup = substr($this->oracle($prefix), $blockIndex * $blockSize, $blockSize);
            if (!isset($dict[$lookup])) {
                return $plaintext;
            }
            $char = chr($dict[$lookup]);

            $plaintext .= $char;
        }

        return $plaintext;
    }

    function execute(): bool
    {
        $blockSize = $this->detectBlockSize();
        print "Block size: {$blockSize}\n";

        $ecb = DetectECB::repeatedBlockCount($this->oracle(str_repeat('a', 100))) > 0;
        print "ECB mode: ";
        print ($ecb ? "Yes\n" : "No...\n");

        $blocksToCrack = strlen($this->oracle('')) / $blockSize;
        print "{$blocksToCrack} blocks to crack\n\n";

        $lastBlock = str_repeat('A', $blockSize);
        for ($i = 0; $i < $blocksToCrack; $i++) {
            $lastBlock = $this->crackBlock($lastBlock, $blockSize, $i);
            print $lastBlock;
        }
        print "\n";

        return true;
    }
}
