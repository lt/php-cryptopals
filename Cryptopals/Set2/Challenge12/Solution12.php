<?php declare(strict_types = 1);

namespace Cryptopals\Set2\Challenge12;

use AES\ECB;
use AES\Key;
use Cryptopals\Set1\Challenge8\Solution8;
use Cryptopals\Set2\Challenge9\PKCS7;

class Solution12 extends Solution8
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
        $message = $myString . $unknownString;

        return $this->ecb->encrypt($this->key, $this->pkcs7->pad($message));
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

    protected function execute(): bool
    {
        $blockSize = $this->detectBlockSize();
        print "Block size: {$blockSize}\n";

        $ecb = $this->repeatedBlockCount($this->oracle(str_repeat('a', 100))) > 0;
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
