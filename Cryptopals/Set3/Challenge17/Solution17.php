<?php declare(strict_types = 1);

namespace Cryptopals\Set3\Challenge17;

use AES\CBC;
use AES\Key;
use Cryptopals\Set2\Challenge15\PKCS7;
use Cryptopals\Solution;

class Solution17 extends Solution
{
    protected $cbc;
    protected $pkcs7;

    protected $key;
    protected $iv;

    protected $texts = [
        'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
        'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
        'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
        'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
        'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
        'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
        'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
        'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
        'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
        'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
    ];

    protected function setUp(): bool
    {
        $this->cbc = new CBC;
        $this->pkcs7 = new PKCS7;

        return true;
    }

    protected function getRandomCiphertext(): string
    {
        $this->key = new Key(random_bytes(16));
        $iv = random_bytes(16);

        $text = base64_decode($this->texts[mt_rand(0, 9)]);
        return $iv . $this->cbc->encrypt($this->key, $iv, $this->pkcs7->pad($text));
    }

    protected function validPadding(string $ciphertext, string $iv): bool
    {
        try {
            $plaintext = $this->cbc->decrypt($this->key, $iv, $ciphertext);
            $this->pkcs7->getPaddingLength($plaintext);

            return true;
        }
        catch (\Exception $e) {
            return false;
        }
    }

    protected function crackBlock(string $block, string $iv): string
    {
        $fauxBlock = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        $realBlock = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        for ($attackPosition = 15; $attackPosition >= 0; $attackPosition--) {
            for ($trialByte = 0; $trialByte < 256; $trialByte++) {
                $fauxBlock[$attackPosition] = $trialByte;

                if ($this->validPadding($block, pack('C16', ...$fauxBlock))) {
                    // 1 in 65536 chance that we got 0x02 0x02 rather than 0x?? 0x01 - I'll take that risk!

                    $currentPadding = 16 - $attackPosition;
                    $realBlock[$attackPosition] = $currentPadding ^ $trialByte ^ ord($iv[$attackPosition]);

                    if ($attackPosition === 0) {
                        break 2;
                    }

                    for ($j = 15; $j >= $attackPosition; $j--) {
                        $fauxBlock[$j] = ($currentPadding + 1) ^ $realBlock[$j] ^ ord($iv[$j]);
                    }

                    break;
                }
            }
        }

        return pack('C16', ...$realBlock);
    }

    protected function execute(): bool
    {
        print "Cracking 10 randomly selected ciphertexts:\n";

        for ($j = 0; $j < 10; $j++) {
            $ciphertext = $this->getRandomCiphertext();

            $blocks = str_split($ciphertext, 16);
            $blockNum = count($blocks) - 1;

            for ($i = $blockNum; $i > 0; $i--) {
                $blocks[$i] = $this->crackBlock($blocks[$i], $blocks[$i - 1]);
            }

            array_shift($blocks);

            print "$j: " . $this->pkcs7->depad(implode($blocks)) . "\n";
        }

        return true;
    }
}
