<?php declare(strict_types = 1);

namespace Cryptopals\Set3\Challenge17;

use Cryptopals\Set2\Challenge15\Solution15;

class Solution17 extends Solution15
{
    protected $cbc;
    protected $encCtx;
    protected $decCtx;
    protected $pad;

    protected function setUp(): bool
    {
        $this->cbc = new \AES\Mode\CBC();
        $this->pad = new \AES\Padding\PKCS7();

        return true;
    }

    protected function getRandomCiphertext(): string
    {
        $texts = [
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

        $texts = array_map('base64_decode', $texts);
        $text = $texts[mt_rand(0,9)];

        return $this->cbc->encrypt($this->encCtx, $text . $this->pad->getPadding($text));
    }

    protected function validPadding(string $ciphertext, string $iv): bool
    {
        try {
            $ctx = clone $this->decCtx;
            $ctx->IV = array_values(unpack('N4', $iv));

            $plaintext = $this->cbc->decrypt($ctx, $ciphertext);
            $this->getPKCS7Len($plaintext);
            
            return true;
        }
        catch (\Exception $e) {
            return false;
        }
    }
    
    protected function crackBlock(string $block, string $iv)
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
            $key = random_bytes(16);
            $iv = random_bytes(16);

            $this->encCtx = new \AES\Context\CBC($key, $iv);
            $this->decCtx = new \AES\Context\CBC($key, $iv);

            $ciphertext = $this->getRandomCiphertext();

            $blocks = str_split($ciphertext, 16);
            array_unshift($blocks, $iv);
            $blockNum = count($blocks) - 1;

            for ($i = $blockNum; $i > 0; $i--) {
                $blocks[$i] = $this->crackBlock($blocks[$i], $blocks[$i - 1]);
            }

            array_shift($blocks);

            print "$j: " . $this->removePKCS7Padding(implode($blocks)) . "\n";
        }

        return true;
    }
}
