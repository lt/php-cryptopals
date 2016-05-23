<?php declare(strict_types = 1);

namespace Cryptopals\Set3\Challenge17;

use Cryptopals\Set2\Challenge15\PKCS7;
use Cryptopals\Solution;

class Solution17 implements Solution
{
    protected $paddingOracle;
    
    function __construct(PaddingOracle $paddingOracle)
    {
        $this->paddingOracle = $paddingOracle;
    }

    protected function crackBlock(string $block, string $iv): string
    {
        $fauxBlock = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        $realBlock = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        for ($attackPosition = 15; $attackPosition >= 0; $attackPosition--) {
            for ($trialByte = 0; $trialByte < 256; $trialByte++) {
                $fauxBlock[$attackPosition] = $trialByte;

                if ($this->paddingOracle->validCiphertext($block, pack('C16', ...$fauxBlock))) {
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

    function execute(): bool
    {
        print "Cracking 10 randomly selected ciphertexts:\n";

        for ($j = 0; $j < 10; $j++) {
            $ciphertext = $this->paddingOracle->getRandomCiphertext();

            $blocks = str_split($ciphertext, 16);
            $blockNum = count($blocks) - 1;

            for ($i = $blockNum; $i > 0; $i--) {
                $blocks[$i] = $this->crackBlock($blocks[$i], $blocks[$i - 1]);
            }

            array_shift($blocks);

            print "$j: " . PKCS7::depad(implode($blocks)) . "\n";
        }

        return true;
    }
}
