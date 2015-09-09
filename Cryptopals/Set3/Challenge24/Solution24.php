<?php declare(strict_types = 1);

namespace Cryptopals\Set3\Challenge24;

use Cryptopals\Set3\Challenge21\Solution21;

class Solution24 extends Solution21
{
    function encrypt($data, $seed = 0)
    {
        $seed &= 0xffff;

        $this->init($seed);

        $dataLen = strlen($data);
        $blocks = ceil($dataLen / 4);
        $keyStream = [];

        while ($blocks--) {
            $keyStream[] = $this->int32();
        }

        return $data ^ pack('N*', ...$keyStream);
    }

    function encryptWithRandomPad($data, $seed = 0)
    {
        return $this->encrypt(random_bytes(mt_rand(1,20)) . $data, $seed);
    }

    protected function execute(): bool
    {
        $plaintext = 'the matasano crypto challenges';
        $sanity = $this->encrypt($this->encrypt($plaintext)) === $plaintext;

        $secretSeed = mt_rand(0, 0xffff);
        $plaintext = str_repeat('A', 14);
        $ciphertext = $this->encryptWithRandomPad($plaintext, $secretSeed);

        $plainLen = strlen($plaintext);

        for ($i = 0; $i < 0xffff; $i++) {
            if ($i % 820 == 0) {
                print '.';
            }

            if (substr($this->encrypt($ciphertext, $i), -$plainLen) === $plaintext) {
                print "\n\nSeed was: $i\n";
                break;
            }
        }

        return $sanity;
    }
}
