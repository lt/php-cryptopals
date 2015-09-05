<?php declare(strict_types = 1);

namespace Cryptopals\Set2\Challenge9;

use Cryptopals\Solution;

class Solution9 extends Solution
{
    protected function addPKCS7Padding(string $data, int $padTo = 16): string
    {
        $dataLen = strlen($data);
        $padLen = $padTo - ($dataLen % $padTo);

        return $data . str_repeat(chr($padLen), $padLen);
    }

    protected function execute(): bool
    {
        $success = 1;

        $success &= $this->addPKCS7Padding('YELLOW SUBMARINE', 20) === "YELLOW SUBMARINE\x04\x04\x04\x04";
        $success &= $this->addPKCS7Padding('YELLOW SUBMARINE', 10) === "YELLOW SUBMARINE\x04\x04\x04\x04";
        $success &= $this->addPKCS7Padding('YELLOW SUBMARINE', 6) === "YELLOW SUBMARINE\x02\x02";
        // make sure a full block of padding is added when the data length is a multiple of the pad length
        $success &= $this->addPKCS7Padding('YELLOW SUBMARINE', 8) === "YELLOW SUBMARINE\x08\x08\x08\x08\x08\x08\x08\x08";
        $success &= $this->addPKCS7Padding('', 4) === "\x04\x04\x04\x04";

        return (bool)$success;
    }
}
