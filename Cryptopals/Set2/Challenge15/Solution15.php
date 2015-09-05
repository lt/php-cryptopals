<?php declare(strict_types = 1);

namespace Cryptopals\Set2\Challenge15;

use Cryptopals\Set2\Challenge9\Solution9;

class Solution15 extends Solution9
{
    protected function getPKCS7Len($data): int
    {
        $dataLen = strlen($data);
        $padChar = $data[$dataLen - 1];
        $padLen = ord($padChar);

        if ($padLen > $dataLen || $padLen === 0) {
            throw new \Exception('Invalid padding');
        }

        for ($i = $dataLen - $padLen; $i < $dataLen; $i++) {
            if ($data[$i] !== $padChar) {
                throw new \Exception('Invalid padding');
            }
        }

        return $padLen;
    }

    protected function removePKCS7Padding($data)
    {
        $padLen = $this->getPKCS7Len($data);
        if ($padLen) {
            return substr($data, 0, -$padLen);
        }
        return $data;
    }

    protected function execute(): bool
    {
        $success = 1;

        try {
            $success &= ($this->getPKCS7Len("ICE ICE BABY\x04\x04\x04\x04") === 4);
        }
        catch (\Exception $e) {
            $success &= false;
        }

        try {
            $this->getPKCS7Len("ICE ICE BABY\x05\x05\x05\x05");
            $success &= false;
        }
        catch (\Exception $e) {
            $success &= true;
        }

        try {
            $this->getPKCS7Len("ICE ICE BABY\x01\x02\x03\x04");
            $success &= false;
        }
        catch (\Exception $e) {
            $success &= true;
        }

        return (bool)$success;
    }
}
