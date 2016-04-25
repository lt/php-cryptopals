<?php declare(strict_types = 1);

namespace Cryptopals\Set2\Challenge9;

class PKCS7
{
    function pad(string $message): string
    {
        return $message . $this->getPadding($message);
    }

    function getPadding(string $message, int $requiredLen = 16): string
    {
        $requiredLen = $requiredLen - (strlen($message) % $requiredLen);
        return str_repeat(chr($requiredLen), $requiredLen);
    }
}
