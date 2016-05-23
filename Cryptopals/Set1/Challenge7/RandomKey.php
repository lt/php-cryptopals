<?php declare(strict_types = 1);

namespace Cryptopals\Set1\Challenge7;

use AES\Key;

class RandomKey extends Key
{
    private $generated = false;

    function __construct() {}

    function newKey()
    {
        $this->generated = true;
        parent::__construct(random_bytes(16));
    }

    function bits(): int
    {
        if (!$this->generated) {
            $this->newKey();
        }

        return parent::bits();
    }

    function encryptionKey(): array
    {
        if (!$this->generated) {
            $this->newKey();
        }

        return parent::encryptionKey();
    }

    function decryptionKey(): array
    {
        if (!$this->generated) {
            $this->newKey();
        }

        return parent::decryptionKey();
    }
}
