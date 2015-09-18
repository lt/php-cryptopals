<?php declare(strict_types = 1);

namespace Cryptopals\Set5\Challenge37;

use Cryptopals\Set5\Challenge36\SRPClient;

class SRPClientAmulN extends SRPClient
{
    function __construct(string $I, string $P, int $mul)
    {
        parent::__construct($I, $P);

        $this->A = gmp_strval(gmp_mul($this->N, $mul), 16);
    }

    function getK(): string
    {
        return hash('sha256', '0');
    }

    function getProof(): string
    {
        return hash_hmac('sha256', $this->getK(), $this->salt);
    }
}

