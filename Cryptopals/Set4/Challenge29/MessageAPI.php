<?php declare(strict_types = 1);

namespace Cryptopals\Set4\Challenge29;

use Cryptopals\Set4\Challenge28\SHA1KeyedMAC;

class MessageAPI
{
    protected $keyedMAC;
    protected $key;
    
    function __construct(SHA1KeyedMAC $keyedMAC)
    {
        $this->keyedMAC = $keyedMAC;
        $this->key = random_bytes(mt_rand(8, 32));
    }

    function sign(string $message): string
    {
        return $this->keyedMAC->mac($this->key, $message);
    }

    function verify(string $message, string $mac): bool
    {
        return hash_equals($mac, $this->sign($message));
    }
}
