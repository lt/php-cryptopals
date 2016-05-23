<?php declare(strict_types = 1);

namespace Cryptopals\Set1\Challenge7;

use AES\ECB;
use Cryptopals\Solution;

class Solution7 implements Solution
{
    protected $ecb;
    protected $key;

    // This uses my own AES library
    // Technically I completed this challenge elsewhere
    function __construct(ECB $ecb, YellowSubmarineKey $key)
    {
        $this->ecb = $ecb;
        $this->key = $key;
    }

    function execute(): bool
    {
        $encrypted = base64_decode(file_get_contents(__DIR__ . '/7.txt'));
        $decrypted = $this->ecb->decrypt($this->key, $encrypted);

        print "Decrypted data:\n";
        print "{$decrypted}\n";

        return $this->ecb->encrypt($this->key, $decrypted) === $encrypted;
    }
}
