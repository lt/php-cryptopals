<?php declare(strict_types = 1);

namespace Cryptopals\Set2\Challenge10;

use AES\CBC;
use Cryptopals\Set1\Challenge7\YellowSubmarineKey;
use Cryptopals\Solution;

class Solution10 implements Solution
{
    protected $cbc;
    protected $key;

    // This uses my own AES library
    // Technically I completed this challenge elsewhere
    function __construct(CBC $ecb, YellowSubmarineKey $key)
    {
        $this->cbc = $ecb;
        $this->key = $key;
    }

    function execute(): bool
    {
        $iv = str_repeat("\0", 16);

        $encrypted = base64_decode(file_get_contents(__DIR__ . '/10.txt'));
        $decrypted = $this->cbc->decrypt($this->key, $iv, $encrypted);

        print "Decrypted data:\n";
        print "{$decrypted}\n";

        return $this->cbc->encrypt($this->key, $iv, $decrypted) === $encrypted;
    }
}
