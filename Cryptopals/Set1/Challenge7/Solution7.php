<?php declare(strict_types = 1);

namespace Cryptopals\Set1\Challenge7;

use AES\ECB;
use AES\Key;
use Cryptopals\Solution;

class Solution7 extends Solution
{
    protected function execute(): bool
    {
        // This uses my own AES library
        // Technically I completed this challenge elsewhere
        $ecb = new ECB;
        $key = new Key('YELLOW SUBMARINE');
        
        $encrypted = base64_decode(file_get_contents(__DIR__ . '/7.txt'));
        $decrypted = $ecb->decrypt($key, $encrypted);

        print "Decrypted data:\n";
        print "{$decrypted}\n";

        return $ecb->encrypt($key, $decrypted) === $encrypted;
    }
}
