<?php declare(strict_types = 1);

namespace Cryptopals\Set2\Challenge10;

use AES\CBC;
use AES\Key;
use Cryptopals\Solution;

class Solution10 extends Solution
{
    protected function execute(): bool
    {
        // This uses my own AES library
        // Technically I completed this challenge elsewhere
        $cbc = new CBC;
        $key = new Key('YELLOW SUBMARINE');
        $iv = str_repeat("\0", 16);

        $encrypted = base64_decode(file_get_contents(__DIR__ . '/10.txt'));
        $decrypted = $cbc->decrypt($key, $iv, $encrypted);

        print "Decrypted data:\n";
        print "{$decrypted}\n";

        return $cbc->encrypt($key, $iv, $decrypted) === $encrypted;
    }
}
