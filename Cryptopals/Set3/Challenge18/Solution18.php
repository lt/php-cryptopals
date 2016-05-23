<?php declare(strict_types = 1);

namespace Cryptopals\Set3\Challenge18;

use Cryptopals\Set1\Challenge7\YellowSubmarineKey;
use Cryptopals\Solution;

class Solution18 implements Solution
{
    protected $ctr;
    protected $key;

    function __construct(AESCTR $ctr, YellowSubmarineKey $key)
    {
        $this->ctr = $ctr;
        $this->key = $key;
    }

    function execute(): bool
    {
        $ciphertext = base64_decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==');

        $plaintext = $this->ctr->decrypt($this->key, str_repeat("\0", 8), $ciphertext);
        $homebrewCipher = $this->ctr->encrypt($this->key, str_repeat("\0", 8), $plaintext);

        print "Decrypted data:\n";
        print "$plaintext\n";
        
        return $ciphertext === $homebrewCipher;
    }
}
