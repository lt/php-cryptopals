<?php declare(strict_types = 1);

namespace Cryptopals\Set3\Challenge18;

use AES\Key;
use Cryptopals\Solution;

class Solution18 extends Solution
{
    protected function execute(): bool
    {
        $ctr = new AESCTR;
        $key = new Key('YELLOW SUBMARINE');

        $ciphertext = base64_decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==');

        $plaintext = $ctr->decrypt($key, str_repeat("\0", 8), $ciphertext);
        $homebrewCipher = $ctr->encrypt($key, str_repeat("\0", 8), $plaintext);

        print "Decrypted data:\n";
        print "$plaintext\n";
        
        return $ciphertext === $homebrewCipher;
    }
}
