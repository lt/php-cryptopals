<?php declare(strict_types = 1);

namespace Cryptopals\Set2\Challenge11;

use AES\CBC;
use AES\ECB;
use Cryptopals\Set1\Challenge7\RandomKey;
use Cryptopals\Set1\Challenge8\DetectECB;
use Cryptopals\Set2\Challenge9\PKCS7;
use Cryptopals\Solution;

class Solution11 implements Solution
{
    protected $ecb;
    protected $cbc;
    protected $key;

    function __construct(ECB $ecb, CBC $cbc, RandomKey $key)
    {
        $this->ecb = $ecb;
        $this->cbc = $cbc;
        $this->key = $key;
    }

    protected function randomlyEncryptECBorCBC(string $data)
    {
        $this->key->newKey();
        $iv = str_repeat("\0", 16);

        $pad1 = random_bytes(mt_rand(5, 10));
        $pad2 = random_bytes(mt_rand(5, 10));

        $message = "$pad1$data$pad2";

        if (mt_rand(0, 1)) {
            return $this->cbc->encrypt($this->key, $iv, PKCS7::pad($message));
        }

        return $this->ecb->encrypt($this->key, PKCS7::pad($message));
    }

    function execute(): bool
    {
        // so the trick is to feed the black box something that will trigger ECBs weakness regardless of padding
        // this means we need at least 3 blocks of repeated data (with padding this reduces to 2 blocks)
        $plaintext = str_repeat('a', 48);

        print "Running 5000 samples\n";
        $ecb = 0;
        for ($i = 0; $i < 5000; $i++) {
            $ciphertext = $this->randomlyEncryptECBorCBC($plaintext);
            if (DetectECB::repeatedBlockCount($ciphertext)) {
                $ecb++;
            }
        }
        print "{$ecb} samples detected as ECB mode\n";

        return $ecb && round(5000 / $ecb) === 2.0;
    }
}
