<?php declare(strict_types = 1);

namespace Cryptopals\Set2\Challenge11;

use AES\CBC;
use AES\ECB;
use AES\Key;
use Cryptopals\Set1\Challenge8\Solution8;
use Cryptopals\Set2\Challenge9\PKCS7;

class Solution11 extends Solution8
{
    protected $ecb;
    protected $cbc;
    protected $pkcs7;

    protected function setUp(): bool
    {
        $this->ecb = new ECB;
        $this->cbc = new CBC;
        $this->pkcs7 = new PKCS7;

        return true;
    }

    protected function randomlyEncryptECBorCBC(string $data)
    {
        $key = new Key(random_bytes(16));
        $iv = str_repeat("\0", 16);

        $pad1 = random_bytes(mt_rand(5, 10));
        $pad2 = random_bytes(mt_rand(5, 10));

        $message = "$pad1$data$pad2";

        if (mt_rand(0, 1)) {
            return $this->cbc->encrypt($key, $iv, $this->pkcs7->pad($message));
        }

        return $this->ecb->encrypt($key, $this->pkcs7->pad($message));
    }

    protected function execute(): bool
    {
        // so the trick is to feed the black box something that will trigger ECBs weakness regardless of padding
        // this means we need at least 3 blocks of repeated data (with padding this reduces to 2 blocks)
        $plaintext = str_repeat('a', 48);

        print "Running 5000 samples\n";
        $ecb = 0;
        for ($i = 0; $i < 5000; $i++) {
            $ciphertext = $this->randomlyEncryptECBorCBC($plaintext);
            if ($this->repeatedBlockCount($ciphertext)) {
                $ecb++;
            }
        }
        print "{$ecb} samples detected as ECB mode\n";

        return $ecb && round(5000 / $ecb) === 2.0;
    }
}
