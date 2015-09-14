<?php declare(strict_types = 1);

namespace Cryptopals\Set4\Challenge26;

use Cryptopals\Set3\Challenge18\Solution18;

class Solution26 extends Solution18
{
    protected function setUp(): bool
    {
        $this->ecb = new \AES\Mode\ECB();
        $this->ctx = new \AES\Context\ECB(random_bytes(16));
        $this->pad = new \AES\Padding\PKCS7();

        return true;
    }

    protected function getQuery(string $userData): string
    {
        $data = http_build_query(
            [
                'comment1' => 'cooking MCs',
                'userdata' => $userData,
                'comment2' => ' lke a pound of bacon'
            ],
            '', ';', PHP_QUERY_RFC3986
        );

        return $this->encrypt($data);
    }

    protected function isAdmin(string $query): bool
    {
        $data = $this->decrypt($query);

        return strpos($data, ';admin=true;') !== false;
    }

    protected function execute(): bool
    {
        // 0..............f|0..............f|0..............f|0..............f|0..............f
        // comment1=cooking|%20MCs;userdata=
        //                 |                |bbbb;admin=true |
        //                                                  ;|comment2=%20like%20a%20pound%20of%20bacon

        $badData = 'bbbb;admin=true';
        $goodData = 'bbbbbbbbbbbbbbb';
        $diff = $badData ^ $goodData;

        $query = $this->getQuery($goodData);

        $query = substr($query, 0, 32) . (substr($query, 32, 15) ^ $diff) . substr($query, 47);

        return $this->isAdmin($query);
    }
}
