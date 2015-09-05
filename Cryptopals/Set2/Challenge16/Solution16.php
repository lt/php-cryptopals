<?php declare(strict_types = 1);

namespace Cryptopals\Set2\Challenge16;

use Cryptopals\Solution;

class Solution16 extends Solution
{
    protected $cbc;
    protected $encCtx;
    protected $decCtx;
    protected $pad;

    protected function setUp(): bool
    {
        $key = random_bytes(16);
        $iv = random_bytes(16);

        $this->cbc = new \AES\Mode\CBC();
        $this->encCtx = new \AES\Context\CBC($key, $iv);
        $this->decCtx = new \AES\Context\CBC($key, $iv);
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

        return $this->cbc->encrypt($this->encCtx, $data . $this->pad->getPadding($data));
    }

    protected function isAdmin($query)
    {
        $data = $this->cbc->decrypt($this->decCtx, $query);

        return strpos($data, ';admin=true;') !== false;
    }

    protected function execute(): bool
    {
        // 0..............f|0..............f|0..............f|0..............f|0..............f
        // comment1=cooking|%20MCs;userdata=
        //                 |                |aaaaaaaaaaaaaaaa|bbbb;admin=true |
        //                                                                   ;comment2=%20like%20a%20pound%20of%20bacon

        // 31 chars to account for the trailing semicolon
        $badData = 'aaaaaaaaaaaaaaaabbbb;admin=true';
        $goodData = 'aaaaaaaaaaaaaaaabbbbbbbbbbbbbbb';
        $badBlock = substr($badData ^ $goodData, 16);

        $query = $this->getQuery($goodData);

        $query = substr($query, 0, 32) . (substr($query, 32, 15) ^ $badBlock) . substr($query, 47);

        return $this->isAdmin($query);
    }
}
