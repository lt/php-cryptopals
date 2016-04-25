<?php declare(strict_types = 1);

namespace Cryptopals\Set2\Challenge16;

use AES\CBC;
use AES\Key;
use Cryptopals\Set2\Challenge15\PKCS7;
use Cryptopals\Solution;

class Solution16 extends Solution
{
    protected $cbc;
    protected $key;
    protected $iv;
    protected $pkcs7;

    protected function setUp(): bool
    {
        $this->cbc = new CBC;
        $this->key = new Key(random_bytes(16));
        $this->iv = random_bytes(16);
        $this->pkcs7 = new PKCS7;

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

        return $this->cbc->encrypt($this->key, $this->iv, $this->pkcs7->pad($data));
    }

    protected function isAdmin(string $query): bool
    {
        $data = $this->cbc->decrypt($this->key, $this->iv, $query);

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

        print "We sent:       {$goodData}\n";
        print "We want:       {$badData}\n";
        print 'Bit flip mask: ' . bin2hex($badBlock) . "\n";

        $query = $this->getQuery($goodData);
        $query = substr($query, 0, 32) . (substr($query, 32, 15) ^ $badBlock) . substr($query, 47);

        return $this->isAdmin($query);
    }
}
