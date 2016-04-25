<?php declare(strict_types = 1);

namespace Cryptopals\Set4\Challenge26;

use AES\Key;
use Cryptopals\Set3\Challenge18\AESCTR;
use Cryptopals\Solution;

class Solution26 extends Solution
{
    protected $ctr;
    protected $key;
    
    protected function setUp(): bool
    {
        $this->ctr = new AESCTR;
        $this->key = new Key(random_bytes(16));
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

        return $this->ctr->encrypt($this->key, str_repeat("\0", 8), $data);
    }

    protected function isAdmin(string $query): bool
    {
        $data = $this->ctr->decrypt($this->key, str_repeat("\0", 8), $query);

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
        $badBlock = $badData ^ $goodData;

        print "We sent:       {$goodData}\n";
        print "We want:       {$badData}\n";
        print 'Bit flip mask: ' . bin2hex($badBlock) . "\n";

        $query = $this->getQuery($goodData);

        $query = substr($query, 0, 32) . (substr($query, 32, 15) ^ $badBlock) . substr($query, 47);

        return $this->isAdmin($query);
    }
}
