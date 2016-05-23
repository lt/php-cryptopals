<?php declare(strict_types = 1);

namespace Cryptopals\Set4\Challenge26;

use Cryptopals\Set1\Challenge7\RandomKey;
use Cryptopals\Set3\Challenge18\AESCTR;

class QueryAPI
{
    protected $ctr;
    protected $key;
    protected $iv;

    function __construct(AESCTR $ctr, RandomKey $key)
    {
        $this->ctr = $ctr;
        $this->key = $key;
        $this->iv = random_bytes(16);
    }
    
    function getQuery(string $userData): string
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

    function isAdmin(string $query): bool
    {
        $data = $this->ctr->decrypt($this->key, str_repeat("\0", 8), $query);

        return strpos($data, ';admin=true;') !== false;
    }
}
