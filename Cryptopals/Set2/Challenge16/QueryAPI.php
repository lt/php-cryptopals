<?php declare(strict_types = 1);

namespace Cryptopals\Set2\Challenge16;

use AES\CBC;
use Cryptopals\Set1\Challenge7\RandomKey;
use Cryptopals\Set2\Challenge15\PKCS7;

class QueryAPI
{
    protected $cbc;
    protected $key;
    protected $iv;

    function __construct(CBC $cbc, RandomKey $key)
    {
        $this->cbc = $cbc;
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

        return $this->cbc->encrypt($this->key, $this->iv, PKCS7::pad($data));
    }

    function isAdmin(string $query): bool
    {
        $data = $this->cbc->decrypt($this->key, $this->iv, $query);

        return strpos($data, ';admin=true;') !== false;
    }

}
