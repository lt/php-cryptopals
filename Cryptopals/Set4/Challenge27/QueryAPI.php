<?php declare(strict_types = 1);

namespace Cryptopals\Set4\Challenge27;

use AES\CBC;
use AES\Key;

class QueryAPI extends \Cryptopals\Set2\Challenge16\QueryAPI
{
    function __construct(CBC $cbc)
    {
        $this->cbc = $cbc;
        $this->iv = random_bytes(16);
        $this->key = new Key($this->iv);
    }

    function isAdmin(string $query): bool
    {
        $data = $this->cbc->decrypt($this->key, $this->iv, $query);

        if (preg_match('/^[\x{21}-\x{7E}]*$/', $data)) {
            return strpos($data, ';admin=true;') !== false;
        }

        throw new \Exception($data);
    }
}
