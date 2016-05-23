<?php declare(strict_types = 1);

namespace Cryptopals\Set4\Challenge27;

use AES\CBC;
use AES\Key;
use Cryptopals\Solution;

class Solution27 implements Solution
{
    protected $cbc;
    protected $queryAPI;

    function __construct(CBC $cbc, QueryAPI $queryAPI)
    {
        $this->cbc = $cbc;
        $this->queryAPI = $queryAPI;
    }

    function execute(): bool
    {
        // 0..............f|0..............f|0..............f|0..............f
        // comment1=cooking|%20MCs;userdata=
        //                 |                |userdata
        //                                           ;comment|2=%20like%20a%20pound%20of%20bacon

        $query = $this->queryAPI->getQuery('userdata');

        $brokenQuery = substr($query, 0, 16) .
            str_repeat("\0", 16) .
            substr($query, 0, 16);

        try {
            $this->queryAPI->isAdmin($brokenQuery);
        }
        catch (\Throwable $e)
        {
            $error = $e->getMessage();
            $recoveredKey = substr($error, 0, 16) ^ substr($error, 32);
            print 'Recovered key: ' . bin2hex($recoveredKey) . "\n";

            $aesKey = new Key($recoveredKey);
            $query = $this->cbc->encrypt($aesKey, $recoveredKey, 'comment1=cooking%20MCs;userdata=x;admin=true;comment2=%20like%20a%20pound%20of%20bacon');
        }

        return $this->queryAPI->isAdmin($query);
    }
}
