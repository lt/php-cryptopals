<?php declare(strict_types = 1);

namespace Cryptopals\Set4\Challenge27;

use AES\CBC;
use AES\Key;
use Cryptopals\Set2\Challenge15\PKCS7;
use Cryptopals\Set2\Challenge16\Solution16;

class Solution27 extends Solution16
{
    protected function setUp(): bool
    {
        $this->cbc = new CBC;
        $this->iv = random_bytes(16);
        $this->key = new Key($this->iv);
        $this->pkcs7 = new PKCS7;

        return true;
    }

    protected function isAdmin(string $query): bool
    {
        $data = $this->cbc->decrypt($this->key, $this->iv, $query);

        if (preg_match('/^[\x{21}-\x{7E}]*$/', $data)) {
            return strpos($data, ';admin=true;') !== false;
        }

        throw new \Exception($data);
    }

    protected function execute(): bool
    {
        // 0..............f|0..............f|0..............f|0..............f
        // comment1=cooking|%20MCs;userdata=
        //                 |                |userdata
        //                                           ;comment|2=%20like%20a%20pound%20of%20bacon

        $query = $this->getQuery('userdata');

        $brokenQuery = substr($query, 0, 16) .
            str_repeat("\0", 16) .
            substr($query, 0, 16);

        try {
            $this->isAdmin($brokenQuery);
        }
        catch (\Throwable $e)
        {
            $error = $e->getMessage();
            $recoveredKey = substr($error, 0, 16) ^ substr($error, 32);
            print 'Recovered key: ' . bin2hex($recoveredKey) . "\n";

            $aesKey = new Key($recoveredKey);
            $query = $this->cbc->encrypt($aesKey, $recoveredKey, 'comment1=cooking%20MCs;userdata=x;admin=true;comment2=%20like%20a%20pound%20of%20bacon');
        }

        return $this->isAdmin($query);
    }
}
