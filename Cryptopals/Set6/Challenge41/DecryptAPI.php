<?php declare(strict_types = 1);

namespace Cryptopals\Set6\Challenge41;

use Cryptopals\Set5\Challenge39\RSA;

class DecryptAPI
{
    protected $rsa;
    
    protected $e;
    protected $n;
    protected $d;

    protected $cache = [];

    function __construct(RSA $rsa)
    {
        $this->rsa = $rsa;
        
        $this->e = gmp_init(65537);
        list(, , $this->n, $this->d) = $this->rsa->generatePQND(256, $this->e);

        return true;
    }

    function publicKey(): array
    {
        return [$this->e, $this->n];
    }

    function decryptBlob(string $blob): string
    {
        $hash = sha1($blob);
        if (isset($this->cache[$hash])) {
            throw new \Exception('Cannot decrypt the same blob twice');
        }
        $this->cache[$hash] = time();

        $message = gmp_import($blob);
        $decrypted = $this->rsa->decrypt($message, $this->d, $this->n);

        return gmp_export($decrypted);
    }
}
