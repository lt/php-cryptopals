<?php declare(strict_types = 1);

namespace Cryptopals\Set6\Challenge46;

use Cryptopals\Set5\Challenge39\RSA;

class ParityOracle
{
    protected $rsa;

    protected $e;
    protected $n;
    protected $d;

    protected $ciphertext;

    function __construct(RSA $rsa)
    {
        $this->rsa = $rsa;

        $this->e = gmp_init(65537);
        list(, , $this->n, $this->d) = $this->rsa->generatePQND(512, $this->e);

        $plaintext = base64_decode('VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==');
        $this->ciphertext = $this->rsa->encrypt(gmp_import($plaintext), $this->e, $this->n);
    }

    function publicKey(): array
    {
        return [$this->e, $this->n];
    }

    function ciphertext(): \GMP
    {
        return $this->ciphertext;
    }

    function oracle(\GMP $ciphertext): bool
    {
        $plaintext = $this->rsa->decrypt($ciphertext, $this->d, $this->n);
        return gmp_testbit($plaintext, 0);
    }

}
