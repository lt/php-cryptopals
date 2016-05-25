<?php declare(strict_types = 1);

namespace Cryptopals\Set6\Challenge42;

use Cryptopals\Set5\Challenge39\RSA;

class MessageAPI
{
    protected $e;
    protected $n;
    protected $d;

    function __construct(RSA $rsa)
    {
        $this->rsa = $rsa;

        $this->e = gmp_init(3);
        list(, , $this->n, $this->d) = $this->rsa->generatePQND(512, $this->e);

        return true;
    }

    function publicKey(): array
    {
        return [$this->e, $this->n];
    }

    function sign(string $message): string
    {
        // No, I am not implementing ASN.1 .. bleurgh
        $suffix = 'ASN1GOOP' . sha1($message, true);
        $ffffPad = str_repeat("\xff", 128 - 3 - strlen($suffix));
        $message = "\0\1{$ffffPad}\0{$suffix}";

        return gmp_export($this->rsa->decrypt(gmp_import($message), $this->d, $this->n));
    }

    function verify(string $message, string $signature): bool
    {
        $decrypted = gmp_export($this->rsa->encrypt(gmp_import($signature), $this->e, $this->n));
        $decrypted = str_pad($decrypted, 128, "\0", STR_PAD_LEFT);

        preg_match('~\x00\x01\xff+\x00ASN1GOOP(.{20})~s', $decrypted, $matches);

        return sha1($message, true) === $matches[1];
    }


}
