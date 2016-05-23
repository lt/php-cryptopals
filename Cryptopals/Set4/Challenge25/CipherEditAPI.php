<?php declare(strict_types = 1);

namespace Cryptopals\Set4\Challenge25;

use AES\ECB;
use Cryptopals\Set1\Challenge7\RandomKey;
use Cryptopals\Set1\Challenge7\YellowSubmarineKey;
use Cryptopals\Set2\Challenge15\PKCS7;
use Cryptopals\Set3\Challenge18\AESCTR;

class CipherEditAPI
{
    protected $ctr;
    protected $key;

    protected $plaintext = '';
    protected $ciphertext = '';
    protected $nonce = '';

    function __construct(AESCTR $ctr, RandomKey $key, ECB $ecb, YellowSubmarineKey $ysKey)
    {
        $this->ctr = $ctr;
        $this->key = $key;
        $this->nonce = random_bytes(8);

        $plaintext = $ecb->decrypt($ysKey, base64_decode(file_get_contents(__DIR__ . '/25.txt')));
        $this->plaintext = PKCS7::depad($plaintext);

        $this->ciphertext = $this->ctr->encrypt($key, $this->nonce, $this->plaintext);
    }

    function getCipherText(): string
    {
        return $this->ciphertext;
    }

    function edit(string $newText, int $offset): string
    {
        $this->plaintext = substr_replace($this->plaintext, $newText, $offset, strlen($newText));

        return $this->ctr->encrypt($this->key, $this->nonce, $this->plaintext);
    }
}
