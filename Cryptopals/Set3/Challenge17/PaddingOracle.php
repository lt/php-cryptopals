<?php declare(strict_types = 1);

namespace Cryptopals\Set3\Challenge17;

use AES\CBC;
use Cryptopals\Set1\Challenge7\RandomKey;
use Cryptopals\Set2\Challenge15\PKCS7;

class PaddingOracle
{
    protected $cbc;
    protected $key;
    protected $iv;

    protected $texts = [
        'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
        'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
        'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
        'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
        'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
        'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
        'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
        'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
        'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
        'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
    ];

    function __construct(CBC $cbc, RandomKey $key)
    {
        $this->cbc = $cbc;
        $this->key = $key;
    }

    function getRandomCiphertext(): string
    {
        $iv = random_bytes(16);

        $text = base64_decode($this->texts[mt_rand(0, 9)]);
        return $iv . $this->cbc->encrypt($this->key, $iv, PKCS7::pad($text));
    }

    function validCiphertext(string $ciphertext, string $iv): bool
    {
        try {
            $plaintext = $this->cbc->decrypt($this->key, $iv, $ciphertext);
            PKCS7::getPaddingLength($plaintext);

            return true;
        }
        catch (\Exception $e) {
            return false;
        }
    }

}
