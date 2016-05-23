<?php declare(strict_types = 1);

namespace Cryptopals\Set2\Challenge13;

use AES\ECB;
use Cryptopals\Set1\Challenge7\RandomKey;
use Cryptopals\Set2\Challenge9\PKCS7;

class ProfileAPI
{
    protected $ecb;
    protected $key;

    function __construct(ECB $ecb, RandomKey $key)
    {
        $this->ecb = $ecb;
        $this->key = $key;
    }

    function encryptedProfileFor(string $email): string
    {
        $profile = http_build_query([
            'email' => $email,
            'uid' => 10,
            'role' => 'user'
        ]);

        return $this->ecb->encrypt($this->key, PKCS7::pad($profile));
    }

    function isAdmin(string $ciphertext): bool
    {
        $decypted = $this->ecb->decrypt($this->key, $ciphertext);

        parse_str($decypted, $profile);
        return isset($profile['role']) && $profile['role'] === 'admin';
    }
}
