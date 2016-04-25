<?php declare(strict_types = 1);

namespace Cryptopals\Set2\Challenge13;

use AES\ECB;
use AES\Key;
use Cryptopals\Set1\Challenge8\Solution8;
use Cryptopals\Set2\Challenge9\PKCS7;

class Solution13 extends Solution8
{
    protected $ecb;
    protected $key;
    protected $pkcs7;

    protected function setUp(): bool
    {
        $this->ecb = new ECB;
        $this->key = new Key(random_bytes(16));
        $this->pkcs7 = new PKCS7;

        return true;
    }

    protected function profileFor(string $email): string
    {
        return http_build_query([
            'email' => $email,
            'uid' => 10,
            'role' => 'user'
        ]);
    }

    protected function encryptedProfileFor(string $email): string
    {
        $profile = $this->profileFor($email);

        return $this->ecb->encrypt($this->key, $this->pkcs7->pad($profile));
    }

    protected function decryptedProfile(string $ciphertext): array
    {
        $decypted = $this->ecb->decrypt($this->key, $ciphertext);

        parse_str($decypted, $profile);
        return $profile;
    }

    protected function execute(): bool
    {
        // assuming we know the structure is email=&uid=&role=
        // 0..............f|0............
        // email=aaaaaaaaaa|admin&uid=...

        $padToAlignEmail = 16 - strlen('email=');

        // pad until we cause a block count increase, then add 4 so we can chop off "user"
        // ....f|0......
        // role=|user...

        $lastLen = strlen($this->encryptedProfileFor('a'));
        for ($i = 2; $i <= 16; $i++) {
            if ($lastLen !== strlen($this->encryptedProfileFor(str_repeat('a', $i)))) {
                break;
            }
        }
        $padToChopRole = $i + 4;

        print "Padding to chop role: $padToChopRole\n";
        print "Padding to align admin: $padToAlignEmail\n";

        $adminInBlock2 = $this->encryptedProfileFor(str_repeat('a', $padToAlignEmail) . 'admin');
        $roleInBlock3 = $this->encryptedProfileFor(str_repeat('a', $padToChopRole));

        // cut and paste
        // 0..............f|0..............f|0..............f
        // <------------- this ------------>|
        // email=aaaaaaaaaa|aaa&uid=10&role=|user
        //                 |                |<-- and this -->
        //                 |email=aaaaaaaaaa|admin&uid=10&rol
        //                 |                |
        // email=aaaaaaaaaa|aaa&uid=10&role=|admin&uid=10&rol
        
        $bakedAuth = substr($roleInBlock3, 0, 32) . substr($adminInBlock2, 16, 16);
        $decryptedProfile = $this->decryptedProfile($bakedAuth);

        print "Decrypted profile:\n";
        print_r($decryptedProfile);

        return $decryptedProfile['role'] === 'admin';
    }
}
