<?php declare(strict_types = 1);

namespace Cryptopals\Set2\Challenge13;

use Cryptopals\Set1\Challenge8\Solution8;

class Solution13 extends Solution8
{
    protected $ecb;
    protected $ctx;
    protected $pad;

    protected function setUp(): bool
    {
        $key = random_bytes(16);

        $this->ecb = new \AES\Mode\ECB();
        $this->ctx = new \AES\Context\ECB($key);
        $this->pad = new \AES\Padding\PKCS7();

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

        return $this->ecb->encrypt($this->ctx, $profile . $this->pad->getPadding($profile));
    }

    protected function decryptedProfile(string $ciphertext): array
    {
        $decypted = $this->ecb->decrypt($this->ctx, $ciphertext);

        parse_str($decypted, $profile);
        return $profile;
    }

    protected function execute(): bool
    {
        // assuming we know the structure is email=&uid=&role=
        // 0..............f|0............
        // email=aaaaaaaaaa|admin&uid=...

        $padToAlignEmail = 16 - strlen('email=');

        // pad until we cause a block count increase, then add 3 so we can chop off "user"
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
        var_dump($decryptedProfile);

        return true;
    }
}
