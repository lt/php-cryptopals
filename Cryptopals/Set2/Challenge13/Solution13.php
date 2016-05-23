<?php declare(strict_types = 1);

namespace Cryptopals\Set2\Challenge13;

use Cryptopals\Solution;

class Solution13 implements Solution
{
    protected $profileAPI;
    
    function __construct(ProfileAPI $profileAPI)
    {
        $this->profileAPI = $profileAPI;
    }

    function execute(): bool
    {
        // assuming we know the structure is email=&uid=&role=
        // 0..............f|0............
        // email=aaaaaaaaaa|admin&uid=...

        $padToAlignEmail = 16 - strlen('email=');

        // pad until we cause a block count increase, then add 4 so we can chop off "user"
        // ....f|0......
        // role=|user...

        $lastLen = strlen($this->profileAPI->encryptedProfileFor('a'));
        for ($i = 2; $i <= 16; $i++) {
            if ($lastLen !== strlen($this->profileAPI->encryptedProfileFor(str_repeat('a', $i)))) {
                break;
            }
        }
        $padToChopRole = $i + 4;

        print "Padding to chop role: $padToChopRole\n";
        print "Padding to align admin: $padToAlignEmail\n";

        $adminInBlock2 = $this->profileAPI->encryptedProfileFor(str_repeat('a', $padToAlignEmail) . 'admin');
        $roleInBlock3 = $this->profileAPI->encryptedProfileFor(str_repeat('a', $padToChopRole));

        // cut and paste
        // 0..............f|0..............f|0..............f
        // <------------- this ------------>|
        // email=aaaaaaaaaa|aaa&uid=10&role=|user
        //                 |                |<-- and this -->
        //                 |email=aaaaaaaaaa|admin&uid=10&rol
        //                 |                |
        // email=aaaaaaaaaa|aaa&uid=10&role=|admin&uid=10&rol
        
        $bakedAuth = substr($roleInBlock3, 0, 32) . substr($adminInBlock2, 16, 16);

        return $this->profileAPI->isAdmin($bakedAuth);
    }
}
