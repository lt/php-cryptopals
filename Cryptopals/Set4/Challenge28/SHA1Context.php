<?php declare(strict_types = 1);

namespace Cryptopals\Set4\Challenge28;

class SHA1Context
{
    public $messageDigest = [
        0x67452301,
        0xefcdab89,
        0x98badcfe,
        0x10325476,
        0xc3d2e1f0
    ];

    public $lengthLow = 0;
    public $lengthHigh = 0;

    public $messageBlock = [];
    public $messageBlockIndex = 0;

    public $computed = 0;
    public $corrupted = 0;
}
