<?php declare(strict_types = 1);

namespace Cryptopals\Set4\Challenge30;

class MD4Context
{
    public $a = 0x67452301;
    public $b = 0xefcdab89;
    public $c = 0x98badcfe;
    public $d = 0x10325476;

    public $lo = 0;
    public $hi = 0;

    public $buffer = [];
}
