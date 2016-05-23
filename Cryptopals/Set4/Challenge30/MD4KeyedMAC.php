<?php declare(strict_types = 1);

namespace Cryptopals\Set4\Challenge30;

class MD4KeyedMAC
{
    protected $md4;

    function __construct(MD4 $md4)
    {
        $this->md4 = $md4;
    }

    function mac(string $key, string $message): string
    {
        $ctx = new MD4Context;

        $this->md4->init($ctx);
        $this->md4->update($ctx, $key . $message);

        return $this->md4->result($ctx);
    }
}
