<?php declare(strict_types = 1);

namespace Cryptopals\Set4\Challenge28;

class SHA1KeyedMAC
{
    protected $sha1;

    function __construct(SHA1 $sha1)
    {
        $this->sha1 = $sha1;
    }

    function mac(string $key, string $message): string
    {
        $ctx = new SHA1Context();

        $this->sha1->reset($ctx);
        $this->sha1->input($ctx, $key . $message);
        $this->sha1->result($ctx);

        return pack('N5', ...$ctx->messageDigest);
    }
}
