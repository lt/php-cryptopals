<?php declare(strict_types = 1);

namespace Cryptopals\Set4\Challenge28;

use Cryptopals\Solution;

class Solution28 extends Solution
{
    protected function sha1KeyedMAC(string $key, string $message): string
    {
        $c = new SHA1Context();

        $s = new SHA1();
        $s->reset($c);
        $s->input($c, $key . $message);
        $s->result($c);

        return pack('N5', ...$c->messageDigest);
    }

    protected function execute(): bool
    {
        print "Expected: A9993E364706816ABA3E25717850C26C9CD0D89D\n";
        print "Homebrew: " . bin2hex($this->sha1KeyedMAC('', 'abc')) . "\n";

        print "Expected: 84983E441C3BD26EBAAE4AA1F95129E5E54670F1\n";
        print "Homebrew: " . bin2hex($this->sha1KeyedMAC('', 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')) . "\n";

        print "Expected: 34AA973CD4C4DAA4F61EEB2BDBAD27316534016F\n";
        print "Homebrew: " . bin2hex($this->sha1KeyedMAC('', str_repeat('a', 1000000))) . "\n";

        return true;
    }
}
