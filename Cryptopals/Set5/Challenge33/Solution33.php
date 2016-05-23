<?php declare(strict_types = 1);

namespace Cryptopals\Set5\Challenge33;

use Cryptopals\Solution;

class Solution33 implements Solution
{
    protected $dh;

    function __construct(DH $dh)
    {
        $this->dh = $dh;
    }

    function execute(): bool
    {
        $a = $this->dh->generatePrivate();
        $b = $this->dh->generatePrivate();

        $A = $this->dh->generatePublic($a);
        $B = $this->dh->generatePublic($b);

        $s = $this->dh->generateShared($a, $B);
        $s2 = $this->dh->generateShared($b, $A);

        print "A and B shared secrets match:\n";
        print gmp_cmp($s, $s2) === 0 ? "Yes!\n\n" : "No :(\n\n";

        print "Shared secret:\n";
        print gmp_strval($s, 16) . "\n";

        return true;
    }
}
