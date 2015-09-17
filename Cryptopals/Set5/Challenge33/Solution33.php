<?php declare(strict_types = 1);

namespace Cryptopals\Set5\Challenge33;

use Cryptopals\Solution;

class Solution33 extends Solution
{
    protected function execute(): bool
    {
        $dh = new DH;

        $a = $dh->generatePrivate();
        $b = $dh->generatePrivate();

        $A = $dh->generatePublic($a);
        $B = $dh->generatePublic($b);

        $s = $dh->generateShared($a, $B);
        $s2 = $dh->generateShared($b, $A);


        print "A and B shared secrets match:\n";
        print gmp_cmp($s, $s2) === 0 ? "Yes!\n\n" : "No :(\n\n";

        print "Shared secret:\n";
        print gmp_strval($s, 16) . "\n";

        return true;
    }
}
