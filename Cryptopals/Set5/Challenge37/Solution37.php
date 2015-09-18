<?php declare(strict_types = 1);

namespace Cryptopals\Set5\Challenge37;

use Cryptopals\Set5\Challenge36\SRPServer;
use Cryptopals\Solution;

class Solution37 extends Solution
{
    function execute(): bool
    {
        $success = 1;
        $I = 'email';

        for ($i = 0; $i < 6; $i++) {
            $S = new SRPServer($I, 'password');
            $C = new SRPClientAmulN($I, 'who cares', $i);

            $C->setSalt($S->getSalt());
            $S->setA($C->getA()); // S->S is now 0
            $C->setB($S->getB());

            print "Client sends A = N*$i. Auth with no password:\n";
            $proofage = $S->getProof() === $C->getProof();
            print $proofage ? "OK\n\n" : "Not OK :(\n\n";

            $success &= $proofage;
        }

        return (bool)$success;
    }
}
