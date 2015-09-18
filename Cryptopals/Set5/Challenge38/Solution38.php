<?php declare(strict_types = 1);

namespace Cryptopals\Set5\Challenge38;

use Cryptopals\Solution;

class Solution38 extends Solution
{
    function execute(): bool
    {
        $I = 'email';
        $P = 'password';

        print "Without MITM:\n";
        $S = new SimpleSRPServer($I, $P);
        $C = new SimpleSRPClient($I, $P);

        $S->setA($C->getA());
        $C->setSalt($S->getSalt());
        $C->setu($S->getu());
        $C->setB($S->getB());

        print $S->getProof() ===
            $C->getProof() ? "OK\n\n" : "Not OK :(\n\n";

        print "With MITM:\n";
        $S = new SimpleSRPServer($I, $P);
        $C = new SimpleSRPClient($I, $P);
        $M = new SimpleSRPSniffer();

        $S->setA($M->sniffA($C->getA()));
        $C->setSalt($M->sniffSalt($S->getSalt()));
        $C->setu($M->sniffu($S->getu()));
        $C->setB($M->sniffB($S->getB()));

        $proofC = $M->sniffProofC($C->getProof());
        $proofS = $M->sniffProofS($S->getProof());

        print $proofS === $proofC ? "OK\n\n" : "Not OK :(\n\n";

        return true;
    }
}
