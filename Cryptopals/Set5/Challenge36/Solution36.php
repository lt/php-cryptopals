<?php declare(strict_types = 1);

namespace Cryptopals\Set5\Challenge36;

use Cryptopals\Solution;

class Solution36 extends Solution
{
    function execute(): bool
    {
        $I = 'email';
        $P = 'password';

        $S = new SRPServer($I, $P);
        $C = new SRPClient($I, $P);

        $C->setSalt($S->getSalt());
        $S->setA($C->getA());
        $C->setB($S->getB());

        return $S->getProof() === $C->getProof();
    }
}
