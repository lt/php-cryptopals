<?php

/*
 * http://cryptopals.com/sets/5/challenges/37/
 *
 * Break SRP with a zero key
 *
 * Get your SRP working in an actual client-server setting. "Log in" with a valid password using the protocol.
 *
 * Now log in without your password by having the client send 0 as its "A" value. What does this to the "S" value that both sides compute?
 *
 * Now log in without your password by having the client send N, N*2, &c.
 *
 * Cryptanalytic MVP award
 * Trevor Perrin and Nate Lawson taught us this attack 7 years ago. It is excellent. Attacks on DH are tricky to "operationalize". But this attack uses the same concepts, and results in auth bypass. Almost every implementation of SRP we've ever seen has this flaw; if you see a new one, go look for this bug.
 */

require_once '36-implement-secure-remote-password.php';

class SRPClientAmulN extends SRPClient
{
    function __construct($I, $P, $mul)
    {
        parent::__construct($I, $P);

        $this->A = gmp_strval(gmp_mul($this->N, "$mul"), 16);
    }

    function getK()
    {
        return hash('sha256', '0');
    }

    function getProof()
    {
        return hash_hmac('sha256', $this->getK(), $this->salt);
    }
}

$I = 'email';

for ($i = 0; $i < 6; $i++) {
    $S = new SRPServer($I, 'password');
    $C = new SRPClientAmulN($I, 'who cares', $i);

    $C->setSalt($S->getSalt());
    $S->setA($C->getA()); // S->S is now 0
    $C->setB($S->getB());

    print "Client sends A = N*$i. Auth with no password:\n";
    print $S->getProof() === $C->getProof() ? "OK\n\n" : "Not OK :(\n\n";
}
