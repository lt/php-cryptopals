<?php declare(strict_types = 1);

/*
 * g = 1
 * ---------------
 * a and b = rand
 * A and B = (1**rand) % p == 1
 * s = (1**rand) % p == 1
 *
 * g = p
 * ---------------
 * a and b = rand
 * A and B = (p**rand) % p == 1 (i.e. 3**4 == 81, 81 % 3 = 0)
 * s = (0**rand) % p == 0
 *
 * g = p - 1
 * ---------------
 * a and b = rand
 * A and B = ((p-1)**rand) % p
 *      when rand is even == 1 (i.e. 4**2 == 16, 16 % 5 == 1)
 *      when rand is odd == p - 1 (i.e. 4**3 == 64, 64 % 5 == 4)
 * s = (B**a) % p
 *      when B is 1 and a is even then s == 1
 *      when B is p - 1
 *          when a is even == 1
 *          when a is odd == p - 1
 */

namespace Cryptopals\Set5\Challenge35;

use Cryptopals\Set5\Challenge33\DH;
use Cryptopals\Solution;

class Solution35 extends Solution
{
    protected function execute(): bool
    {
        print "Testing normal comms:\n\n";

        $A = new ConversationEntity('A', new DH);
        $B = new ConversationEntity('B', new DH);

        $M = new MITM($A, $B);

        $A->groupNeg();
        $A->send('Hello there!');
        $B->send('Hi!');

        print "\nMITM with g = 1:\n\n";

        $A = new ConversationEntity('A', new DH);
        $B = new ConversationEntity('B', new DH);

        $M = new MITM1($A, $B);

        $A->groupNeg();
        $A->send('Hello there!');
        $B->send('Hi!');

        print "\nMITM with g = p:\n\n";

        $A = new ConversationEntity('A', new DH);
        $B = new ConversationEntity('B', new DH);

        $M = new MITMP($A, $B);

        $A->groupNeg();
        $A->send('Hello there!');
        $B->send('Hi!');

        print "\nMITM with g = p - 1:\n\n";

        $A = new ConversationEntity('A', new DH);
        $B = new ConversationEntity('B', new DH);

        $M = new MITMPminus1($A, $B);

        $A->groupNeg();
        $A->send('Hello there!');
        $B->send('Hi!');

        return true;
    }
}
