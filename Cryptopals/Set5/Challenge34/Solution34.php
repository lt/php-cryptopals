<?php declare(strict_types = 1);

namespace Cryptopals\Set5\Challenge34;

use AES\CBC;
use Cryptopals\Set5\Challenge33\DH;
use Cryptopals\Solution;

class Solution34 implements Solution
{
    protected $dh;
    protected $cbc;

    function __construct(CBC $cbc, DH $dh)
    {
        $this->dh = $dh;
        $this->cbc = $cbc;
    }

    function execute(): bool
    {
        print "Testing normal comms:\n\n";

        $A = new ConversationEntity('A', $this->dh, $this->cbc);
        $B = new ConversationEntity('B', $this->dh, $this->cbc);

        $A->onSend = [$B, 'receive'];
        $B->onSend = [$A, 'receive'];

        $A->kexRequest();
        $A->send('Hello there!');
        $B->send('Hi!');

        print "\nSetting up MITM:\n\n";

        $A = new ConversationEntity('A', $this->dh, $this->cbc);
        $B = new ConversationEntity('B', $this->dh, $this->cbc);
        $M = new MITM($this->dh, $this->cbc, $A, $B);

        $A->onSend = function(string $data) use($M, $B) {
            $M->sniffA($data, $B);
        };

        $B->onSend = function(string $data) use($M, $A) {
            $M->sniffB($data, $A);
        };

        $A->kexRequest();
        $A->send('Hello there!');
        $B->send('Hi!');

        return true;
    }
}
