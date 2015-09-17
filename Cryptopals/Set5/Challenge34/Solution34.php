<?php declare(strict_types = 1);

namespace Cryptopals\Set5\Challenge34;

use Cryptopals\Set5\Challenge33\DH;
use Cryptopals\Solution;

class Solution34 extends Solution
{
    protected $cbc;
    protected $pad;

    protected function setUp(): bool
    {
        $this->cbc = new \AES\Mode\CBC();
        $this->pad = new \AES\Padding\PKCS7();

        return true;
    }

    protected function execute(): bool
    {
        $dh = new DH();

        print "Testing normal comms:\n\n";

        $A = new ConversationEntity('A', $dh);
        $B = new ConversationEntity('B', $dh);

        $A->onSend = [$B, 'receive'];
        $B->onSend = [$A, 'receive'];

        $A->kexRequest();
        $A->send('Hello there!');
        $B->send('Hi!');

        print "\nSetting up MITM:\n\n";

        $state = 0;
        $stolenP = null;
        $evilShared = null;

        $A = new ConversationEntity('A', $dh);
        $B = new ConversationEntity('B', $dh);

        $A->onSend = function($data) use ($B, &$state, &$stolenP, &$evilShared, $dh) {
            if ($state === 0) {
                print "M: Manipulating kex req\n";

                $obj = json_decode($data);
                $obj->A = $obj->p;

                $stolenP = gmp_init($obj->p, 16);
                $evilShared = gmp_strval($dh->generateShared($stolenP, $stolenP), 16);

                $state = 1;
                $B->receive(json_encode($obj));
            }
            else {
                $key = substr(sha1($evilShared, true), 0, 16);
                $iv = substr($data, 0, 16);

                $ctx = new \AES\Context\CBC($key, $iv);
                $message = $this->cbc->decrypt($ctx, substr($data, 16));
                $message = substr($message, 0, -$this->pad->getPadLen($message));

                print "M: sniffed: $message\n";
            }
        };

        $B->onSend = function($data) use ($A, &$state, &$stolenP, &$evilShared) {
            if ($state === 1) {
                print "M: Manipulating kex resp\n";

                $obj = json_decode($data);
                $obj->B = gmp_strval($stolenP, 16);

                $state = 2;
                $A->receive(json_encode($obj));
            }
            else {
                $key = substr(sha1($evilShared, true), 0, 16);
                $iv = substr($data, 0, 16);

                $ctx = new \AES\Context\CBC($key, $iv);
                $message = $this->cbc->decrypt($ctx, substr($data, 16));
                $message = substr($message, 0, -$this->pad->getPadLen($message));

                print "M: sniffed: $message\n";
            }
        };

        $A->kexRequest();
        $A->send('Hello there!');
        $B->send('Hi!');

        return true;
    }
}
