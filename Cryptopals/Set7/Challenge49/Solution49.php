<?php declare(strict_types = 1);

namespace Cryptopals\Set7\Challenge49;

use Cryptopals\Set2\Challenge15\PKCS7;
use Cryptopals\Solution;

class Solution49 implements Solution
{
    protected $frontend;

    function __construct(Frontend $frontend)
    {
        $this->frontend = $frontend;
    }

    function execute(): bool
    {
        $lastMessage = '';
        $lastIV = '';
        $lastMAC = '';

        print "Attacker-controlled IV:\n\n";
        $backend = $this->frontend->getBackend();
        $backend->setSniffer(
            function(string $data) use(&$lastMessage, &$lastIV, &$lastMAC) {
                $lastMessage = substr($data, 0, -32);
                $lastIV = substr($data, -32, 16);
                $lastMAC = substr($data, -16);

                print "Sniffed: {$lastMessage}\n     IV: " .
                    bin2hex($lastIV) . "\n    MAC: " .
                    bin2hex($lastMAC) . "\n";
            }
        );

        // Simulate someone else sending a million spacebucks so we can sniff it
        $this->frontend->transfer(123, 99, 1000000);

        $badMessage = 'from=123&to=42&amount=1000000';
        $badIV = $lastIV ^ $lastMessage ^ $badMessage; // PHP truncates messages to len(iv)
        $backend->process($badMessage, $badIV, $lastMAC);
        $part1success = $lastIV === $badIV;

        print str_repeat('#', 80);

        print "\nFixed IV:\n\n";
        $backend->setSniffer(
            function(string $data) use(&$lastMessage, &$lastIV, &$lastMAC) {
                $lastMessage = substr($data, 0, -16);
                $lastIV = str_repeat("\0", 16);
                $lastMAC = substr($data, -16);

                print "Sniffed: {$lastMessage}\n    MAC: " .
                    bin2hex($lastMAC) . "\n";
            }
        );

        // Simulate someone else sending a tx it
        $this->frontend->transferMulti(99, [
            13 => 1000,
            27 => 1000
        ]);

        $lastMessageVictim = $lastMessage;
        $lastMACVictim = $lastMAC;

/*

---------------|---------------|---------------|---------------|
from=99&tx_list=13:1000;27:1000_
E(v0^0)        |E(v1^E(v0^0)) = Mv
---------------|---------------|---------------|---------------|
                                from=42&tx_list=99:0;42:1000000_
                               |E(a0^0)        |ECB(a1^E(a0^0)) = Ma
---------------|---------------|---------------|---------------|
from=99&tx_list=13:1000;27:1000_< junk: new iv >99:0;42:1000000_
                               |E(a0^Mv)       |ECB(a1^E(a0^Mv)) = Ma
*/

        // This is us controlling the first block
        $this->frontend->transferMulti(42, [
            99 => 0,
            42 => 100000
        ]);

        $lastMessageAttacker = $lastMessage;
        $lastMACAttacker = $lastMAC;
        $lastMAC = null;

        $forgedMessage = PKCS7::pad($lastMessageVictim) . ($lastMessageAttacker ^ $lastMACVictim) . substr($lastMessageAttacker, 16);
        $backend->processMulti($forgedMessage, $lastMACAttacker);

        $part2success = $lastMAC === $lastMACAttacker;

        return $part1success && $part2success;
    }
}
