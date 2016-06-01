<?php declare(strict_types = 1);

namespace Cryptopals\Set7\Challenge50;

use AES\ECB;
use Cryptopals\Set1\Challenge7\YellowSubmarineKey;
use Cryptopals\Set7\Challenge49\CBCMAC;
use Cryptopals\Solution;

class Solution50 implements Solution
{
    protected $ecb;
    protected $mac;
    protected $key;

    function __construct(ECB $ecb, CBCMAC $mac, YellowSubmarineKey $key)
    {
        $this->ecb = $ecb;
        $this->mac = $mac;
        $this->key = $key;
    }

    function execute(): bool
    {
        $knownCode = "alert('MZA who was that?');\n";
        $knownHash = hex2bin('296b8d7cb78a243dda4d0a61d33bbdd1');
        $fixedIV = str_repeat("\0", 16);

        if (!hash_equals($knownHash, $this->mac->mac($this->key, $fixedIV, $knownCode))) {
            return false;
        }

        $m0 = 'alert("Ayo, the '; // ^ 0
        $i0 = $this->ecb->encrypt($this->key, $m0 ^ $fixedIV);

        $m1 = 'Wu is back!");//'; // ecb(m0 ^ 0)
        $i1 = $this->ecb->encrypt($this->key, $m1 ^ $i0);

        $m2 = $this->ecb->decrypt($this->key, str_repeat("\0", 16)) ^ $i1; // ecb( ^ ecb(m0 ^ 0))

        // Shorter end-code for an extra encrypt round, but contains a newline
        //$m2 = $this->ecb->decrypt($this->key, $this->ecb->encrypt($this->key, $knownCode ^ $fixedIV)) ^ $i1;
        print "Magic block to reset IV: " . bin2hex($m2) . "\n\n";

        $badCode = $m0 . $m1 . $m2 . $knownCode;
        print "Bad code:\n{$badCode}\n";

        if (!hash_equals($knownHash, $this->mac->mac($this->key, $fixedIV, $badCode))) {
            return false;
        }

        return true;
    }
}
