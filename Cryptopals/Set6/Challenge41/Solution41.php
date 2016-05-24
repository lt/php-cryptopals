<?php declare(strict_types = 1);

namespace Cryptopals\Set6\Challenge41;

use Cryptopals\Set5\Challenge39\RSA;
use Cryptopals\Solution;

class Solution41 implements Solution
{
    protected $rsa;
    protected $decryptAPI;
    
    function __construct(RSA $rsa, DecryptAPI $decryptAPI)
    {
        $this->rsa = $rsa;
        $this->decryptAPI = $decryptAPI;
    }
    
    function captureCiphertext(): string
    {
        list($e, $n) = $this->decryptAPI->publicKey();
        
        $plaintext = gmp_import('the matasano crypto challenges');
        $encrypted = $this->rsa->encrypt($plaintext, $e, $n);
        
        $ciphertext = gmp_export($encrypted);
        return $ciphertext;
    }

    function execute(): bool
    {
        $ciphertext = $this->captureCiphertext();

        /* Grabbing this for comparison at the end, not using it elsewhere */
        $actualPlaintext = $this->decryptAPI->decryptBlob($ciphertext);

        print 'Captured ciphertext: ' . bin2hex($ciphertext) . "\n\n";

        list($e, $n) = $this->decryptAPI->publicKey();
        $multiplier = 2;

        // \o/ homomorphism
        $cPrime = gmp_export((gmp_powm($multiplier, $e, $n) * gmp_import($ciphertext)) % $n);
        $pPrime = $this->decryptAPI->decryptBlob($cPrime);
        $p = gmp_export((gmp_import($pPrime) / $multiplier) % $n);

        print "Recovered plaintext: {$p}\n";

        return $actualPlaintext === $p;
    }
}
