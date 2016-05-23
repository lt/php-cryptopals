<?php declare(strict_types = 1);

namespace Cryptopals\Set4\Challenge25;

use Cryptopals\Solution;

class Solution25 implements Solution
{
    protected $editAPI;
    
    function __construct(CipherEditAPI $editAPI)
    {
        $this->editAPI = $editAPI;
    }

    function execute(): bool
    {
        $ciphertext = $this->editAPI->getCipherText();

        $editedCiphertext = $this->editAPI->edit(str_repeat("\0", strlen($ciphertext)), 0);

        print "Recovered plaintext:\n";
        print $ciphertext ^ $editedCiphertext . "\n";

        return true;
    }
}
