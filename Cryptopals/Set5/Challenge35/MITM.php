<?php declare(strict_types = 1);

namespace Cryptopals\Set5\Challenge35;

use AES\CBC;
use Cryptopals\Set2\Challenge15\PKCS7;

class MITM
{
    protected $cbc;
    protected $pkcs7;
    
    function __construct(ConversationEntity $A, ConversationEntity $B)
    {
        $this->cbc = new CBC;
        $this->pkcs7 = new PKCS7;
        
        $A->onSend = function(string $data) use ($B) {
            $B->receive($this->sniffData($data));
        };

        $B->onSend = function(string $data) use ($A) {
            $A->receive($this->sniffData($data));
        };
    }
    
    function sniffData(string $data): string
    {
        return $data;
    }
}
