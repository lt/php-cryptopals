<?php declare(strict_types = 1);

namespace Cryptopals\Set5\Challenge35;

class MITM
{
    protected $cbc;
    protected $pad;
    
    function __construct(ConversationEntity $A, ConversationEntity $B)
    {
        $this->cbc = new \AES\Mode\CBC();
        $this->pad = new \AES\Padding\PKCS7();
        
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
