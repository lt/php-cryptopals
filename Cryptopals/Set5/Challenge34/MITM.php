<?php declare(strict_types = 1);

namespace Cryptopals\Set5\Challenge34;

use AES\CBC;
use AES\Key;
use Cryptopals\Set2\Challenge15\PKCS7;
use Cryptopals\Set5\Challenge33\DH;

class MITM
{
    protected $dh;
    protected $cbc;

    protected $state = 0;
    protected $stolenP = null;
    protected $evilShared = null;

    function __construct(DH $dh, CBC $cbc)
    {
        $this->cbc = $cbc;
        $this->dh = $dh;
    }

    function sniffA(string $data, ConversationEntity $B)
    {
        if ($this->state === 0) {
            print "M: Manipulating kex req\n";

            $obj = json_decode($data);
            $obj->A = $obj->p;

            $this->stolenP = gmp_init($obj->p, 16);
            $this->evilShared = gmp_strval($this->dh->generateShared($this->stolenP, $this->stolenP), 16);

            $this->state = 1;
            $B->receive(json_encode($obj));
        }
        else {
            $key = new Key(substr(sha1($this->evilShared, true), 0, 16));
            $iv = substr($data, 0, 16);

            $message = $this->cbc->decrypt($key, $iv, substr($data, 16));
            $message = PKCS7::depad($message);

            print "M: sniffed: $message\n";
        }
    }

    function sniffB(string $data, ConversationEntity $A)
    {
        if ($this->state === 1) {
            print "M: Manipulating kex resp\n";

            $obj = json_decode($data);
            $obj->B = gmp_strval($this->stolenP, 16);

            $this->state = 2;
            $A->receive(json_encode($obj));
        }
        else {
            $key = new Key(substr(sha1($this->evilShared, true), 0, 16));
            $iv = substr($data, 0, 16);

            $message = $this->cbc->decrypt($key, $iv, substr($data, 16));
            $message = PKCS7::depad($message);

            print "M: sniffed: $message\n";
        }
    }
}
