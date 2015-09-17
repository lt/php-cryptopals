<?php declare(strict_types = 1);

namespace Cryptopals\Set5\Challenge35;

class MITM1 extends MITM
{
    function sniffData(string $data): string
    {
        $obj = json_decode($data);
        
        if (is_object($obj)) {
            if (is_object($obj) && ($obj->msg === 'neg' || $obj->msg === 'ack')) {
                print "M: manipulating g\n";
                $obj->g = '1';
                $data = json_encode($obj);
            }
            else {
                print "M: sniffed: $data\n";
            }
        }
        else {
            $key = substr(sha1('1', true), 0, 16);
            $iv = substr($data, 0, 16);

            $ctx = new \AES\Context\CBC($key, $iv);
            $message = $this->cbc->decrypt($ctx, substr($data, 16));
            $message = substr($message, 0, -$this->pad->getPadLen($message));

            print "M: sniffed: $message\n";
        }
        
        return $data;
    }
}
