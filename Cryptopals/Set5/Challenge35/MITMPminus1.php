<?php declare(strict_types = 1);

namespace Cryptopals\Set5\Challenge35;

class MITMPminus1 extends MITM
{
    private $Pminus1;

    function sniffData(string $data): string
    {
        $obj = json_decode($data);
        
        if (is_object($obj)) {
            if ($obj->msg === 'neg' || $obj->msg === 'ack') {
                print "M: manipulating g\n";
                $this->Pminus1 = gmp_strval(gmp_sub(gmp_init($obj->p, 16), gmp_init(1)), 16);
                $obj->g = $this->Pminus1;
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

            // kind of dirty I guess, but gets the job done.
            $obj = json_decode($message);
            if (!is_object($obj)) {
                $key = substr(sha1($this->Pminus1, true), 0, 16);
                $iv = substr($data, 0, 16);

                $ctx = new \AES\Context\CBC($key, $iv);
                $message = $this->cbc->decrypt($ctx, substr($data, 16));
                $message = substr($message, 0, -$this->pad->getPadLen($message));
            }

            print "M: sniffed: $message\n";
        }
        
        return $data;
    }
}
