<?php declare(strict_types = 1);

namespace Cryptopals\Set2\Challenge15;

use Cryptopals\Solution;

class Solution15 implements Solution
{
    function execute(): bool
    {
        $success = true;

        print 'Testing \'ICE ICE BABY\x04\x04\x04\x04\' has pad length of 4: ';
        try {
            $success = $success && (PKCS7::getPaddingLength("ICE ICE BABY\x04\x04\x04\x04") === 4);
            print "OK\n";
        }
        catch (\Exception $e) {
            $success = false;
            print "FAIL\n";
        }

        print 'Testing \'ICE ICE BABY\x05\x05\x05\x05\' is invalid: ';
        try {
            PKCS7::depad("ICE ICE BABY\x05\x05\x05\x05");
            $success = false;
            print "FAIL\n";
        }
        catch (\Exception $e) {
            $success = $success && true;
            print "OK\n";
        }

        print 'Testing \'ICE ICE BABY\x01\x02\x03\x04\' is invalid: ';
        try {
            PKCS7::depad("ICE ICE BABY\x01\x02\x03\x04");
            $success = false;
            print "FAIL\n";
        }
        catch (\Exception $e) {
            $success = $success && true;
            print "OK\n";
        }

        return $success;
    }
}
