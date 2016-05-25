<?php declare(strict_types = 1);

namespace Cryptopals\Set6\Challenge42;

use Cryptopals\Solution;

class Solution42 implements Solution
{
    protected $messageAPI;
    
    function __construct(MessageAPI $messageAPI)
    {
        $this->messageAPI = $messageAPI;
    }

    function execute(): bool
    {
        $message = 'hi mom';

        print 'Testing with real signature: ';
        $kownSignature = $this->messageAPI->sign($message);
        $ok = $this->messageAPI->verify($message, $kownSignature);
        print $ok ? "OK\n" : "FAIL\n";

        $hash = sha1($message, true);
        $badSigRaw = str_pad("\0\1\xff\0ASN1GOOP{$hash}", 128, "\0", STR_PAD_RIGHT);
        $badSig = gmp_export(gmp_root(gmp_import($badSigRaw), 3) + 1);

        print 'Testing with fake signature: ';
        $ok = $this->messageAPI->verify($message, $badSig);
        print $ok ? "OK\n" : "FAIL\n";

        return $ok;
    }
}
