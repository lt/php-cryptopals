<?php declare(strict_types = 1);

namespace Cryptopals\Set4\Challenge30;

use Cryptopals\Solution;

class Solution30 implements Solution
{
    protected $messageAPI;
    protected $md4;

    function __construct(MessageAPI $messageAPI, MD4 $md4)
    {
        $this->messageAPI = $messageAPI;
        $this->md4 = $md4;
    }

    protected function getGlue(string $message, int $offset = 0): string
    {
        $messageLen = strlen($message) + $offset;
        $padLen = 64 - ($messageLen % 64);

        if ($padLen < 9) {
            $padLen += 64;
        }

        $messageLen <<= 3;

        return "\x80" . str_repeat("\0", $padLen - 9) . pack('C4', $messageLen, $messageLen >> 8, $messageLen >> 16, $messageLen >> 24) . "\0\0\0\0";
    }

    function execute(): bool
    {
        $message = 'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon';
        $mac = $this->messageAPI->sign($message);

        // attacker has access to message and mac, but not key

        print "Message: $message\n";
        print "Old MAC: " . bin2hex($mac) . "\n\n";

        $ctx = new MD4Context();
        $digest = array_values(unpack('V4', $mac));
        $messageLen = strlen($message);
        $suffix = ';admin=true';

        $keyLen = 0;
        while ($keyLen < 33) {
            $glue = $this->getGlue($message, $keyLen);

            $this->md4->init($ctx);
            list($ctx->a, $ctx->b, $ctx->c, $ctx->d) = $digest;
            $ctx->lo = ($messageLen + $keyLen + strlen($glue));

            $this->md4->update($ctx, $suffix);
            $newMac = $this->md4->result($ctx);
            if ($this->messageAPI->verify($message . $glue . $suffix, $newMac)) {
                print "Key len: $keyLen\n\n";
                print "Message: $message$glue$suffix\n";
                print "New MAC: " . bin2hex($newMac) . "\n\n";
                return true;
            }

            $keyLen ++;
        }

        return false;
    }
}
