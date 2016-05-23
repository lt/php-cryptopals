<?php declare(strict_types = 1);

namespace Cryptopals\Set4\Challenge29;

use Cryptopals\Set4\Challenge28\SHA1;
use Cryptopals\Set4\Challenge28\SHA1Context;
use Cryptopals\Solution;

class Solution29 implements Solution
{
    protected $messageAPI;
    protected $sha1;

    function __construct(MessageAPI $messageAPI, SHA1 $sha1)
    {
        $this->messageAPI = $messageAPI;
        $this->sha1 = $sha1;
    }

    protected function getGlue(string $message, int $offset = 0): string
    {
        $messageLen = strlen($message) + $offset;
        $padLen = 64 - ($messageLen % 64);

        if ($padLen < 9) {
            $padLen += 64;
        }

        return "\x80" . str_repeat("\0", $padLen - 5) . pack('N', $messageLen << 3);
    }

    function execute(): bool
    {
        $message = 'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon';
        $mac = $this->messageAPI->sign($message);

        // attacker has access to message and mac, but not key
        print "Message: $message\n";
        print "Old MAC: " . bin2hex($mac) . "\n\n";

        $ctx = new SHA1Context();
        $digest = array_values(unpack('N5', $mac));
        $messageLen = strlen($message);
        $suffix = ';admin=true';

        $keyLen = 0;
        while ($keyLen < 33) {
            $glue = $this->getGlue($message, $keyLen);

            $this->sha1->reset($ctx);

            $ctx->messageDigest = $digest;
            $ctx->lengthLow = ($messageLen + $keyLen + strlen($glue)) << 3;

            $this->sha1->input($ctx, $suffix);
            $this->sha1->result($ctx);

            $newMac = pack('N5', ...$ctx->messageDigest);

            if ($this->messageAPI->verify($message . $glue . $suffix, $newMac)) {
                print "Key len: $keyLen\n";
                print "Message: $message$glue$suffix\n";
                print "New MAC: " . bin2hex($newMac) . "\n";
                return true;
            }

            $keyLen ++;
        }

        return false;
    }
}
