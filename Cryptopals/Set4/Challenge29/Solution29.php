<?php declare(strict_types = 1);

namespace Cryptopals\Set4\Challenge29;

use Cryptopals\Set4\Challenge28\SHA1;
use Cryptopals\Set4\Challenge28\SHA1Context;
use Cryptopals\Set4\Challenge28\Solution28;

class Solution29 extends Solution28
{
    protected $apiKey;

    protected function setUp(): bool
    {
        $this->apiKey = random_bytes(mt_rand(8, 32));
        return true;
    }

    protected function apiSign(string $message): string
    {
        return $this->sha1KeyedMAC($this->apiKey, $message);
    }

    protected function apiVerify(string $message, string $mac): bool
    {
        return hash_equals($mac, $this->apiSign($message));
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


    protected function execute(): bool
    {
        $message = 'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon';
        $mac = $this->apiSign($message);

        // attacker has access to message and mac, but not key

        print "Message: $message\n";
        print "Old MAC: " . bin2hex($mac) . "\n\n";


        $s = new SHA1();
        $c = new SHA1Context();
        $digest = array_values(unpack('N5', $mac));
        $messageLen = strlen($message);
        $suffix = ';admin=true';

        $keyLen = 0;
        while ($keyLen < 33) {
            $glue = $this->getGlue($message, $keyLen);

            $s->reset($c);

            $c->messageDigest = $digest;
            $c->lengthLow = ($messageLen + $keyLen + strlen($glue)) << 3;

            $s->input($c, $suffix);
            $s->result($c);

            $newMac = pack('N5', ...$c->messageDigest);

            if ($this->apiVerify($message . $glue . $suffix, $newMac)) {
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
