<?php declare(strict_types = 1);

namespace Cryptopals\Set4\Challenge30;

use Cryptopals\Solution;

class Solution30 extends Solution
{
    protected $apiKey;

    protected function setUp(): bool
    {
        $this->apiKey = random_bytes(mt_rand(8, 32));
        return true;
    }

    protected function apiSign(string $message): string
    {
        return $this->md4KeyedMAC($this->apiKey, $message);
    }

    protected function apiVerify(string $message, string $mac): bool
    {
        return hash_equals($mac, $this->apiSign($message));
    }

    protected function md4KeyedMAC(string $key, string $message): string
    {
        $c = new MD4Context();

        $m = new MD4();
        $m->init($c);
        $m->update($c, $key . $message);

        return $m->result($c);
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

    protected function execute(): bool
    {
        $message = 'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon';
        $mac = $this->apiSign($message);

        // attacker has access to message and mac, but not key

        print "Message: $message\n";
        print "Old MAC: " . bin2hex($mac) . "\n\n";

        $m = new MD4();
        $c = new MD4Context();
        $digest = array_values(unpack('V4', $mac));
        $messageLen = strlen($message);
        $suffix = ';admin=true';

        $keyLen = 0;
        while ($keyLen < 33) {
            $glue = $this->getGlue($message, $keyLen);

            $m->init($c);

            list($c->a, $c->b, $c->c, $c->d) = $digest;

            $c->lo = ($messageLen + $keyLen + strlen($glue));

            $m->update($c, $suffix);

            $newMac = $m->result($c);

            if ($this->apiVerify($message . $glue . $suffix, $newMac)) {
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
