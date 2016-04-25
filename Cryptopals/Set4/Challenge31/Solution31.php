<?php declare(strict_types = 1);

namespace Cryptopals\Set4\Challenge31;

use Cryptopals\Set4\Challenge28\Solution28;

class Solution31 extends Solution28
{
    protected $apiKey;

    protected function setUp(): bool
    {
        $this->apiKey = random_bytes(mt_rand(8, 32));
        return true;
    }

    protected function apiSign(string $message): string
    {
        return $this->HMACSHA1($this->apiKey, $message);
    }

    protected function apiVerify(string $message, string $mac): int
    {
        return $this->insecureCompare($mac, $this->apiSign($message)) ? 200 : 500;
    }
    
    protected function HMACSHA1(string $key, string $message): string
    {
        $keyLen = strlen($key);

        if ($keyLen > 64) {
            $key = $this->sha1KeyedMAC('', $message);
        }
        else if ($keyLen < 64) {
            $key .= str_repeat("\0", 64 - $keyLen);
        }

        $oPad = str_repeat("\x5c", 64) ^ $key;
        $iPad = str_repeat("\x36", 64) ^ $key;

        return $this->sha1KeyedMAC($oPad, $this->sha1KeyedMAC($iPad, $message));
    }

    protected function insecureCompare(string $one, string $two): bool
    {
        $three = unpack('C*', $one ^ $two);
        foreach ($three as $k => $v) {
            if ($v) {
                // 50ms seems a bit long considering we didn't do the web api
                usleep(10000 * $k);
                return false;
            }
        }

        return true;
    }
    
    protected function execute(): bool
    {
        // attacker has a file but not the key to generate valid signature

        $file = 'my evil file';
        $crackedSig = str_repeat("\0", 20);

        print "This will take a while.\n\n";
        print bin2hex($this->apiSign($file)) . "\n\n";

        for ($x = 0; $x < 20; $x++) {
            $timings = [];

            for ($i = 0; $i < 256; $i++) {
                $crackedSig[$x] = chr($i);
                $start = microtime(true);
                if ($this->apiVerify($file, $crackedSig) === 500) {
                    $timings[$i] = microtime(true) - $start;
                }
                else {
                    $timings[$i] = PHP_INT_MAX;
                }
            }

            arsort($timings);
            $crackedSig[$x] = chr(key($timings));
            print bin2hex($crackedSig) . "\n";
        }

        print "\nActual signature:\n";
        print bin2hex($this->apiSign($file)) . "\n";
        return $this->apiVerify($file, $crackedSig) === 200;
    }
}
