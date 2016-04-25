<?php declare(strict_types = 1);

namespace Cryptopals\Set4\Challenge32;

use Cryptopals\Set4\Challenge31\Solution31;

class Solution32 extends Solution31
{
    protected function insecureCompare(string $one, string $two): bool
    {
        $three = unpack('C*', $one ^ $two);
        foreach ($three as $k => $v) {
            if ($v) {
                usleep(5000 * $k);
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

        print "This will take an even longer while.\n\n";
        print bin2hex($this->apiSign($file)) . "\n\n";

        for ($x = 0; $x < 20; $x++) {
            $timings = [];

            for ($i = 0; $i < 256; $i++) {
                $crackedSig[$x] = chr($i);

                for ($samples = 0; $samples < 10; $samples++) {
                    $start = microtime(true);
                    if ($this->apiVerify($file, $crackedSig) === 500) {
                        $stop = microtime(true) - $start;
                        if (isset($timings[$i])) {
                            $timings[$i] += $stop;
                        }
                        else {
                            $timings[$i] = $stop;
                        }
                    }
                    else {
                        $timings[$i] = PHP_INT_MAX;
                    }
                }
                $timings[$i] /= $samples;
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
