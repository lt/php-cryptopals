<?php declare(strict_types = 1);

namespace Cryptopals\Set4\Challenge32;

use Cryptopals\Solution;

class Solution32 implements Solution
{
    protected $messageAPI;

    function __construct(MessageAPI $messageAPI)
    {
        $this->messageAPI = $messageAPI;
    }

    function execute(): bool
    {
        // attacker has a file but not the key to generate valid signature
        $file = 'my evil file';
        $crackedSig = str_repeat("\0", 20);

        print "This will take an even longer while.\n\n";

        for ($x = 0; $x < 20; $x++) {
            $timings = [];

            for ($i = 0; $i < 256; $i++) {
                $crackedSig[$x] = chr($i);

                for ($samples = 0; $samples < 10; $samples++) {
                    $start = microtime(true);
                    if ($this->messageAPI->verify($file, $crackedSig) === 500) {
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
        print bin2hex($this->messageAPI->sign($file)) . "\n";
        return $this->messageAPI->verify($file, $crackedSig) === 200;
    }
}
