<?php declare(strict_types = 1);

namespace Cryptopals\Set3\Challenge22;

use Cryptopals\Solution;
use MersenneTwister\MT;

class Solution22 extends Solution
{
    protected function execute(): bool
    {
        $mt = new MT;

        // Sorry, going for simulated passage of time.
        $now = time();

        $mt->init($now - mt_rand(80, 2000)); // randception
        $r = $mt->int32();

        print "Random number from the past: $r\n";
        print "Time is " . date('H:i:s', $now) . "\n\n";

        for ($i = 0; $i <= 2000; $i++) {
            $mt->init($now - $i);
            if ($mt->int32() === $r) {
                print "RNG was seeded at: " . date('H:i:s', $now - $i) . "\n";
                return true;
            }
        }

        return false;
    }
}
