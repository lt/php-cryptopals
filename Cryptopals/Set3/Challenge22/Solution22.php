<?php declare(strict_types = 1);

namespace Cryptopals\Set3\Challenge22;

use Cryptopals\Set3\Challenge21\Solution21;

class Solution22 extends Solution21
{
    protected function execute(): bool
    {
        // Sorry, going for simulated passage of time.

        $now = time();

        $this->init($now - mt_rand(80, 2000)); // randception
        $r = $this->int32();

        print "Random number from the past: $r\n";
        print "Time is " . date('H:i:s', $now) . "\n\n";

        for ($i = 0; $i <= 2000; $i++) {
            $this->init($now - $i);
            if ($this->int32() === $r) {
                print "RNG was seeded at: " . date('H:i:s', $now - $i) . "\n";
                return true;
            }
        }

        return false;
    }
}
