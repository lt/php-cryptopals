<?php declare(strict_types = 1);

namespace Cryptopals\Set3\Challenge22;

use Cryptopals\Solution;
use MersenneTwister\MT;

class Solution22 implements Solution
{
    protected $mt;

    function __construct(MT $mt)
    {
        $this->mt = $mt;
    }

    function execute(): bool
    {
        // Sorry, going for simulated passage of time.
        $now = time();

        $this->mt->init($now - mt_rand(80, 2000)); // randception
        $r = $this->mt->int32();

        print "Random number from the past: $r\n";
        print "Time is " . date('H:i:s', $now) . "\n\n";

        for ($i = 0; $i <= 2000; $i++) {
            $this->mt->init($now - $i);
            if ($this->mt->int32() === $r) {
                print "RNG was seeded at: " . date('H:i:s', $now - $i) . "\n";
                return true;
            }
        }

        return false;
    }
}
