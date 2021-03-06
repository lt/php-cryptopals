<?php declare(strict_types = 1);

namespace Cryptopals\Set3\Challenge23;

use Cryptopals\Solution;
use MersenneTwister\MT;

class Solution23 implements Solution
{
    protected $mt;
    protected $mtClone;

    function __construct(MT $mt, ClonableMT $mtClone)
    {
        $this->mt = $mt;
        $this->mtClone = $mtClone;
    }

    protected function untemper($value)
    {
        $y = $value ^ ($value >> 18); // Only 14 bits affected, so we can restore them all at once
        $y ^= ($y << 15) & 0xefc60000; // Only 15 bits affected (17 remain after shift, but mask makes it 15)

        // here we have to restore 7 bits at a time
        $x = $y ^ (($y << 7) & 0x9d2c5680); // 14
        $x = $y ^ (($x << 7) & 0x9d2c5680); // 21
        $x = $y ^ (($x << 7) & 0x9d2c5680); // 28
        $y ^= ($x << 7) & 0x9d2c5680;

        // here we have to restore 11 bits at a time
        $x = $y ^ ($y >> 11);
        return $y ^ ($x >> 11);
    }

    function execute(): bool
    {
        $success = true;
        $state = [];

        for ($i = 0; $i < 624; $i++) {
            $state[] = $this->untemper($this->mt->int32());
        }
        $this->mtClone->setState($state);
        $this->mtClone->setIndex($i);

        print "Original:      Clone:\n";
        for ($i = 0; $i < 10; $i++) {
            $original = $this->mt->int32();
            $clone = $this->mtClone->int32();
            $success &= ($original === $clone);

            print str_pad((string)$original, 15) . $clone . "\n";
        }

        return (bool)$success;
    }
}
