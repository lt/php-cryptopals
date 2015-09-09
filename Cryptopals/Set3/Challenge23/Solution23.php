<?php declare(strict_types = 1);

namespace Cryptopals\Set3\Challenge23;

use Cryptopals\Set3\Challenge21\Solution21;

class Solution23 extends Solution21
{
    protected $vanillaMT;

    protected function setUp(): bool
    {
        $this->vanillaMT = new Solution21;
        $this->vanillaMT->init(time()); // :D :D

        return true;
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

    protected function execute(): bool
    {
        $success = 1;
        for ($i = 0; $i < 624; $i++) {
            $this->MT[] = $this->untemper($this->vanillaMT->int32());
        }
        $this->index = $i;

        print "Original:      Clone:\n";
        for ($i = 0; $i < 10; $i++) {
            $original = $this->vanillaMT->int32();
            $clone = $this->int32();
            $success &= ($original === $clone);

            print str_pad((string)$original, 15) . $clone . "\n";
        }

        return (bool)$success;
    }
}
