<?php

/*
 * http://cryptopals.com/sets/3/challenges/21/
 *
 * Implement the MT19937 Mersenne Twister RNG
 *
 * You can get the psuedocode for this from Wikipedia.
 *
 * If you're writing in Python, Ruby, or (gah) PHP, your language is probably already giving you MT19937 as "rand()"; don't use rand(). Write the RNG yourself.
 */

if (PHP_INT_SIZE < 8) {
    throw new Exception('64 bit PHP required!');
}

class MT19937
{
    private $MT = [];
    private $index = 624;

    function init($seed = 5489)
    {
        $MT = [$seed];

        for ($i = 0; $i < 623; $i++) {
            $MT[$i + 1] = (1812433253 * ($MT[$i] ^ ($MT[$i] >> 30)) + $i) & 0xffffffff;
        }

        $this->MT = $MT;
        $this->index = 624;
    }

    function int32()
    {
        if ($this->index > 623) {
            for ($i = 0; $i < 227; $i++) {
                $y = ($this->MT[$i] & 0x80000000) | ($this->MT[$i + 1] & 0x7fffffff);
                $this->MT[$i] = $this->MT[$i + 397] ^ ($y >> 1) ^ (($y & 1) * 0x9908b0df);
            }

            for (; $i < 623; $i++) {
                $y = ($this->MT[$i] & 0x80000000) | ($this->MT[$i + 1] & 0x7fffffff);
                $this->MT[$i] = $this->MT[$i - 227] ^ ($y >> 1) ^ (($y & 1) * 0x9908b0df);
            }

            $y = ($this->MT[623] & 0x80000000) | ($this->MT[0] & 0x7fffffff);
            $this->MT[623] = $this->MT[396] ^ ($y >> 1) ^ (($y & 1) * 0x9908b0df);

            $this->index = 0;
        }

        $y = $this->MT[$this->index++];

        $y ^= $y >> 11;
        $y ^= ($y << 7) & 0x9d2c5680;
        $y ^= ($y << 15) & 0xefc60000;

        return $y ^ ($y >> 18);
    }
}

// don't output if we're included into another script.
if (!debug_backtrace()) {
    $mt = new MT19937();
    $mt->init(time()); // :D

    print "Getting some random numbers:\n";
    for ($i = 0; $i < 10; $i++) {
        print $mt->int32() . "\n";
    }
}