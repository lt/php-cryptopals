<?php declare(strict_types = 1);

namespace Cryptopals\Set3\Challenge21;

use Cryptopals\Solution;

class Solution21 extends Solution
{
    protected $MT = [];
    protected $index = 625;

    function init($seed = 5489)
    {
        $MT = [$seed & 0xffffffff];

        for ($i = 1; $i < 624; $i++) {
            $MT[$i] = (1812433253 * ($MT[$i - 1] ^ ($MT[$i - 1] >> 30)) + $i) & 0xffffffff;
        }

        $this->MT = $MT;
        $this->index = 624;
    }

    protected function twist($m, $u, $v)
    {
        $y = ($u & 0x80000000) | ($v & 0x7fffffff);
        return $m ^ (($y >> 1) & 0x7fffffff) ^ (0x9908b0df * ($v & 1));
    }

    function int32()
    {
        if ($this->index >= 624) {
            if ($this->index === 625) {
                $this->init();
            }

            for ($i = 0; $i < 227; $i++) {
                $this->MT[$i] = $this->twist($this->MT[$i + 397], $this->MT[$i], $this->MT[$i + 1]);
            }
            for (; $i < 623; $i++) {
                $this->MT[$i] = $this->twist($this->MT[$i - 227], $this->MT[$i], $this->MT[$i + 1]);
            }
            $this->MT[623] = $this->twist($this->MT[396], $this->MT[623], $this->MT[0]);

            $this->index = 0;
        }

        $y = $this->MT[$this->index++];

        $y ^= ($y >> 11) & 0x001fffff;
        $y ^= ($y <<  7) & 0x9d2c5680;
        $y ^= ($y << 15) & 0xefc60000;
        $y ^= ($y >> 18) & 0x00003fff;

        return $y;
    }

    protected function execute(): bool
    {
        $success = 1;

        $this->init(12345678);

        $rand = $this->int32();
        print "$rand\n";
        $success &= ($rand === 1055721139);

        $rand = $this->int32();
        print "$rand\n";
        $success &= ($rand === 3422054626);

        $rand = $this->int32();
        print "$rand\n";
        $success &= ($rand === 2561641375);

        return (bool)$success;
    }
}
