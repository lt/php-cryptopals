<?php declare(strict_types = 1);

namespace Cryptopals\Set3\Challenge21;

use Cryptopals\Solution;
use MersenneTwister\MT;

class Solution21 extends Solution
{
    protected function execute(): bool
    {
        $mt = new MT;
        $success = 1;

        $mt->init(12345678);

        $rand = $mt->int32();
        print "$rand\n";
        $success &= ($rand === 1055721139);

        $rand = $mt->int32();
        print "$rand\n";
        $success &= ($rand === 3422054626);

        $rand = $mt->int32();
        print "$rand\n";
        $success &= ($rand === 2561641375);

        return (bool)$success;
    }
}
