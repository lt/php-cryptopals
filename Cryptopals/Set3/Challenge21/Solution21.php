<?php declare(strict_types = 1);

namespace Cryptopals\Set3\Challenge21;

use Cryptopals\Solution;
use MersenneTwister\MT;

class Solution21 implements Solution
{
    protected $mt;
    
    function __construct(MT $mt)
    {
        $this->mt = $mt;
    }

    function execute(): bool
    {
        $success = 1;

        $this->mt->init(12345678);

        $rand = $this->mt->int32();
        print "$rand\n";
        $success &= ($rand === 1055721139);

        $rand = $this->mt->int32();
        print "$rand\n";
        $success &= ($rand === 3422054626);

        $rand = $this->mt->int32();
        print "$rand\n";
        $success &= ($rand === 2561641375);

        return (bool)$success;
    }
}
