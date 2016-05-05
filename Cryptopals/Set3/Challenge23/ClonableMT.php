<?php declare(strict_types = 1);

namespace Cryptopals\Set3\Challenge23;

use MersenneTwister\MT;

class ClonableMT extends MT
{
    function setState(array $state)
    {
        $this->state = $state;
    }

    function setIndex(int $index)
    {
        $this->index = $index;
    }
}
