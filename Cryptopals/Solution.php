<?php declare(strict_types = 1);

namespace Cryptopals;

abstract class Solution
{
    protected function setUp(): bool
    {
        return true;
    }

    abstract protected function execute(): bool;

    final function runSolution(): bool
    {
        return $this->setUp() && $this->execute();
    }
}
