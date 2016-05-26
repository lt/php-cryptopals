<?php declare(strict_types = 1);

namespace Cryptopals\Set6\Challenge45;

/*
Same as Challenge 43 but doesn't throw exceptions
*/
use Cryptopals\Set6\Challenge43\DSA;

class WeakDSA extends DSA
{
    protected function validateR(\GMP $r) {}
    protected function validateS(\GMP $s) {}
    protected function validateSignature(\GMP $r, \GMP $s) {}
}
