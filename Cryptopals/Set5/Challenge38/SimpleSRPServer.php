<?php declare(strict_types = 1);

namespace Cryptopals\Set5\Challenge38;

class SimpleSRPServer extends SimpleSRP
{
    private $v;
    private $b;

    function __construct(string $I, string $P)
    {
        parent::__construct($I, $P);

        $this->salt = gmp_strval(gmp_random(), 16);
        $this->x = gmp_init(hash('sha256', $this->salt . $P), 16);
        $this->v = gmp_powm($this->g, $this->x, $this->N);

        $this->b = gmp_random();
        $this->B = gmp_strval(gmp_powm($this->g, $this->b, $this->N), 16);

        $this->u = gmp_init(substr(gmp_strval(gmp_random(), 16), 0, 32), 16);
    }

    function getSalt(): string
    {
        return $this->salt;
    }

    function setA(string $A)
    {
        $this->A = gmp_init($A, 16);

        $this->S = gmp_powm(gmp_mul($this->A, gmp_powm($this->v, $this->u, $this->N)), $this->b, $this->N);
    }

    function getB(): string
    {
        return $this->B;
    }

    function getu(): string
    {
        return gmp_strval($this->u, 16);
    }
}