<?php declare(strict_types = 1);

namespace Cryptopals\Set5\Challenge36;

class SRPServer extends SRP
{
    private $v;
    private $b;

    function setCredentials(string $I, string $P)
    {
        parent::setCredentials($I, $P);
        $this->salt = gmp_strval(gmp_random(), 16);
        $this->x = gmp_init(hash('sha256', $this->salt . $P), 16);
        $this->v = gmp_powm($this->g, $this->x, $this->N);

        $this->b = gmp_random();
        $this->B = gmp_strval(gmp_powm(gmp_add(gmp_mul($this->k, $this->v), gmp_powm($this->g, $this->b, $this->N)), '1', $this->N), 16);
    }

    function getSalt(): string
    {
        return $this->salt;
    }

    function setA(string $A)
    {
        $this->A = gmp_init($A, 16);
        $this->u = gmp_init(hash('sha256', $A . $this->B), 16);

        $this->S = gmp_powm(gmp_mul($this->A, gmp_powm($this->v, $this->u, $this->N)), $this->b, $this->N);
    }

    function getB(): string
    {
        return $this->B;
    }
}
