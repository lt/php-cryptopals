<?php declare(strict_types = 1);

namespace Cryptopals\Set5\Challenge36;

class SRPClient extends SRP
{
    private $a;
    
    function setCredentials(string $I, string $P)
    {
        parent::setCredentials($I, $P);
        $this->a = gmp_random();
        $this->A = gmp_strval(gmp_powm($this->g, $this->a, $this->N), 16);
    }

    function setSalt(string $salt)
    {
        $this->salt = $salt;
        $this->x = gmp_init(hash('sha256', $salt . $this->P), 16);
    }

    function getA(): string
    {
        return $this->A;
    }

    function setB(string $B)
    {
        $this->B = gmp_init($B, 16);
        $this->u = gmp_init(hash('sha256', $this->A . $B), 16);

        $this->S = gmp_powm(
            gmp_sub($this->B, gmp_mul($this->k, gmp_powm($this->g, $this->x, $this->N))),
            gmp_add($this->a, gmp_mul($this->u, $this->x)),
            $this->N
        );
    }
}
