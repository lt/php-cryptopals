<?php declare(strict_types = 1);

namespace Cryptopals\Set5\Challenge38;

class SimpleSRPClient extends SimpleSRP
{
    private $a;

    function __construct(string $I, string $P)
    {
        parent::__construct($I, $P);

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

        $this->S = gmp_powm(
            $this->B,
            gmp_add($this->a, gmp_mul($this->u, $this->x)),
            $this->N
        );
    }

    function setu(string $u)
    {
        $this->u = gmp_init($u, 16);
    }
}
