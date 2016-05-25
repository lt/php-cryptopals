<?php declare(strict_types = 1);

namespace Cryptopals\Set6\Challenge43;

class DSA
{
    public $L;
    public $N;
    public $p;
    public $q;
    public $g;

    function __construct()
    {
        $this->L = 1024;
        $this->N = 160; // SHA1

        $this->p = gmp_init('0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1');
        $this->q = gmp_init('0xf4f47f05794b256174bba6e9b396a7707e563c5b');
        $this->g = gmp_init('0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291');
    }

    protected function validateR(\GMP $r)
    {
        if ($r == 0) {
            throw new \InvalidArgumentException('Bad k (r == 0)');
        }
    }

    protected function validateS(\GMP $s)
    {
        if ($s == 0) {
            throw new \InvalidArgumentException('Bad k (s == 0)');
        }
    }

    function sign(string $message, \GMP $privateKey, \GMP $subKey)
    {
        $r = gmp_powm($this->g, $subKey, $this->p) % $this->q;
        $this->validateR($r);

        $h = gmp_import(sha1($message, true));
        $s = (gmp_invert($subKey, $this->q) * ($h + $privateKey * $r)) % $this->q;
        $this->validateS($s);

        return [$r, $s];
    }

    protected function validateSignature(\GMP $r, \GMP $s)
    {
        //Reject the signature if 0 < r < q or 0 < s < q is not satisfied.
        if (!(0 < $r && $r < $this->q)) {
            throw new \InvalidArgumentException('Bad signature (r)');
        }
        if (!(0 < $s && $s < $this->q)) {
            throw new \InvalidArgumentException('Bad signature (s)');
        }
    }

    function verify(string $message, array $signature, \GMP $publicKey): bool
    {
        list($r, $s) = $signature;
        $this->validateSignature($r, $s);

        $h = gmp_import(sha1($message, true));
        $w = gmp_invert($s, $this->q);
        $u1 = ($h * $w) % $this->q;
        $u2 = ($r * $w) % $this->q;
        $v = ((gmp_powm($this->g, $u1, $this->p) * gmp_powm($publicKey, $u2, $this->p)) % $this->p) % $this->q;

        return $v == $r;
    }
}
