<?php declare(strict_types = 1);

namespace Cryptopals\Set5\Challenge38;

class SimpleSRP
{
    protected $N;
    protected $g = '2';
    protected $k = '3';

    protected $I;
    protected $P;

    protected $salt;
    protected $x;
    protected $A;
    protected $B;
    protected $u;
    protected $S;

    function __construct()
    {
        $this->N = gmp_init('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff', 16);
    }
    
    function setCredentials(string $I, string $P)
    {
        $this->I = $I;
        $this->P = $P;
    }

    function getProof(): string
    {
        return hash_hmac('sha256', hash('sha256', gmp_strval($this->S)), $this->salt);
    }
}
