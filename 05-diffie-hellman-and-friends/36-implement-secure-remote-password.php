<?php

/*
 * http://cryptopals.com/sets/5/challenges/36/
 *
 * Implement Secure Remote Password (SRP)
 *
 * To understand SRP, look at how you generate an AES key from DH; now, just observe you can do the "opposite" operation an generate a numeric parameter from a hash. Then:
 *
 * Replace A and B with C and S (client & server)
 *
 * C & S
 * Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
 *
 * S
 * 1. Generate salt as random integer
 * 2. Generate string xH=SHA256(salt|password)
 * 3. Convert xH to integer x somehow (put 0x on hexdigest)
 * 4. Generate v=g**x % N
 * 5. Save everything but x, xH
 *
 * C->S
 * Send I, A=g**a % N (a la Diffie Hellman)
 * S->C
 * Send salt, B=kv + g**b % N
 * S, C
 * Compute string uH = SHA256(A|B), u = integer of uH
 *
 * C
 * 1. Generate string xH=SHA256(salt|password)
 * 2. Convert xH to integer x somehow (put 0x on hexdigest)
 * 3. Generate S = (B - k * g**x)**(a + u * x) % N
 * 4. Generate K = SHA256(S)
 *
 * S
 * 1. Generate S = (A * v**u) ** b % N
 * 2. Generate K = SHA256(S)
 *
 * C->S
 * Send HMAC-SHA256(K, salt)
 * S->C
 * Send "OK" if HMAC-SHA256(K, salt) validates
 *
 * You're going to want to do this at a REPL of some sort; it may take a couple tries.
 *
 * It doesn't matter how you go from integer to string or string to integer (where things are going in or out of SHA256) as long as you do it consistently. I tested by using the ASCII decimal representation of integers as input to SHA256, and by converting the hexdigest to an integer when processing its output.
 *
 * This is basically Diffie Hellman with a tweak of mixing the password into the public keys. The server also takes an extra step to avoid storing an easily crackable password-equivalent.
 */

class SRP
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

    function __construct($I, $P)
    {
        $this->N = gmp_init('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff', 16);
        $this->I = $I;
        $this->P = $P;
    }

    function getK()
    {
        return hash('sha256', gmp_strval($this->S));
    }

    function getProof()
    {
        return hash_hmac('sha256', $this->getK(), $this->salt);
    }
}

class SRPServer extends SRP
{
    private $v;
    private $b;

    function __construct($I, $P)
    {
        parent::__construct($I, $P);

        $this->salt = gmp_strval(gmp_random(), 16);
        $this->x = gmp_init(hash('sha256', $this->salt . $P), 16);
        $this->v = gmp_powm($this->g, $this->x, $this->N);

        $this->b = gmp_random();
        $this->B = gmp_strval(gmp_powm(gmp_add(gmp_mul($this->k, $this->v), gmp_powm($this->g, $this->b, $this->N)), '1', $this->N), 16);
    }

    function getSalt()
    {
        return $this->salt;
    }

    function setA($A)
    {
        $this->A = gmp_init($A, 16);
        $this->u = gmp_init(hash('sha256', $A . $this->B), 16);

        $this->S = gmp_powm(gmp_mul($this->A, gmp_powm($this->v, $this->u, $this->N)), $this->b, $this->N);
    }

    function getB()
    {
        return $this->B;
    }
}

class SRPClient extends SRP
{
    private $a;

    function __construct($I, $P)
    {
        parent::__construct($I, $P);

        $this->a = gmp_random();
        $this->A = gmp_strval(gmp_powm($this->g, $this->a, $this->N), 16);
    }

    function setSalt($salt)
    {
        $this->salt = $salt;
        $this->x = gmp_init(hash('sha256', $salt . $this->P), 16);
    }

    function getA()
    {
        return $this->A;
    }

    function setB($B)
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

// don't output if we're included into another script.
if (!debug_backtrace()) {
    $I = 'email';
    $P = 'password';

    $S = new SRPServer($I, $P);
    $C = new SRPClient($I, $P);

    $C->setSalt($S->getSalt());
    $S->setA($C->getA());
    $C->setB($S->getB());

    print $S->getProof() === $C->getProof() ? "OK\n\n" : "Not OK :(\n\n";
}
