<?php

/*
 * http://cryptopals.com/sets/5/challenges/38/
 *
 * Offline dictionary attack on simplified SRP
 *
 * S
 * x = SHA256(salt|password)
 * v = g**x % n
 *
 * C->S
 * I, A = g**a % n
 *
 * S->C
 * salt, B = g**b % n, u = 128 bit random number
 *
 * C
 * x = SHA256(salt|password)
 * S = B**(a + ux) % n
 * K = SHA256(S)
 *
 * S
 * S = (A * v ** u)**b % n
 * K = SHA256(S)
 *
 * C->S Send HMAC-SHA256(K, salt)
 * S->C Send "OK" if HMAC-SHA256(K, salt) validates
 *
 * Note that in this protocol, the server's "B" parameter doesn't depend on the password (it's just a Diffie Hellman public key).
 *
 * Make sure the protocol works given a valid password.
 *
 * Now, run the protocol as a MITM attacker: pose as the server and use arbitrary values for b, B, u, and salt.
 *
 * Crack the password from A's HMAC-SHA256(K, salt).
 */

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

    function __construct($I, $P)
    {
        $this->N = gmp_init('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff', 16);
        $this->I = $I;
        $this->P = $P;
    }

    function getProof()
    {
        return hash_hmac('sha256', hash('sha256', gmp_strval($this->S)), $this->salt);
    }
}

class SimpleSRPServer extends SimpleSRP
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
        $this->B = gmp_strval(gmp_powm($this->g, $this->b, $this->N), 16);

        $this->u = gmp_init(substr(gmp_strval(gmp_random(), 16), 0, 32), 16);
    }

    function getSalt()
    {
        return $this->salt;
    }

    function setA($A)
    {
        $this->A = gmp_init($A, 16);

        $this->S = gmp_powm(gmp_mul($this->A, gmp_powm($this->v, $this->u, $this->N)), $this->b, $this->N);
    }

    function getB()
    {
        return $this->B;
    }

    function getu()
    {
        return gmp_strval($this->u, 16);
    }
}

class SimpleSRPClient extends SimpleSRP
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

        $this->S = gmp_powm(
            $this->B,
            gmp_add($this->a, gmp_mul($this->u, $this->x)),
            $this->N
        );
    }

    function setu($u)
    {
        $this->u = gmp_init($u, 16);
    }
}

class SimpleSRPSniffer
{
    private $N;
    private $salt;
    private $A;
    private $B;
    private $u;
    private $proofS;
    private $proofC;
    private $badb;
    private $badB;

    function __construct()
    {
        $this->N = gmp_init('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff', 16);

        $this->badb = gmp_random();
        $this->badB = gmp_strval(gmp_powm('2', $this->badb, $this->N), 16);
    }

    function sniffSalt($salt)
    {
        $this->salt = $salt;
        return $salt;
    }

    function sniffA($A)
    {
        $this->A = gmp_init($A, 16);
        return $A;
    }

    function sniffB($B)
    {
        $this->B = gmp_init($B, 16);

        print "M: Sending bad B\n";
        return $this->badB;
    }

    function sniffu($u)
    {
        $this->u = gmp_init($u, 16);
        return $u;
    }

    function sniffProofS($proof)
    {
        print "M: Sending proof\n";
        return $this->proofS;
    }

    function sniffProofC($proof)
    {
        print "M: Captured HMAC-SHA256(K, salt)\n";
        print "$proof\n";
        print "M: K = SHA256(A * (g ** SHA256(salt|password) % N))\n";
        $this->proofC = $proof;

        $passwords = [
            '123456',
            'password',
            '12345678',
            'qwerty',
            'abc123',
            '123456789',
            '111111',
            '1234567',
            'iloveyou',
            'adobe123',
            '123123',
            'admin',
            '1234567890',
            'letmein',
            'photoshop',
            '1234',
            'monkey',
            'shadow',
            'sunshine',
            '12345',
            'password1',
            'princess',
            'azerty',
            'trustno1',
            '000000',
        ];
        shuffle($passwords);

        foreach ($passwords as $P) {
            $x = gmp_init(hash('sha256', $this->salt . $P), 16);
            $v = gmp_powm('2', $x, $this->N);

            $S = gmp_powm(gmp_mul($this->A, gmp_powm($v, $this->u, $this->N)), $this->badb, $this->N);

            $this->proofS = hash_hmac('sha256', hash('sha256', gmp_strval($S)), $this->salt);

            print "M: '$P' => {$this->proofS}\n";
            if ($this->proofS === $this->proofC) {
                break;
            }
        }

        return $proof;
    }
}

// don't output if we're included into another script.
if (!debug_backtrace()) {
    $I = 'email';
    $P = 'password';

    print "Without MITM:\n";
    $S = new SimpleSRPServer($I, $P);
    $C = new SimpleSRPClient($I, $P);

    $S->setA($C->getA());
    $C->setSalt($S->getSalt());
    $C->setu($S->getu());
    $C->setB($S->getB());

    print $S->getProof() ===
        $C->getProof() ? "OK\n\n" : "Not OK :(\n\n";

    print "With MITM:\n";
    $S = new SimpleSRPServer($I, $P);
    $C = new SimpleSRPClient($I, $P);
    $M = new SimpleSRPSniffer();

    $S->setA($M->sniffA($C->getA()));
    $C->setSalt($M->sniffSalt($S->getSalt()));
    $C->setu($M->sniffu($S->getu()));
    $C->setB($M->sniffB($S->getB()));

    $proofC = $M->sniffProofC($C->getProof());
    $proofS = $M->sniffProofS($S->getProof());

    print $proofS === $proofC ? "OK\n\n" : "Not OK :(\n\n";
}
