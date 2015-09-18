<?php declare(strict_types = 1);

namespace Cryptopals\Set5\Challenge38;

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

    function sniffSalt(string $salt): string
    {
        $this->salt = $salt;
        return $salt;
    }

    function sniffA(string $A): string
    {
        $this->A = gmp_init($A, 16);
        return $A;
    }

    function sniffB(string $B): string
    {
        $this->B = gmp_init($B, 16);

        print "M: Sending bad B\n";
        return $this->badB;
    }

    function sniffu(string $u): string
    {
        $this->u = gmp_init($u, 16);
        return $u;
    }

    function sniffProofS(string $proof): string
    {
        print "M: Sending proof\n";
        return $this->proofS;
    }

    function sniffProofC(string $proof): string
    {
        print "M: Captured HMAC-SHA256(K, salt)\n";
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
                print "\nM: Password => '$P'\n";
                break;
            }
        }

        return $proof;
    }
}
