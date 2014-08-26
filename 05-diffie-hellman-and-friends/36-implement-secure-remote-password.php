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

/*
// C & S have agreed:
$N = gmp_init('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff', 16);
$g = '2';
$k = '3';
$I = 'email';
$P = 'password';

// S
$salt = gmp_random();
$xH = hash('sha256', gmp_strval($salt) . $P);
$x = gmp_init($xH, 16);
$v = gmp_powm($g, $x, $N);

// C -> S
$a = gmp_random();
$A = gmp_powm($g, $a, $N);

// S -> C
$b = gmp_random();
$B = gmp_powm(gmp_add(gmp_mul($k, $v), gmp_powm($g, $b, $N)), '1', $N);

// S and C
$uH = hash('sha256', gmp_strval($A) . gmp_strval($B));
$u = gmp_init($uH, 16);

// C
$xH = hash('sha256', gmp_strval($salt) . $P);
$x = gmp_init($xH, 16);
$Sc = gmp_powm(
        gmp_mul(gmp_sub($B, $k), gmp_powm($g, $x, $N)),
        gmp_add($a, gmp_mul($u, $x)),
        $N
    );
$Kc = hash('sha256', gmp_strval($Sc));

// S
$Ss = gmp_powm(gmp_mul($A, gmp_powm($v, $u, $N)), $b, $N);
$Ks = hash('sha256', gmp_strval($Ss));

// C -> S
$proofC = hash_hmac('sha256', $Kc, gmp_strval($salt));

// S -> C
$proofS = hash_hmac('sha256', $Ks, gmp_strval($salt));

var_dump(gmp_strval($Sc), gmp_strval($Ss));

print $proofS === $proofC ? "OK\n\n" : "Not OK :(\n\n";
*/

$N = gmp_init('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff', 16);
$g = '2';
$k = '3';
$I = 'email';
$P = 'password';

// S
$salt = gmp_init('c074c31f47082b39', 16);
$xH = hash('sha256', gmp_strval($salt) . $P);
$x = gmp_init($xH, 16);
$v = gmp_powm($g, $x, $N);

// C -> S
$a = gmp_random();
$A = gmp_powm($g, $a, $N);

// S -> C
$b = gmp_random();
$B = gmp_powm(gmp_add(gmp_mul($k, $v), gmp_powm($g, $b, $N)), '1', $N);

// S and C
$uH = hash('sha256', gmp_strval($A) . gmp_strval($B));
$u = gmp_init($uH, 16);

// C
$Sc = gmp_powm(
    gmp_sub($B, gmp_mul($k, gmp_powm($g, $x, $N))),
    gmp_add($a, gmp_mul($u, $x)),
    $N
);
$Kc = hash('sha256', gmp_strval($Sc));

// S
$Ss = gmp_powm(gmp_mul($A, gmp_powm($v, $u, $N)), $b, $N);
$Ks = hash('sha256', gmp_strval($Ss));

// C -> S
$proofC = hash_hmac('sha256', $Kc, gmp_strval($salt));

// S -> C
$proofS = hash_hmac('sha256', $Ks, gmp_strval($salt));

print $proofS === $proofC ? "OK\n\n" : "Not OK :(\n\n";