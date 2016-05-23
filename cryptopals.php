#!/bin/env php
<?php declare(strict_types = 1);

namespace Cryptopals;

use Auryn\InjectionException;
use Auryn\Injector;

require 'vendor/autoload.php';

if ($argc < 2) {
    print basename($argv[0]) . " <challenge_id>\n";
    exit(1);
}

$sets = [1 =>
    'Basics',
    'Block crypto',
    'Block & stream crypto',
    'Stream crypto and randomness',
    'Diffie-Hellman and friends',
    'RSA and DSA',
    'Hashes'
];

$challenges = [1 =>
    'Convert hex to base64',
    'Fixed XOR',
    'Single-byte XOR cipher',
    'Detect single-character XOR',
    'Implement repeating-key XOR',
    'Break repeating-key XOR',
    'AES in ECB mode',
    'Detect AES in ECB mode',
    'Implement PKCS#7 padding',
    'Implement CBC mode',
    'An ECB/CBC detection oracle',
    'Byte-at-a-time ECB decryption (Simple)',
    'ECB cut-and-paste',
    'Byte-at-a-time ECB decryption (Harder)',
    'PKCS#7 padding validation',
    'CBC bitflipping attacks',
    'The CBC padding oracle',
    'Implement CTR, the stream cipher mode',
    'Break fixed-nonce CTR mode using substitions',
    'Break fixed-nonce CTR statistically',
    'Implement the MT19937 Mersenne Twister RNG',
    'Crack an MT19937 seed',
    'Clone an MT19937 RNG from its output',
    'Create the MT19937 stream cipher and break it',
    'Break "random access read/write" AES CTR',
    'CTR bitflipping',
    'Recover the key from CBC with IV=Key',
    'Implement a SHA-1 keyed MAC',
    'Break a SHA-1 keyed MAC using length extension',
    'Break an MD4 keyed MAC using length extension',
    'Implement and break HMAC-SHA1 with an artificial timing leak',
    'Break HMAC-SHA1 with a slightly less artificial timing leak',
    'Implement Diffie-Hellman',
    'Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection',
    'Implement DH with negotiated groups, and break with malicious "g" parameters',
    'Implement Secure Remote Password (SRP)',
    'Break SRP with a zero key',
    'Offline dictionary attack on simplified SRP',
    'Implement RSA',
    'Implement an E=3 RSA Broadcast attack',
    'Implement unpadded message recovery oracle',
    'Bleichenbacher\'s e=3 RSA Attack',
    'DSA key recovery from nonce',
    'DSA nonce recovery from repeated nonce',
    'DSA parameter tampering',
    'RSA parity oracle',
    'Bleichenbacher\'s PKCS 1.5 Padding Oracle (Simple Case)',
    'Bleichenbacher\'s PKCS 1.5 Padding Oracle (Complete Case)',
    'CBC-MAC Message Forgery',
    'Hashing with CBC-MAC',
    'Compression Ratio Side-Channel Attacks',
    'Iterated Hash Function Multicollisions',
    'Kelsey and Schneier\'s Expandable Messages',
    'Kelsey and Kohno\'s Nostradamus Attack',
    'MD4 Collisions',
    'RC4 Single-Byte Biases'
];

$challengeId = (int)$argv[1];
$setId = ceil($challengeId / 8);

$challengeName = $challenges[$challengeId] ?? null;
$setName = $sets[$setId] ?? null;

$injector = new Injector();
$solutionClass = "\\Cryptopals\\Set{$setId}\\Challenge{$challengeId}\\Solution{$challengeId}";

try {
    /** @var \Cryptopals\Solution $solution */
    $solution = $injector->make($solutionClass);
}
catch (InjectionException $e) {
    print "Could not instantiate solution for Challenge {$challengeId}\n";
    $message = $e->getMessage();
    print "{$message}\n";
    exit(1);
}

print "Set {$setId}: {$setName}\n";
print "Challenge {$challengeId}: {$challengeName}\n";
print str_repeat('#', 80) . "\n";

$result = $solution->execute();

print str_repeat('#', 80) . "\n";
print ($result ? 'Success' : 'Failure') . "\n";
