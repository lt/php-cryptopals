<?php

/*
 * http://cryptopals.com/sets/3/challenges/23/
 *
 * Clone an MT19937 RNG from its output
 *
 * The internal state of MT19937 consists of 624 32 bit integers.
 *
 * For each batch of 624 outputs, MT permutes that internal state. By permuting state regularly, MT19937 achieves a period of 2**19937, which is Big.
 *
 * Each time MT19937 is tapped, an element of its internal state is subjected to a tempering function that diffuses bits through the result.
 *
 * The tempering function is invertible; you can write an "untemper" function that takes an MT19937 output and transforms it back into the corresponding element of the MT19937 state array.
 *
 * To invert the temper transform, apply the inverse of each of the operations in the temper transform in reverse order. There are two kinds of operations in the temper transform each applied twice; one is an XOR against a right-shifted value, and the other is an XOR against a left-shifted value AND'd with a magic number. So you'll need code to invert the "right" and the "left" operation.
 *
 * Once you have "untemper" working, create a new MT19937 generator, tap it for 624 outputs, untemper each of them to recreate the state of the generator, and splice that state into a new instance of the MT19937 generator.
 *
 * The new "spliced" generator should predict the values of the original.
 *
 * Stop and think for a second.
 * How would you modify MT19937 to make this attack hard? What would happen if you subjected each tempered output to a cryptographic hash?
 */

require_once '21-implement-the-mt19937-mersenne-twister-rng.php';

class MT19937_c23 extends MT19937
{
    function splice(array $MT)
    {
        $this->MT = $MT;
    }
}

function untemper($value)
{
    $y = $value ^ ($value >> 18); // Only 14 bits affected, so we can restore them all at once
    $y ^= ($y << 15) & 0xefc60000; // Only 15 bits affected (17 remain after shift, but mask makes it 15)

    // here we have to restore 7 bits at a time
    $x = $y ^ (($y << 7) & 0x9d2c5680); // 14
    $x = $y ^ (($x << 7) & 0x9d2c5680); // 21
    $x = $y ^ (($x << 7) & 0x9d2c5680); // 28
    $y ^= ($x << 7) & 0x9d2c5680;

    // here we have to restore 11 bits at a time
    $x = $y ^ ($y >> 11);
    return $y ^ ($x >> 11);
}

$mt = new MT19937;
$mt->init(time()); // :D :D

$state = [];

for ($i = 0; $i < 624; $i++) {
    $state[] = untemper($mt->int32());
}

$mt_c23 = new MT19937_c23();
$mt_c23->splice($state);

print "Original:      Clone:\n";
for ($i = 0; $i < 10; $i++) {
    print str_pad($mt->int32(), 15) . $mt_c23->int32() . "\n";
}