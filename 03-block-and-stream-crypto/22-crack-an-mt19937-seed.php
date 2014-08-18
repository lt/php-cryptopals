<?php

/*
 * http://cryptopals.com/sets/3/challenges/22/
 *
 * Crack an MT19937 seed
 *
 * Make sure your MT19937 accepts an integer seed value. Test it (verify that you're getting the same sequence of outputs given a seed).
 *
 * Write a routine that performs the following operation:
 * - Wait a random number of seconds between, I don't know, 40 and 1000.
 * - Seeds the RNG with the current Unix timestamp
 * - Waits a random number of seconds again.
 * - Returns the first 32 bit output of the RNG.
 *
 * You get the idea. Go get coffee while it runs. Or just simulate the passage of time, although you're missing some of the fun of this exercise if you do that.
 *
 * From the 32 bit RNG output, discover the seed.
 */

require_once '21-implement-the-mt19937-mersenne-twister-rng.php';

// Sorry, going for simulated passage of time.

$now = time();

$mt = new MT19937();
$mt->init($now - mt_rand(80, 2000)); // randception
$r = $mt->int32();

print "Got first random number: $r\n";
print "Time is " . date('H:i:s', $now) . "\n\n";

for ($i = 0; $i <= 2000; $i++) {
    $mt->init($now - $i); // randception
    if ($mt->int32() === $r) {
        print "RNG was seeded at: " . date('H:i:s', $now - $i) . "\n\n";
    }
}