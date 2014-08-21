<?php

/*
 * http://cryptopals.com/sets/4/challenges/31/
 *
 * Implement and break HMAC-SHA1 with an artificial timing leak
 *
 * The psuedocode on Wikipedia should be enough. HMAC is very easy.
 *
 * Using the web framework of your choosing (Sinatra, web.py, whatever), write a tiny application that has a URL that takes a "file" argument and a "signature" argument, like so:
 * http://localhost:9000/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51
 *
 * Have the server generate an HMAC key, and then verify that the "signature" on incoming requests is valid for "file", using the "==" operator to compare the valid MAC for a file with the "signature" parameter (in other words, verify the HMAC the way any normal programmer would verify it).
 *
 * Write a function, call it "insecure_compare", that implements the == operation by doing byte-at-a-time comparisons with early exit (ie, return false at the first non-matching byte).
 *
 * In the loop for "insecure_compare", add a 50ms sleep (sleep 50ms after each byte).
 *
 * Use your "insecure_compare" function to verify the HMACs on incoming requests, and test that the whole contraption works. Return a 500 if the MAC is invalid, and a 200 if it's OK.
 *
 * Using the timing leak in this application, write a program that discovers the valid MAC for any file.
 *
 * Why artificial delays?
 * Early-exit string compares are probably the most common source of cryptographic timing leaks, but they aren't especially easy to exploit. In fact, many timing leaks (for instance, any in C, C++, Ruby, or Python) probably aren't exploitable over a wide-area network at all. To play with attacking real-world timing leaks, you have to start writing low-level timing code. We're keeping things cryptographic in these challenges.
 */

require_once '../utils/random-bytes.php';
require_once '28-implement-a-sha-1-keyed-mac.php';

function HMACSHA1($key, $message)
{
    $keyLen = strlen($key);

    if ($keyLen > 64) {
        $key = sha1KeyedMAC('', $message);
    }
    else if ($keyLen < 64) {
        $key .= str_repeat("\0", 64 - $keyLen);
    }

    $oPad = str_repeat("\x5c", 64) ^ $key;
    $iPad = str_repeat("\x36", 64) ^ $key;

    return sha1KeyedMAC($oPad, sha1KeyedMAC($iPad, $message));
}

function insecureCompare($one, $two)
{
    $three = unpack('C*', $one ^ $two);
    foreach ($three as $k => $v) {
        if ($v) {
            usleep(50000 * $k);
            return false;
        }
    }

    return true;
}

class pretendAPI
{
    private $key;

    function __construct()
    {
        $this->key = getRandomBytes(64);
    }

    function generate($file)
    {
        return HMACSHA1($this->key, $file);
    }

    function validate($file, $signature)
    {
        return insecureCompare($signature, HMACSHA1($this->key, $file)) ? 200 : 500;
    }
}

$api = new pretendAPI();

// attacker has a file but not the key to generate valid signature

$file = 'my evil file';

$crackedSig = str_repeat("\0", 20);

print "This will take a while.\n\n";

for ($x = 0; $x < 20; $x++) {
    $timings = [];

    for ($i = 0; $i < 256; $i++) {
        $crackedSig[$x] = chr($i);
        $start = microtime(true);
        if ($api->validate($file, $crackedSig) === 500) {
            $timings[$i] = microtime(true) - $start;
        }
        else {
            $timings[$i] = PHP_INT_MAX;
        }
    }

    arsort($timings);
    $crackedSig[$x] = chr(key($timings));
    var_dump(bin2hex($crackedSig));
}

print "\nFinal signature validates:\n";
print $api->validate($file, $crackedSig) === 200 ? "Success!\n\n" : "Failure :(\n\n";
