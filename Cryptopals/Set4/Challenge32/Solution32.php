<?php

/*
 * http://cryptopals.com/sets/4/challenges/32/
 *
 * Break HMAC-SHA1 with a slightly less artificial timing leak
 *
 * Reduce the sleep in your "insecure_compare" until your previous solution breaks. (Try 5ms to start.)
 *
 * Now break it again.
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
            usleep(1000 * $k);
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
        $this->key = random_bytes(64);
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

        for ($samples = 0; $samples < 10; $samples++) {
            $start = microtime(true);
            if ($api->validate($file, $crackedSig) === 500) {
                $stop = microtime(true) - $start;
                if (isset($timings[$i])) {
                    $timings[$i] += $stop;
                }
                else {
                    $timings[$i] = $stop;
                }
            }
            else {
                $timings[$i] = PHP_INT_MAX;
            }
        }
        $timings[$i] /= $samples;
    }

    arsort($timings);
    $crackedSig[$x] = chr(key($timings));
    var_dump(bin2hex($crackedSig));
}

print "\nFinal signature validates:\n";
print $api->validate($file, $crackedSig) === 200 ? "Success!\n\n" : "Failure :(\n\n";
