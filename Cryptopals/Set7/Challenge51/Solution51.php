<?php declare(strict_types = 1);

namespace Cryptopals\Set7\Challenge51;

use AES\CBC;
use AES\CTR;
use Cryptopals\Set1\Challenge7\RandomKey;
use Cryptopals\Set2\Challenge15\PKCS7;
use Cryptopals\Solution;

class Solution51 implements Solution
{
    protected $ctr;
    protected $cbc;
    protected $key;

    function __construct(CTR $ctr, CBC $cbc, RandomKey $key)
    {
        $this->ctr = $ctr;
        $this->cbc = $cbc;
        $this->key = $key;
    }

    function oracleCTR(string $payload): int
    {
        $payloadLen = strlen($payload);
        $request = "POST / HTTP/1.1\r\nHost: hapless.com\r\nCookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\r\nContent-Length: {$payloadLen}\r\n\r\n{$payload}";
        $compressedRequest = gzdeflate($request);

        $this->key->newKey();
        $encryptedRequest = $this->ctr->encrypt($this->key, random_bytes(16), $compressedRequest);

        return strlen($encryptedRequest);
    }

    function oracleCBC(string $payload): int
    {
        $payloadLen = strlen($payload);
        $request = "POST / HTTP/1.1\r\nHost: hapless.com\r\nCookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\r\nContent-Length: {$payloadLen}\r\n\r\n{$payload}";
        $compressedRequest = gzdeflate($request);

        $this->key->newKey();
        $encryptedRequest = $this->cbc->encrypt($this->key, random_bytes(16), PKCS7::pad($compressedRequest));

        return strlen($encryptedRequest);
    }

    function execute(): bool
    {
        $charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
        $prefix = 'sessionid=';
        $pad = 0;
        $padding = '';

        $sidLen = 44;
        $numChars = strlen($charset);

        print "CTR:\n";

        for ($x = 0; $x < $sidLen; $x++) {
            $lens = [];
            $bestLen = 999;
            $bestChar = 0;
            for ($y = 0; $y < $numChars; $y++) {
                $len = $this->oracleCTR($padding . $prefix . $charset[$y]);
                $lens[$len]++;
                if ($len < $bestLen) {
                    $bestLen = $len;
                    $bestChar = $y;
                }
            }

            if (count($lens) === 1) {
                $pad++;
                print "Looks like we hit a boundary at char {$x} - padding to {$pad}\n";
                $x--;
                $padding = random_bytes($pad);
                continue;
            }

            $prefix .= $charset[$bestChar];
        }

        $ctrPrefix = $prefix;

        print "Recovered: {$prefix}\n";
        print str_repeat('#', 80);
        print "\nCBC:\n";

        $prefix = 'sessionid=';
        $pad = 0;
        $padding = '';

        for ($x = 0; $x < $sidLen; $x++) {
            $lens = [];
            $bestLen = 999;
            $bestChar = 0;
            for ($y = 0; $y < $numChars; $y++) {
                $len = $this->oracleCBC($padding . $prefix . $charset[$y]);
                $lens[$len]++;
                if ($len < $bestLen) {
                    $bestLen = $len;
                    $bestChar = $y;
                }
            }

            if (count($lens) === 1) {
                $pad++;
                print "Looks like we hit a boundary at char {$x} - padding to {$pad}\n";
                $x--;
                $padding = random_bytes($pad);
                continue;
            }
            $pad = 0;

            $prefix .= $charset[$bestChar];
        }

        print "Recovered: {$prefix}\n";
        $cbcPrefix = $prefix;

        return ($ctrPrefix === $cbcPrefix) && ($cbcPrefix === 'sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=');
    }
}
