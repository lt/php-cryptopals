<?php declare(strict_types = 1);

namespace Cryptopals\Set1\Challenge8;

use Cryptopals\Solution;

class Solution8 implements Solution
{
    function execute(): bool
    {
        $data = array_map('hex2bin', file(__DIR__ . '/8.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));

        foreach ($data as $k => $encrypted) {
            $repetitions = DetectECB::repeatedBlockCount($encrypted);

            if ($repetitions) {
                $line = $k + 1;
                print "String on line {$line} has {$repetitions} repeated blocks (probable ECB)\n";
            }
        }

        return true;
    }
}
