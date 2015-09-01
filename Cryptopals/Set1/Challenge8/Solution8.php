<?php declare(strict_types = 1);

namespace Cryptopals\Set1\Challenge8;

use Cryptopals\Solution;

class Solution8 extends Solution
{
    protected function repeatedBlockCount(string $data): int
    {
        $dataLen = strlen($data);
        $repetitions = 0;

        for ($i = 0; $i < $dataLen; $i += 16) {
            $block = substr($data, $i, 16);
            $repetition = strpos($data, $block, $i + 16);

            if ($repetition && $repetition % 16 === 0) {
                $repetitions++;
            }
        }

        return $repetitions;
    }
    
    protected function execute(): bool
    {
        $data = array_map('hex2bin', file(__DIR__ . '/8.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));

        foreach ($data as $k => $encrypted) {
            $repetitions = $this->repeatedBlockCount($encrypted);

            if ($repetitions) {
                $line = $k + 1;
                print "String on line $line has repeated blocks (probable ECB)\n";
            }
        }

        return true;
    }
}
