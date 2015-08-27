<?php declare(strict_types = 1);

namespace Cryptopals\Set1\Challenge4;

use Cryptopals\Set1\Challenge3\Solution3;

class Solution4 extends Solution3
{
    protected function scoreSingleByteXORStrings(array $strings): array
    {
        $topScores = [];
        $topChars = [];

        foreach ($strings as $stringIndex => $string) {
            $scores = $this->scoreSingleByteXORs($string);
            arsort($scores);
            $topScores[$stringIndex] = current($scores);
            $topChars[$stringIndex] = key($scores);
        }

        return [$topScores, $topChars];
    }

    protected function execute(): bool
    {
        $inputs = file(__DIR__ . '/4.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $inputs = array_map('hex2bin', $inputs);

        list($topScores, $topChars) = $this->scoreSingleByteXORStrings($inputs);
        arsort($topScores);

        $limit = 5;
        print "Score | Line | Char | Output\n";
        print "---------------------------- -  -   -\n";

        $i = 0;
        foreach ($topScores as $stringIndex => $score) {
            $char = $topChars[$stringIndex];
            printf(
                "%5.2f | %4u | 0x%2x | %s\n",
                $score,
                $stringIndex,
                $char,
                $inputs[$stringIndex] ^ str_repeat(chr($char), strlen($inputs[$stringIndex]))
            );

            if (++$i === $limit) {
                break;
            }
        }

        // Ok this isn't really a true/false success one, but after a couple
        // of runs, I know the output is correct.
        return true;
    }
}
