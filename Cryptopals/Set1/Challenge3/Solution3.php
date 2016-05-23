<?php declare(strict_types = 1);

namespace Cryptopals\Set1\Challenge3;

use Cryptopals\Solution;

class Solution3 implements Solution
{
    function execute(): bool
    {
        $input = hex2bin('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736');
        $inputLen = strlen($input);

        $scores = SingleByteXORScore::score($input);

        arsort($scores);

        $limit = 5;
        print "Score | Char | Output\n";
        print "--------------------- -  -   -\n";

        $i = 0;
        foreach ($scores as $k => $v) {
            printf("%5.2f | 0x%2x | %s\n", $v, $k, $input ^ str_repeat(chr($k), $inputLen));

            if (++$i === $limit) {
                break;
            }
        }

        // Ok this isn't really a true/false success one, but after a couple
        // of runs, I know the output is correct.
        return true;
    }
}
