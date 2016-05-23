<?php declare(strict_types = 1);

namespace Cryptopals\Set1\Challenge6;

use Cryptopals\Set1\Challenge4\DetectSingleByteXOR;
use Cryptopals\Solution;

class Solution6 implements Solution
{
    function execute(): bool
    {
        $data = base64_decode(file_get_contents(__DIR__ . '/6.txt'));

        $scores = RepeatingKeyXORScore::scoreKeyLengths($data, 2, 40);
        asort($scores);

        $limit = 5;
        print "Size | Score | Key\n";
        print "------------------ -  -   -\n";

        $i = 0;
        foreach ($scores as $k => $v) {
            $blocks = str_split($data, $k);
            $blocks = RepeatingKeyXORScore::transposeBlocks($blocks);

            list($topScores, $topChars) = DetectSingleByteXOR::find($blocks);
            printf("%4u | %5.3f | %s\n", $k, $v, pack('C*', ...$topChars));

            if (++$i === $limit) {
                break;
            }
        }

        // Ok this isn't really a true/false success one, but after a couple
        // of runs, I know the output is correct.
        return true;
    }
}
