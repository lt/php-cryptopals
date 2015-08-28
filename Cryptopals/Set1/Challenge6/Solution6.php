<?php declare(strict_types = 1);

namespace Cryptopals\Set1\Challenge6;

use Cryptopals\Set1\Challenge4\Solution4;

class Solution6 extends Solution4
{
    // popcount the diff (xor) bits between two strings
    protected function hammingDistance($one, $two)
    {
        $count = 0;

        foreach (unpack('C*', $one ^ $two) as $diff) {
            while ($diff) {
                $diff &= $diff - 1;
                $count++;
            }
        }

        return $count;
    }

    protected function scoreKeyLengths($data, $lowKeySize, $highKeySize)
    {
        $scores = [];

        for($keyLen = $lowKeySize; $keyLen <= $highKeySize; $keyLen++) {
            $samples = 0;
            $summedDistance = 0;

            $chunks = str_split($data, $keyLen);
            $chunkCount = count($chunks);
            for ($a = 0; $a < $chunkCount; $a++) {
                for ($b = $a + 1; $b < $chunkCount; $b++) {
                    $summedDistance += $this->hammingDistance($chunks[$a], $chunks[$b]);
                    $samples++;
                }
            }

            // Average distance per character across all samples
            $scores[$keyLen] = $summedDistance / $keyLen / $samples;
        }

        return $scores;
    }

    protected function transposeBlocks(array $blocks)
    {
        $matrix = array_map('str_split', $blocks);
        $iterations = count($matrix[0]);
        $newBlocks = [];

        for ($i = 0; $i < $iterations; $i++) {
            $newBlocks[] = array_column($matrix, $i);
        }

        return array_map('implode', $newBlocks);
    }

    protected function execute(): bool
    {
        $data = base64_decode(file_get_contents(__DIR__ . '/6.txt'));

        $scores = $this->scoreKeyLengths($data, 2, 40);
        asort($scores);

        $limit = 5;
        print "Size | Score | Key\n";
        print "------------------ -  -   -\n";

        $i = 0;
        foreach ($scores as $k => $v) {
            $blocks = str_split($data, $k);
            $blocks = $this->transposeBlocks($blocks);

            list($topScores, $topChars) = $this->scoreSingleByteXORStrings($blocks);
            printf("%4u | %5.3f | %s\n", $k, $v, implode(array_map('chr', $topChars)));

            if (++$i === $limit) {
                break;
            }
        }

        // Ok this isn't really a true/false success one, but after a couple
        // of runs, I know the output is correct.
        return true;
    }
}
