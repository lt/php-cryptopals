<?php declare(strict_types = 1);

namespace Cryptopals\Set1\Challenge6;

use Cryptopals\Set1\Challenge3\SingleByteXORScore;

class RepeatingKeyXORScore extends SingleByteXORScore
{
    // popcount the diff (xor) bits between two strings
    protected static function hammingDistance(string $one, string $two): int
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

    static function scoreKeyLengths(string $data, int $lowKeySize, int $highKeySize): array
    {
        $scores = [];

        for($keyLen = $lowKeySize; $keyLen <= $highKeySize; $keyLen++) {
            $samples = 0;
            $summedDistance = 0;

            $chunks = str_split($data, $keyLen);
            $chunkCount = count($chunks);
            for ($a = 0; $a < $chunkCount; $a++) {
                for ($b = $a + 1; $b < $chunkCount; $b++) {
                    $summedDistance += static::hammingDistance($chunks[$a], $chunks[$b]);
                    $samples++;
                }
            }

            // Average distance per character across all samples
            $scores[$keyLen] = $summedDistance / $keyLen / $samples;
        }

        return $scores;
    }

    static function transposeBlocks(array $blocks): array
    {
        $matrix = array_map('str_split', $blocks);
        $iterations = count($matrix[0]);
        $newBlocks = [];

        for ($i = 0; $i < $iterations; $i++) {
            $newBlocks[] = array_column($matrix, $i);
        }

        return array_map('implode', $newBlocks);
    }
}
