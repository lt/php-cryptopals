<?php declare(strict_types = 1);

namespace Cryptopals\Set1\Challenge4;

use Cryptopals\Set1\Challenge3\SingleByteXORScore;

class DetectSingleByteXOR
{
    static function find(array $strings, array $overrideWeights = []): array
    {
        $topScores = [];
        $topChars = [];

        foreach ($strings as $stringIndex => $string) {
            $scores = SingleByteXORScore::score($string, $overrideWeights);
            arsort($scores);
            $topScores[$stringIndex] = current($scores);
            $topChars[$stringIndex] = key($scores);
        }

        return [$topScores, $topChars];
    }
}
