<?php declare(strict_types = 1);

namespace Cryptopals\Set3\Challenge20;

use Cryptopals\Set1\Challenge3\SingleByteXORScore;
use Cryptopals\Set1\Challenge6\RepeatingKeyXORScore;
use Cryptopals\Set1\Challenge7\RandomKey;
use Cryptopals\Set3\Challenge18\AESCTR;
use Cryptopals\Solution;

class Solution20 implements Solution
{
    protected $ctr;
    protected $key;
    
    function __construct(AESCTR $ctr, RandomKey $key)
    {
        $this->ctr = $ctr;
        $this->key = $key;
    }

    protected function scoreSingleByteXORStrings(array $strings): array
    {
        $topScores = [];
        $topChars = [];

        $first = true;

        foreach ($strings as $stringIndex => $string) {
            $scores = SingleByteXORScore::score($string, $first ? RepeatingKeyXORScore::FREQ_START_EN : RepeatingKeyXORScore::FREQ_EN);
            arsort($scores);
            $topScores[$stringIndex] = current($scores);
            $topChars[$stringIndex] = key($scores);
            $first = false;
        }

        return [$topScores, $topChars];
    }

    function execute(): bool
    {
        $plaintexts = array_map('base64_decode', file(__DIR__ . '/20.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));
        $ciphertexts = array_map(function ($pt) {
            return $this->ctr->encrypt($this->key, str_repeat("\0", 8), $pt);
        }, $plaintexts);

        // challenge text says use a common length, but we can recover more if we don't
        // this is because after transposition there's still enough data to statistically recover more
        /*
        $cipherLens = array_map('strlen', $ciphertexts);
        $minLength = min($cipherLens);
        $truncated = array_map('str_split', $ciphertexts, array_fill(0, count($plaintexts), $minLength));
        $truncated = array_column($truncated, 0);
        */
        $truncated = $ciphertexts;

        print "\nSolving keys based on English Language scoring:\n";

        $blocks = RepeatingKeyXORScore::transposeBlocks($ciphertexts);

        list($topScores, $topChars) = $this->scoreSingleByteXORStrings($blocks);

        $potentialKey = pack('C*', ...$topChars);

        foreach ($truncated as $k => $ciphertext) {
            $recovered = $ciphertext ^ $potentialKey;
            if ($recovered !== $plaintexts[$k]) {
                print "Cracked : $recovered\nOriginal: {$plaintexts[$k]}\n\n";
            }
        }

        return true;
    }
}


