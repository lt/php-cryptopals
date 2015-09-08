<?php declare(strict_types = 1);

namespace Cryptopals\Set1\Challenge3;

use Cryptopals\Solution;

class Solution3 extends Solution
{
    // https://en.wikipedia.org/wiki/Letter_frequency#Relative_frequencies_of_letters_in_the_English_language
    const FREQ_EN = [
        'e' => 12.702, 't' => 9.056, 'a' => 8.167, 'o' => 7.507, 'i' => 6.966, 'n' => 6.749,
        's' =>  6.327, 'h' => 6.094, 'r' => 5.987, 'd' => 4.253, 'l' => 4.025, 'c' => 2.782,
        'u' =>  2.758, 'm' => 2.406, 'w' => 2.361, 'f' => 2.228, 'g' => 2.015, 'y' => 1.974,
        'p' =>  1.929, 'b' => 1.492, 'v' => 0.978, 'k' => 0.772, 'j' => 0.153, 'x' => 0.150,
        'q' =>  0.095, 'z' => 0.074,

        /*
         * More from https://en.wikipedia.org/wiki/Letter_frequency
         *
         * "In English, the space is slightly more frequent than the top letter (e)
         * and the non-alphabetic characters (digits, punctuation, etc.) collectively
         * occupy the fourth position, between t and a."
         *
         * Made up values based on the above. Lots of "etc." unaccounted for.
         */
        ' ' => 13
    ];

    // https://en.wikipedia.org/wiki/Letter_frequency#Relative_frequencies_of_the_first_letters_of_a_word_in_the_English_language
    const FREQ_START_EN = [
        't' => 16.671, 'a' => 11.602, 's' => 7.755, 'h' => 7.232, 'w' => 6.753, 'i' => 6.286,
        'o' =>  6.264, 'b' =>  4.702, 'm' => 4.383, 'f' => 3.779, 'c' => 3.511, 'l' => 2.705,
        'd' =>  2.670, 'p' =>  2.545, 'n' => 2.365, 'e' => 2.007, 'g' => 1.950, 'r' => 1.653,
        'y' =>  1.620, 'u' =>  1.487, 'v' => 0.649, 'j' => 0.597, 'k' => 0.590, 'q' => 0.173,
        'z' =>  0.034, 'x' =>  0.017
    ];

    protected function scoreASCII(string $data, array $overrideWeights = []): float
    {
        $data = strtolower($data);
        $dataLen = strlen($data);

        $score = 0;
        for ($i = 0; $i < $dataLen; $i++) {
            $c = $data[$i];

            // Control characters or extended ASCII
            if (($c < ' ') || ($c > '~')) {
                $score -= 100;
                continue;
            }

            // First letter of the string, or preceeded by space or tab
            $weights = $overrideWeights + (($i === 0 || $data[$i - 1] === ' ' || $data[$i - 1] === "\x9") ?
                self::FREQ_START_EN : self::FREQ_EN);

            if (isset($weights[$c])) {
                $score += $weights[$c];
            }
            else {
                $score -= 3;
            }
        }

        // Normalise
        return $score / $dataLen;
    }

    protected function scoreSingleByteXORs(string $input, array $overrideWeights = []): array
    {
        $inputLen = strlen($input);

        $scores = [];

        for ($i = 0; $i < 256; $i++) {
            $trial = $input ^ str_repeat(chr($i), $inputLen);
            $scores[$i] = $this->scoreASCII($trial, $overrideWeights);
        }

        return $scores;
    }

    protected function execute(): bool
    {
        $input = hex2bin('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736');
        $inputLen = strlen($input);

        $scores = $this->scoreSingleByteXORs($input);

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
