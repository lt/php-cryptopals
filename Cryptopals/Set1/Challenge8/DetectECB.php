<?php declare(strict_types = 1);

namespace Cryptopals\Set1\Challenge8;

class DetectECB
{
    static function repeatedBlockCount(string $data): int
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
}
