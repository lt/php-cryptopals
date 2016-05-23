<?php declare(strict_types = 1);

namespace Cryptopals\Set1\Challenge5;

use Cryptopals\Solution;

class Solution5 implements Solution
{
    protected function repeatingKeyXOR(string $input, string $key): string
    {
        $inputLen = strlen($input);
        $keyLen = strlen($key);

        for ($i = 0; $i < $inputLen; $i++) {
            $input[$i] = $input[$i] ^ $key[$i % $keyLen];
        }

        return $input;
    }

    function execute(): bool
    {
        $input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        $key = 'ICE';
        $expected = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f';

        $output = $this->repeatingKeyXOR($input, $key);
        $output = bin2hex($output);

        print 'Expected: ' . $expected . "\n";
        print 'Actual:   ' . $output . "\n";

        return $output === $expected;
    }
}
