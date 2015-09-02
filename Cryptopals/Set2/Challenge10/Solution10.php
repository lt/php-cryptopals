<?php declare(strict_types = 1);

namespace Cryptopals\Set2\Challenge10;

use Cryptopals\Solution;

class Solution10 extends Solution
{
    protected $aes;
    protected $ctx;
    protected $pad;

    protected function setUp(): bool
    {
        // This uses my own AES library
        // Technically I completed this challenge elsewhere
        $this->aes = new \AES\Mode\CBC();
        $this->ctx = new \AES\Context\CBC('YELLOW SUBMARINE', str_repeat("\0", 16));
        $this->pad = new \AES\Padding\PKCS7();

        return true;
    }

    protected function execute(): bool
    {
        $encrypted = base64_decode(file_get_contents(__DIR__ . '/10.txt'));

        $decrypted = $this->aes->decrypt($this->ctx, $encrypted);

        // From previous runs I know this is padded.
        $padLen = $this->pad->getPadLen($decrypted);

        print "Decrypted data:\n";
        print substr($decrypted, 0, -$padLen) . "\n";

        // Ok this isn't really a true/false success one, but after a couple
        // of runs, I know the output is correct.
        return true;
    }
}
