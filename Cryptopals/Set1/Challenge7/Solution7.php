<?php declare(strict_types = 1);

namespace Cryptopals\Set1\Challenge7;

use Cryptopals\Solution;

class Solution7 extends Solution
{
    protected $aes;
    protected $ctx;
    protected $pad;

    protected function setUp(): bool
    {
        // This uses my own AES library
        // Technically I completed this challenge elsewhere
        $this->aes = new \AES\Mode\ECB();
        $this->ctx = new \AES\Context\ECB('YELLOW SUBMARINE');
        $this->pad = new \AES\Padding\PKCS7();

        return true;
    }

    protected function execute(): bool
    {
        $encrypted = base64_decode(file_get_contents(__DIR__ . '/7.txt'));

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
