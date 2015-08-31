<?php declare(strict_types = 1);

namespace Cryptopals\Set1\Challenge7;

use Cryptopals\Common\AES128;
use Cryptopals\Solution;

class Solution7 extends Solution
{
    protected $aes;
    protected $encryptionKey;
    protected $decryptionKey;

    protected function encrypt(string $message): string
    {
        $offset = 0;
        $out = '';
        $messageLen = strlen($message);
        $blocks = $messageLen >> 4;

        while ($blocks--) {
            $out .= $this->aes->encryptBlock($this->encryptionKey, substr($message, $offset, 16));
            $offset += 16;
        }

        return $out;
    }

    protected function decrypt(string $message)
    {
        $offset = 0;
        $out = '';
        $messageLen = strlen($message);
        $blocks = $messageLen >> 4;

        while ($blocks--) {
            $out .= $this->aes->decryptBlock($this->decryptionKey, substr($message, $offset, 16));
            $offset += 16;
        }

        return $out;
    }

    protected function setUp(): bool
    {
        $this->aes = new AES128();

        return true;
    }

    protected function execute(): bool
    {
        $encrypted = base64_decode(file_get_contents(__DIR__ . '/7.txt'));
        list($this->encryptionKey, $this->decryptionKey) = $this->aes->init('YELLOW SUBMARINE');

        $decrypted = $this->decrypt($encrypted);

        print "Decrypted data:\n";
        print $decrypted . "\n";

        // Ok this isn't really a true/false success one, but after a couple
        // of runs, I know the output is correct.
        return true;
    }
}
