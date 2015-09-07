<?php declare(strict_types = 1);

namespace Cryptopals\Set3\Challenge18;

use Cryptopals\Set1\Challenge6\Solution6;

class Solution18 extends Solution6
{
    protected $ecb;
    protected $ctx;
    protected $pad;

    protected function setUp(): bool
    {
        $this->ecb = new \AES\Mode\ECB();
        $this->ctx = new \AES\Context\ECB('YELLOW SUBMARINE');
        $this->pad = new \AES\Padding\PKCS7();

        return true;
    }

    // Not using the AES lib fully because the counter is implemented funny in the challenge
    function encrypt($message)
    {
        $blocks = str_split($message, 16);
        $counter = 0;

        foreach ($blocks as &$block) {
            $block ^= $this->ecb->encrypt($this->ctx, pack('P2', 0, $counter++));
        }

        return implode($blocks);
    }

    function decrypt($message)
    {
        return $this->encrypt($message);
    }

    protected function execute(): bool
    {
        $ciphertext = base64_decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==');

        $plaintext = $this->decrypt($ciphertext);
        $homebrewCipher = $this->encrypt($plaintext);

        print "Decrypted data:\n";
        print "$plaintext\n";
        
        return $ciphertext === $homebrewCipher;
    }
}
