<?php declare(strict_types = 1);

namespace Cryptopals\Set4\Challenge25;

use Cryptopals\Set3\Challenge18\Solution18;

class Solution25 extends Solution18
{
    protected $plaintext = '';
    protected $ciphertext = '';
    protected $nonce = '';

    protected function edit(string $newText, int $offset): string
    {
        $newLen = strlen($newText);

        $this->plaintext = substr($this->plaintext, 0, $offset) . $newText . substr($this->plaintext, $offset + $newLen);

        return $this->encrypt($this->plaintext, $this->nonce);
    }

    protected function setUp(): bool
    {
        $this->ecb = new \AES\Mode\ECB();
        $this->ctx = new \AES\Context\ECB('YELLOW SUBMARINE');
        $this->pad = new \AES\Padding\PKCS7();

        $this->plaintext = $this->ecb->decrypt($this->ctx, base64_decode(file_get_contents(__DIR__ . '/25.txt')));
        $this->plaintext = substr($this->plaintext, 0, -$this->pad->getPadLen($this->plaintext));

        $this->nonce = random_bytes(8);
        $this->ctx = new \AES\Context\ECB(random_bytes(16));
        $this->ciphertext = $this->encrypt($this->plaintext, $this->nonce);

        return true;
    }

    protected function execute(): bool
    {
        $ciphertext = $this->ciphertext;

        $editedCiphertext = $this->edit(str_repeat("\0", strlen($ciphertext)), 0);

        print "Recovered plaintext:\n";
        print $ciphertext ^ $editedCiphertext . "\n";

        return true;
    }
}
