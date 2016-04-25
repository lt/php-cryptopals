<?php declare(strict_types = 1);

namespace Cryptopals\Set4\Challenge25;

use AES\ECB;
use AES\Key;
use Cryptopals\Set2\Challenge15\PKCS7;
use Cryptopals\Set3\Challenge18\AESCTR;
use Cryptopals\Set3\Challenge18\Solution18;

class Solution25 extends Solution18
{
    protected $ctr;
    protected $key;

    protected $plaintext = '';
    protected $ciphertext = '';
    protected $nonce = '';

    protected function edit(string $newText, int $offset): string
    {
        $newLen = strlen($newText);

        $this->plaintext = substr($this->plaintext, 0, $offset) . $newText . substr($this->plaintext, $offset + $newLen);

        return $this->ctr->encrypt($this->key, $this->nonce, $this->plaintext);
    }

    protected function setUp(): bool
    {
        $ecb = new ECB;
        $this->ctr = new AESCTR;
        $this->key = new Key(random_bytes(16));
        $this->nonce = random_bytes(8);

        $pkcs7 = new PKCS7;

        $plaintext = $ecb->decrypt(new Key('YELLOW SUBMARINE'), base64_decode(file_get_contents(__DIR__ . '/25.txt')));
        $this->plaintext = $pkcs7->depad($plaintext);

        $this->ciphertext = $this->ctr->encrypt($this->key, $this->nonce, $this->plaintext);

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
