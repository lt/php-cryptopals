<?php declare(strict_types = 1);

namespace Cryptopals\Set7\Challenge49;

use AES\Cipher;
use AES\Exception\IVLengthException;
use AES\Key;
use Cryptopals\Set2\Challenge15\PKCS7;

class CBCMAC extends Cipher
{
    function mac(Key $key, string $iv, string $data): string
    {
        if (strlen($iv) !== 16) {
            throw new IVLengthException;
        }

        $data = PKCS7::pad($data);
        $dataLen = strlen($data);

        for ($offset = 0; $offset < $dataLen; $offset += 16) {
            $iv = $this->encryptBlock($key, substr($data, $offset, 16) ^ $iv);
        }

        return $iv;
    }
}
