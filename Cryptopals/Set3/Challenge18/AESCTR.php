<?php declare(strict_types = 1);

namespace Cryptopals\Set3\Challenge18;

use AES\Context\CTR\{
    Context,
    EncryptionContext,
    DecryptionContext
};
use AES\CTR;
use AES\Exception\IVLengthException;
use AES\Key;

class AESCTR extends CTR
{
    private function init(Context $context, Key $key, string $nonce)
    {
        if (strlen($nonce) !== 8) {
            throw new IVLengthException;
        }

        $context->key = $key;
        $context->nonce = [unpack('P', $nonce)[1], 0];
    }

    function initEncryption(Key $key, string $nonce): EncryptionContext
    {
        $context = new EncryptionContext;
        $this->init($context, $key, $nonce);
        return $context;
    }

    function initDecryption(Key $key, string $nonce): DecryptionContext
    {
        $context = new DecryptionContext;
        $this->init($context, $key, $nonce);
        return $context;
    }

    private function transcrypt(Context $context, string $message): string
    {
        $nonce = $context->nonce;
        $keyStream = $context->keyStream;

        $bytesRequired = strlen($message) - strlen($keyStream);
        $bytesOver = $bytesRequired % 16;

        $blockCount = ($bytesRequired >> 4) + ($bytesOver > 0);
        while ($blockCount--) {
            $keyStream .= $this->encryptBlock($context->key, pack('P2', ...$nonce));
            $nonce[1]++;
        }

        $context->keyStream = substr($keyStream, $bytesRequired);
        $context->nonce = $nonce;

        return $message ^ $keyStream;
    }

    function streamEncrypt(EncryptionContext $ctx, string $message): string
    {
        return $this->transcrypt($ctx, $message);
    }

    function streamDecrypt(DecryptionContext $ctx, string $message): string
    {
        return $this->transcrypt($ctx, $message);
    }
}
