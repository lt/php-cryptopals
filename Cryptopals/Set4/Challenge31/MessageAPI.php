<?php declare(strict_types = 1);

namespace Cryptopals\Set4\Challenge31;

use Cryptopals\Set4\Challenge28\SHA1KeyedMAC;

class MessageAPI
{
    // 50ms seems a bit long considering we didn't do the web api
    public $sleep = 20000;
    
    protected $keyedMAC;
    protected $key;

    function __construct(SHA1KeyedMAC $keyedMAC)
    {
        $this->keyedMAC = $keyedMAC;
        $this->key = random_bytes(mt_rand(8, 32));
    }
    
    function sign(string $message): string
    {
        return $this->HMACSHA1($this->key, $message);
    }

    function verify(string $message, string $mac): int
    {
        return $this->insecureCompare($mac, $this->sign($message)) ? 200 : 500;
    }

    protected function HMACSHA1(string $key, string $message): string
    {
        $keyLen = strlen($key);

        if ($keyLen > 64) {
            $key = $this->keyedMAC->mac('', $message);
        }
        else if ($keyLen < 64) {
            $key .= str_repeat("\0", 64 - $keyLen);
        }

        $oPad = str_repeat("\x5c", 64) ^ $key;
        $iPad = str_repeat("\x36", 64) ^ $key;

        return $this->keyedMAC->mac($oPad, $this->keyedMAC->mac($iPad, $message));
    }

    protected function insecureCompare(string $one, string $two): bool
    {
        $three = unpack('C*', $one ^ $two);
        foreach ($three as $k => $v) {
            if ($v) {
                usleep($this->sleep * $k);
                return false;
            }
        }

        return true;
    }
}
