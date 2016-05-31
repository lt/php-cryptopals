<?php declare(strict_types = 1);

namespace Cryptopals\Set7\Challenge49;

use Cryptopals\Set1\Challenge7\YellowSubmarineKey;

class Frontend
{
    protected $backend;
    protected $cbc;
    protected $key;
    
    function __construct(Backend $backend, CBCMAC $cbc, YellowSubmarineKey $key)
    {
        $this->backend = $backend;
        $this->cbc = $cbc;
        $this->key = $key;
    }
    
    // Some information leak - Challenge says backend is publicly accessible
    function getBackend(): Backend
    {
        return $this->backend;
    }

    // Pretend this is authenticated to a logged on user.
    function transfer(int $from, int $to, int $amount): bool
    {
        $message = "from={$from}&to={$to}&amount={$amount}";
        $iv = random_bytes(16);
        $mac = $this->cbc->mac($this->key, $iv, $message);

        return $this->backend->process($message, $iv, $mac);
    }

    // Pretend this is also authenticated to a logged on user.
    function transferMulti(int $from, array $transactions): bool
    {
        $txList = '';
        foreach ($transactions as $to => $amount) {
            $txList .= ($txList ? ";{$to}:{$amount}" : "{$to}:{$amount}");
        }
        
        $message = "from={$from}&tx_list={$txList}";
        $iv = str_repeat("\0", 16);
        $mac = $this->cbc->mac($this->key, $iv, $message);

        return $this->backend->processMulti($message, $mac);
    }
}
