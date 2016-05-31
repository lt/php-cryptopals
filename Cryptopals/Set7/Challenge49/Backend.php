<?php declare(strict_types = 1);

namespace Cryptopals\Set7\Challenge49;

use Cryptopals\Set1\Challenge7\YellowSubmarineKey;

class Backend
{
    protected $backend;
    protected $cbc;
    protected $key;

    protected $sniffer;

    function __construct(CBCMAC $cbc, YellowSubmarineKey $key)
    {
        $this->cbc = $cbc;
        $this->key = $key;
    }

    function process(string $message, string $iv, string $mac): bool
    {
        if (!hash_equals($mac, $this->cbc->mac($this->key, $iv, $message))) {
            print 'Server: Invalid MAC';
            return false;
        }

        if (!preg_match('~^from=(\d+)&to=(\d+)&amount=(\d+)$~', $message, $match)) {
            print 'Server: Invalid message';
            return false;
        }

        if (is_callable($this->sniffer)) {
            ($this->sniffer)($message . $iv . $mac);
        }

        print "Server: {$match[1]} -> {$match[2]}: {$match[3]}\n";
        return true;
    }

    function processMulti(string $message, string $mac): bool
    {
        $iv = str_repeat("\0", 16);
        
        if (!hash_equals($mac, $this->cbc->mac($this->key, $iv, $message))) {
            print 'Server: Invalid MAC';
            return false;
        }

        // Had to deliberately weaken this to accept the extended CBC block
        if (!preg_match('~^from=(\d+)&tx_list=(\d+:[^;]+(?:;?\d+:[^;]+)*)$~', $message, $match)) {
            print 'Server: Invalid message';
            return false;
        }

        preg_match_all('~(?:^|;)(\d+):(\d+)~', $match[2], $txList, PREG_SET_ORDER);

        if (is_callable($this->sniffer)) {
            ($this->sniffer)($message . $mac);
        }

        foreach ($txList as list(, $to, $amount)) {
            if (!is_numeric($amount)) {
                print "Invalid transaction\n";
                continue;
            }

            print "Server: {$match[1]} -> {$to}: {$amount}\n";
        }

        return true;
    }
    
    // Pretend we can see network traffic or something
    function setSniffer(callable $sniffer)
    {
        $this->sniffer = $sniffer;
    }
}
