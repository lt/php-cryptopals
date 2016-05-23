<?php declare(strict_types = 1);

namespace Cryptopals\Set2\Challenge16;

use Cryptopals\Solution;

class Solution16 implements Solution
{
    protected $queryAPI;

    function __construct(QueryAPI $queryAPI)
    {
        $this->queryAPI = $queryAPI;
    }

    function execute(): bool
    {
        // 0..............f|0..............f|0..............f|0..............f|0..............f
        // comment1=cooking|%20MCs;userdata=
        //                 |                |aaaaaaaaaaaaaaaa|bbbb;admin=true |
        //                                                                   ;comment2=%20like%20a%20pound%20of%20bacon

        // 31 chars to account for the trailing semicolon
        $badData = 'aaaaaaaaaaaaaaaabbbb;admin=true';
        $goodData = 'aaaaaaaaaaaaaaaabbbbbbbbbbbbbbb';
        $badBlock = substr($badData ^ $goodData, 16);

        print "We sent:       {$goodData}\n";
        print "We want:       {$badData}\n";
        print 'Bit flip mask: ' . bin2hex($badBlock) . "\n";

        $query = $this->queryAPI->getQuery($goodData);
        $query = substr_replace($query, substr($query, 32) ^ $badBlock, 32, 15);

        return $this->queryAPI->isAdmin($query);
    }
}
