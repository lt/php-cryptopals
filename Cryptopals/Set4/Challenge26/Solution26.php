<?php declare(strict_types = 1);

namespace Cryptopals\Set4\Challenge26;

use Cryptopals\Solution;

class Solution26 implements Solution
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
        //                 |                |bbbb;admin=true |
        //                                                  ;|comment2=%20like%20a%20pound%20of%20bacon

        $badData = 'bbbb;admin=true';
        $goodData = 'bbbbbbbbbbbbbbb';
        $badBlock = $badData ^ $goodData;

        print "We sent:       {$goodData}\n";
        print "We want:       {$badData}\n";
        print 'Bit flip mask: ' . bin2hex($badBlock) . "\n";

        $query = $this->queryAPI->getQuery($goodData);

        $query = substr($query, 0, 32) . (substr($query, 32, 15) ^ $badBlock) . substr($query, 47);

        return $this->queryAPI->isAdmin($query);
    }
}
