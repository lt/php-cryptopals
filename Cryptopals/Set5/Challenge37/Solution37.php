<?php declare(strict_types = 1);

namespace Cryptopals\Set5\Challenge37;

use Cryptopals\Set5\Challenge36\SRPServer;
use Cryptopals\Solution;

class Solution37 implements Solution
{
    protected $server;
    protected $client;

    function __construct(SRPServer $server, SRPClientAmulN $client)
    {
        $this->server = $server;
        $this->client = $client;
    }

    function execute(): bool
    {
        $success = true;
        $I = 'email';

        for ($i = 0; $i < 6; $i++) {
            $this->server->setCredentials($I, 'password');
            $this->client->setCredentials($I, 'who cares');
            $this->client->setMul($i);

            $this->client->setSalt($this->server->getSalt());
            $this->server->setA($this->client->getA()); // S->S is now 0
            $this->client->setB($this->server->getB());

            print "Client sends A = N*$i. Auth with no password:\n";
            $proofage = $this->server->getProof() === $this->client->getProof();
            print $proofage ? "OK\n\n" : "Not OK :(\n\n";

            $success = $success && $proofage;
        }

        return $success;
    }
}
