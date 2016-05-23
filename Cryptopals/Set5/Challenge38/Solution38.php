<?php declare(strict_types = 1);

namespace Cryptopals\Set5\Challenge38;

use Cryptopals\Solution;

class Solution38 implements Solution
{
    protected $client;
    protected $server;
    protected $sniffer;

    function __construct(SimpleSRPClient $client, SimpleSRPServer $server, SimpleSRPSniffer $sniffer)
    {
        $this->client = $client;
        $this->server = $server;
        $this->sniffer = $sniffer;
    }

    function execute(): bool
    {
        $I = 'email';
        $P = 'password';

        print "Without MITM:\n";
        $this->server->setCredentials($I, $P);
        $this->client->setCredentials($I, $P);

        $this->server->setA($this->client->getA());
        $this->client->setSalt($this->server->getSalt());
        $this->client->setu($this->server->getu());
        $this->client->setB($this->server->getB());

        print $this->server->getProof() ===
            $this->client->getProof() ? "OK\n\n" : "Not OK :(\n\n";

        print "With MITM:\n";
        $this->server->setA($this->sniffer->sniffA($this->client->getA()));
        $this->client->setSalt($this->sniffer->sniffSalt($this->server->getSalt()));
        $this->client->setu($this->sniffer->sniffu($this->server->getu()));
        $this->client->setB($this->sniffer->sniffB($this->server->getB()));

        $proofC = $this->sniffer->sniffProofC($this->client->getProof());
        $proofS = $this->sniffer->sniffProofS($this->server->getProof());

        print $proofS === $proofC ? "OK\n\n" : "Not OK :(\n\n";

        return true;
    }
}
