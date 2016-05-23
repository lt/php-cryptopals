<?php declare(strict_types = 1);

namespace Cryptopals\Set5\Challenge36;

use Cryptopals\Solution;

class Solution36 implements Solution
{
    protected $server;
    protected $client;

    function __construct(SRPServer $server, SRPClient $client)
    {
        $this->server = $server;
        $this->client = $client;
    }

    function execute(): bool
    {
        $I = 'email';
        $P = 'password';

        $this->server->setCredentials($I, $P);
        $this->client->setCredentials($I, $P);

        $this->client->setSalt($this->server->getSalt());
        $this->server->setA($this->client->getA());
        $this->client->setB($this->server->getB());

        return $this->server->getProof() === $this->client->getProof();
    }
}
