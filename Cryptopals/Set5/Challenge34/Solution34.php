<?php

/*
 * http://cryptopals.com/sets/5/challenges/34/
 *
 * Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
 *
 * Use the code you just worked out to build a protocol and an "echo" bot. You don't actually have to do the network part of this if you don't want; just simulate that. The protocol is:
 *
 * A->B
 * Send "p", "g", "A"
 * B->A
 * Send "B"
 * A->B
 * Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
 * B->A
 * Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
 *
 * (In other words, derive an AES key from DH with SHA1, use it in both directions, and do CBC with random IVs appended or prepended to the message).
 *
 * Now implement the following MITM attack:
 *
 * A->M
 * Send "p", "g", "A"
 * M->B
 * Send "p", "g", "p"
 * B->M
 * Send "B"
 * M->A
 * Send "p"
 * A->M
 * Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
 * M->B
 * Relay that to B
 * B->M
 * Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
 * M->A
 * Relay that to A
 *
 * M should be able to decrypt the messages. "A" and "B" in the protocol --- the public keys, over the wire --- have been swapped out with "p". Do the DH math on this quickly to see what that does to the predictability of the key.
 *
 * Decrypt the messages from M's vantage point as they go by.
 *
 * Note that you don't actually have to inject bogus parameters to make this attack work; you could just generate Ma, MA, Mb, and MB as valid DH parameters to do a generic MITM attack. But do the parameter injection attack; it's going to come up again.
 */

require_once '../utils/random-bytes.php';
require_once '../02-block-crypto/10-implement-cbc-mode.php';
require_once '../04-stream-crypto-and-randomness/28-implement-a-sha-1-keyed-mac.php';
require_once '33-implement-diffie-hellman.php';

class ConversationEntity
{
    private $name;
    private $dh;

    private $priv;
    private $pub;
    private $shared;

    public $onSend;

    function __construct($name, DH $dh)
    {
        $this->name = $name;
        $this->dh = $dh;

        $this->priv = $dh->generatePrivate();
        $this->pub = $dh->generatePublic($this->priv);
    }

    function kexRequest()
    {
        print "{$this->name}: kex req\n";

        $obj = new \stdClass();
        $obj->p = $this->dh->p();
        $obj->g = $this->dh->g();
        $obj->A = gmp_strval($this->pub, 16);

        $func = $this->onSend;
        $func(json_encode($obj));
    }

    function kexResponse($data)
    {
        $obj = json_decode($data);
        // we can ignore p and g for now, since we use the same DH implementation. Normally we'd have to do "stuff"
        if (property_exists($obj, 'A')) {
            $this->shared = gmp_strval($this->dh->generateShared($this->priv, gmp_init($obj->A, 16)), 16);

            $obj = new \stdClass();
            $obj->B = gmp_strval($this->pub, 16);

            print "{$this->name}: kex resp\n";

            $func = $this->onSend;
            $func(json_encode($obj));
        }
        elseif (property_exists($obj, 'B')) {
            $this->shared = gmp_strval($this->dh->generateShared($this->priv, gmp_init($obj->B, 16)), 16);
        }
    }

    function send($data)
    {
        $key = sha1($this->shared, true);
        $iv = getRandomBytes(16);

        $message = $iv . encryptAES128CBC($data, $key, $iv);

        print "{$this->name}: sending: $data\n";

        $func = $this->onSend;
        $func($message);
    }

    function receive($data)
    {
        if (!$this->shared) {
            $this->kexResponse($data);
            return;
        }

        $key = sha1($this->shared, true);
        $iv = substr($data, 0, 16);

        $message = decryptAES128CBC(substr($data, 16), $key, $iv);

        print "{$this->name} received: $message\n";
    }
}


$dh = new DH;

print "Testing normal comms:\n\n";

$A = new ConversationEntity('A', $dh);
$B = new ConversationEntity('B', $dh);

$A->onSend = [$B, 'receive'];
$B->onSend = [$A, 'receive'];

$A->kexRequest();
$A->send('Hello there!');
$B->send('Hi!');

print "\nSetting up MITM:\n\n";

$state = 0;
$stolenP = null;
$evilShared = null;

$A = new ConversationEntity('A', $dh);
$B = new ConversationEntity('B', $dh);

$A->onSend = function($data) use ($B, &$state, &$stolenP, &$evilShared, $dh) {
    if ($state === 0) {
        print "M: Manipulating kex req\n";

        $obj = json_decode($data);
        $obj->A = $obj->p;

        $stolenP = gmp_init($obj->p, 16);
        $evilShared = gmp_strval($dh->generateShared($stolenP, $stolenP), 16);

        $state = 1;
        $B->receive(json_encode($obj));
    }
    else {
        $key = sha1($evilShared, true);
        $iv = substr($data, 0, 16);

        $message = decryptAES128CBC(substr($data, 16), $key, $iv);

        print "M: sniffed: $message\n";
    }
};

$B->onSend = function($data) use ($A, &$state, &$stolenP, &$evilShared) {
    if ($state === 1) {
        print "M: Manipulating kex resp\n";

        $obj = json_decode($data);
        $obj->B = gmp_strval($stolenP, 16);

        $state = 2;
        $A->receive(json_encode($obj));
    }
    else {
        $key = sha1($evilShared, true);
        $iv = substr($data, 0, 16);

        $message = decryptAES128CBC(substr($data, 16), $key, $iv);

        print "M: sniffed: $message\n";
    }
};

$A->kexRequest();
$A->send('Hello there!');
$B->send('Hi!');
