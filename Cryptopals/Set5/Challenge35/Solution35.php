<?php

/*
 * http://cryptopals.com/sets/5/challenges/35/
 *
 * Implement DH with negotiated groups, and break with malicious "g" parameters
 *
 * A->B
 * Send "p", "g"
 * B->A
 * Send ACK
 * A->B
 * Send "A"
 * B->A
 * Send "B"
 * A->B
 * Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
 * B->A
 * Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
 *
 * Do the MITM attack again, but play with "g". What happens with:
 * g = 1
 * g = p
 * g = p - 1
 *
 * Write attacks for each.
 *
 * When does this ever happen?
 * Honestly, not that often in real-world systems. If you can mess with "g", chances are you can mess with something worse. Most systems pre-agree on a static DH group. But the same construction exists in Elliptic Curve Diffie-Hellman, and this becomes more relevant there.
 */

/*
 * g = 1
 * ---------------
 * a and b = rand
 * A and B = (1**rand) % p == 1
 * s = (1**rand) % p == 1
 *
 * g = p
 * ---------------
 * a and b = rand
 * A and B = (p**rand) % p == 1 (i.e. 3**4 == 81, 81 % 3 = 0)
 * s = (0**rand) % p == 0
 *
 * g = p - 1
 * ---------------
 * a and b = rand
 * A and B = ((p-1)**rand) % p
 *      when rand is even == 1 (i.e. 4**2 == 16, 16 % 5 == 1)
 *      when rand is odd == p - 1 (i.e. 4**3 == 64, 64 % 5 == 4)
 * s = (B**a) % p
 *      when B is 1 and a is even then s == 1
 *      when B is p - 1
 *          when a is even == 1
 *          when a is odd == p - 1
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

    private $state = 0;

    public $onSend;

    function __construct($name, DH $dh)
    {
        $this->name = $name;
        $this->dh = $dh;

        $this->priv = $this->dh->generatePrivate();
    }

    function groupNeg()
    {
        print "{$this->name}: p/g neg\n";

        $obj = new \stdClass();
        $obj->msg = 'neg';
        $obj->p = $this->dh->p();
        $obj->g = $this->dh->g();

        $func = $this->onSend;
        $func(json_encode($obj));
    }

    function groupAck()
    {
        print "{$this->name}: p/g ack\n";

        $obj = new \stdClass();
        $obj->msg = 'ack';
        $obj->p = $this->dh->p();
        $obj->g = $this->dh->g();

        $func = $this->onSend;
        $func(json_encode($obj));
    }

    function sendPub()
    {
        print "{$this->name}: send pub\n";

        $this->pub = $this->dh->generatePublic($this->priv);

        $obj = new \stdClass();
        $obj->msg = 'pub';
        $obj->pub = gmp_strval($this->pub, 16);

        $func = $this->onSend;
        $func(json_encode($obj));
    }

    function send($data)
    {
        $obj = new \stdClass();
        $obj->msg = 'dat';
        $obj->data = $data;

        $data = json_encode($obj);

        if (!is_null($this->shared)) {
            $key = sha1($this->shared, true);
            $iv = random_bytes(16);

            $data = $iv . encryptAES128CBC($data, $key, $iv);
        }

        $dataLen = strlen($data);

        print "{$this->name}: sending $dataLen bytes\n";

        $func = $this->onSend;
        $func($data);
    }

    function receive($data)
    {
        $dataLen = strlen($data);
        print "{$this->name}: received $dataLen bytes\n";

        if (!is_null($this->shared)) {
            $key = sha1($this->shared, true);
            $iv = substr($data, 0, 16);

            $data = decryptAES128CBC(substr($data, 16), $key, $iv);
        }

        $obj = json_decode($data);

        switch ($obj->msg) {
            case 'neg':
                print "{$this->name}: received group negotiation\n";
                $this->dh->g($obj->g);
                $this->groupAck();
                $this->sendPub();
                break;
            case 'ack':
                print "{$this->name}: received group acknowledgement\n";
                $this->dh->g($obj->g);
                $this->sendPub();
                break;
            case 'pub':
                print "{$this->name}: received public key\n";
                $this->shared = gmp_strval($this->dh->generateShared($this->priv, gmp_init($obj->pub, 16)), 16);
                break;
            case 'dat':
                print "{$this->name}: received data: {$obj->data}\n";
                break;
            default:
                print "{$this->name}: unknown message\n";
        }
    }
}

class MITM
{
    function sniffData($data)
    {
        return $data;
    }

    function __construct(ConversationEntity $A, ConversationEntity $B)
    {
        $A->onSend = function($data) use ($B) {
            $B->receive($this->sniffData($data));
        };

        $B->onSend = function($data) use ($A) {
            $A->receive($this->sniffData($data));
        };
    }
}

class MITM1 extends MITM
{
    function sniffData($data)
    {
        $obj = json_decode($data);
        if (is_object($obj)) {
            if (is_object($obj) && ($obj->msg === 'neg' || $obj->msg === 'ack')) {
                print "M: manipulating g\n";
                $obj->g = '1';
                $data = json_encode($obj);
            }
            else {
                print "M: sniffed: $data\n";
            }
        }
        else {
            $key = sha1('1', true);
            $iv = substr($data, 0, 16);

            $message = decryptAES128CBC(substr($data, 16), $key, $iv);
            print "M: sniffed: $message\n";
        }
        return $data;
    }
}

class MITMP extends MITM
{
    function sniffData($data)
    {
        $obj = json_decode($data);
        if (is_object($obj)) {
            if (is_object($obj) && ($obj->msg === 'neg' || $obj->msg === 'ack')) {
                print "M: manipulating g\n";
                $obj->g = $obj->p;
                $data = json_encode($obj);
            }
            else {
                print "M: sniffed: $data\n";
            }
        }
        else {
            $key = sha1('0', true);
            $iv = substr($data, 0, 16);

            $message = decryptAES128CBC(substr($data, 16), $key, $iv);
            print "M: sniffed: $message\n";
        }
        return $data;
    }
}


class MITMPminus1 extends MITM
{
    private $Pminus1;

    function sniffData($data)
    {
        $obj = json_decode($data);
        if (is_object($obj)) {
            if ($obj->msg === 'neg' || $obj->msg === 'ack') {
                print "M: manipulating g\n";
                $this->Pminus1 = gmp_strval(gmp_sub(gmp_init($obj->p, 16), gmp_init(1)), 16);
                $obj->g = $this->Pminus1;
                $data = json_encode($obj);
            }
            else {
                print "M: sniffed: $data\n";
            }
        }
        else {
            $key = sha1('1', true);
            $iv = substr($data, 0, 16);

            $message = decryptAES128CBC(substr($data, 16), $key, $iv);

            // kind of dirty I guess, but gets the job done.
            $obj = json_decode($message);
            if (!is_object($obj)) {
                $key = sha1($this->Pminus1, true);
                $iv = substr($data, 0, 16);

                $message = decryptAES128CBC(substr($data, 16), $key, $iv);
            }

            print "M: sniffed: $message\n";
        }
        return $data;
    }
}


print "Testing normal comms:\n\n";

$A = new ConversationEntity('A', new DH);
$B = new ConversationEntity('B', new DH);

$M = new MITM($A, $B);

$A->groupNeg();
$A->send('Hello there!');
$B->send('Hi!');



print "\nMITM with g = 1:\n\n";

$A = new ConversationEntity('A', new DH);
$B = new ConversationEntity('B', new DH);

$M = new MITM1($A, $B);

$A->groupNeg();
$A->send('Hello there!');
$B->send('Hi!');



print "\nMITM with g = p:\n\n";

$A = new ConversationEntity('A', new DH);
$B = new ConversationEntity('B', new DH);

$M = new MITMP($A, $B);

$A->groupNeg();
$A->send('Hello there!');
$B->send('Hi!');



print "\nMITM with g = p - 1:\n\n";

$A = new ConversationEntity('A', new DH);
$B = new ConversationEntity('B', new DH);

$M = new MITMPminus1($A, $B);

$A->groupNeg();
$A->send('Hello there!');
$B->send('Hi!');
