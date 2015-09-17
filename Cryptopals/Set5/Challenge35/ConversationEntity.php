<?php declare(strict_types = 1);

namespace Cryptopals\Set5\Challenge35;

use Cryptopals\Set5\Challenge33\DH;

class ConversationEntity
{
    private $name;
    private $dh;

    private $priv;
    private $pub;
    private $shared;

    public $onSend;

    protected $cbc;
    protected $pad;

    function __construct(string $name, DH $dh)
    {
        $this->name = $name;
        $this->dh = $dh;

        $this->cbc = new \AES\Mode\CBC();
        $this->pad = new \AES\Padding\PKCS7();

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

    function send(string $data)
    {
        $obj = new \stdClass();
        $obj->msg = 'dat';
        $obj->data = $data;

        $data = json_encode($obj);

        if (!is_null($this->shared)) {
            $key = substr(sha1($this->shared, true), 0, 16);
            $iv = random_bytes(16);

            $ctx = new \AES\Context\CBC($key, $iv);
            $data = $iv . $this->cbc->encrypt($ctx, $data . $this->pad->getPadding($data));
        }

        $dataLen = strlen($data);

        print "{$this->name}: sending $dataLen bytes\n";

        $func = $this->onSend;
        $func($data);
    }

    function receive(string $data)
    {
        $dataLen = strlen($data);
        print "{$this->name}: received $dataLen bytes\n";

        if (!is_null($this->shared)) {

            $key = substr(sha1($this->shared, true), 0, 16);
            $iv = substr($data, 0, 16);

            $ctx = new \AES\Context\CBC($key, $iv);
            $data = $this->cbc->decrypt($ctx, substr($data, 16));
            $data = substr($data, 0, -$this->pad->getPadLen($data));
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
