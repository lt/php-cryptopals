<?php declare(strict_types = 1);

namespace Cryptopals\Set5\Challenge34;

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
        $key = substr(sha1($this->shared, true), 0, 16);
        $iv = random_bytes(16);

        $ctx = new \AES\Context\CBC($key, $iv);
        $message = $iv . $this->cbc->encrypt($ctx, $data . $this->pad->getPadding($data));

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

        $key = substr(sha1($this->shared, true), 0, 16);
        $iv = substr($data, 0, 16);

        $ctx = new \AES\Context\CBC($key, $iv);
        $message = $this->cbc->decrypt($ctx, substr($data, 16));
        $message = substr($message, 0, -$this->pad->getPadLen($message));

        print "{$this->name} received: $message\n";
    }
}
