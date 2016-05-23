<?php declare(strict_types = 1);

namespace Cryptopals\Set5\Challenge34;

use AES\CBC;
use AES\Key;
use Cryptopals\Set2\Challenge15\PKCS7;
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
    protected $pkcs7;

    function __construct(string $name, DH $dh, CBC $cbc)
    {
        $this->name = $name;
        $this->dh = $dh;
        $this->cbc = $cbc;

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

    function kexResponse(string $data)
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

    function send(string $data)
    {
        $key = new Key(substr(sha1($this->shared, true), 0, 16));
        $iv = random_bytes(16);

        $message = $iv . $this->cbc->encrypt($key, $iv, PKCS7::pad($data));

        print "{$this->name}: sending: $data\n";

        $func = $this->onSend;
        $func($message);
    }

    function receive(string $data)
    {
        if (!$this->shared) {
            $this->kexResponse($data);
            return;
        }

        $key = new Key(substr(sha1($this->shared, true), 0, 16));
        $iv = substr($data, 0, 16);

        $message = $this->cbc->decrypt($key, $iv, substr($data, 16));
        $message = PKCS7::depad($message);

        print "{$this->name} received: $message\n";
    }
}
