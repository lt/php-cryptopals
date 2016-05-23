<?php declare(strict_types = 1);

namespace Cryptopals\Set1\Challenge7;

use AES\Key;

class YellowSubmarineKey extends Key
{
    function __construct()
    {
        parent::__construct('YELLOW SUBMARINE');
    }
}
