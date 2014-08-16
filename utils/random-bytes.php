<?php

if (extension_loaded('openssl')) {
    function getRandomBytes($count)
    {
        return openssl_random_pseudo_bytes($count);
    }
}
else if (extension_loaded('mcrypt')) {
    function getRandomBytes($count)
    {
        return mcrypt_create_iv($count, MCRYPT_DEV_URANDOM);
    }
}
else {
    throw new RuntimeException('You need either the OpenSSL or MCrypt extensions installed for this one');
}