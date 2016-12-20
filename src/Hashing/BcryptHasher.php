<?php
// Jivoo
// Copyright (c) 2015 Niels Sonnich Poulsen (http://nielssp.dk)
// Licensed under the MIT license.
// See the LICENSE file or http://opensource.org/licenses/MIT for more information.
namespace Jivoo\Security\Hashing;

/**
 * A password hasher using Blowfish (with PHP 5.3.7 security fixes).
 */
class BcryptHasher implements \Jivoo\Security\PasswordHasher
{
    const SALT_LENGTH = 22;

    /**
     * @var string
     */
    private $prefix;
    
    /**
     * Construct Blowfish password hasher.
     * @param int $cost A number between 4 and 31 that sets the cost of the hash
     * computation.
     */
    public function __construct($cost = 10)
    {
        assume($cost >= 4 and $cost <= 31);
        $this->prefix = sprintf('$2y$%02d$', $cost);
    }

    /**
     * Generate a random salt.
     * @return string Salt.
     */
    public static function genSalt()
    {
        $bytes = Random::bytes(self::SALT_LENGTH);
        $b64 = rtrim(base64_encode($bytes), '=');
        $salt = Binary::slice(str_replace('+', '.', $b64), 0, self::SALT_LENGTH);
        return $this->prefix . $salt;
    }

    /**
     * {@inheritdoc}
     */
    public function hash($password)
    {
        return crypt($password, self::genSalt());
    }

    /**
     * {@inheritdoc}
     */
    public function verify($password, $hash)
    {
        $actual = crypt($password, $hash);
        if (strlen($actual) != strlen($hash)) {
            return false;
        }
        $res = $hash ^ $actual;
        $ret = 0;
        for ($i = strlen($res) - 1; $i >= 0; $i--) {
            $ret |= ord($res[$i]);
        }
        return $ret === 0;
    }

    /**
     * {@inheritdoc}
     */
    public function needsRehash($hash)
    {
        return substr_compare($hash, $this->prefix, 0, strlen($this->prefix)) !== 0;
    }
}
