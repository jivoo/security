<?php
// Jivoo Security
// Copyright (c) 2016 Niels Sonnich Poulsen (http://nielssp.dk)
// Licensed under the MIT license.
// See the LICENSE file or http://opensource.org/licenses/MIT for more information.
namespace Jivoo\Security;

/**
 * Provides password hashing.
 */
class Hash
{
    
    /**
     * @var PasswordHasher
     */
    private static $hasher = null;
    
    public static function getHasher()
    {
        if (!isset(self::$hasher)) {
            if (function_exists('password_hash')) {
                self::$hasher = new Hashing\DefaultHasher();
            } else {
                self::$hasher = new Hashing\BcryptHasher();
            }
        }
        return self::$hasher;
    }
    
    /**
     *
     * @param \Jivoo\Security\PasswordHasher $hasher
     */
    public static function setHaher(PasswordHasher $hasher)
    {
        self::$hasher = $hasher;
    }
    
    /**
     * Hash a password.
     * @param string $password Cleartext password.
     * @return string Hashed password.
     */
    public static function hash($password)
    {
        return self::getHasher()->hash($password);
    }
    
    /**
     * Compare a cleartext password to a hash string.
     * @param string $password Cleartext password.
     * @param string $hash Hash string.
     * @return bool True if they match, false otherwise.
     */
    public static function verify($password, $hash)
    {
        return self::getHasher()->verify($password, $hash);
    }
    
    /**
     * Whether the password needs to be rehashed.
     * @param string $hash Hashed password.
     * @return bool True if a rehash is needed.
     */
    public static function needsRehash($hash)
    {
        return self::getHasher()->needsRehash($hash);
    }
}
