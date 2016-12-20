<?php
// Jivoo
// Copyright (c) 2015 Niels Sonnich Poulsen (http://nielssp.dk)
// Licensed under the MIT license.
// See the LICENSE file or http://opensource.org/licenses/MIT for more information.
namespace Jivoo\Security\Hashing;

use Jivoo\Security\PasswordHasher;
use Jivoo\Security\UnsupportedHashTypeException;

/**
 * A password hasher using the PHP {@see password_hash} function.
 */
class DefaultHasher implements PasswordHasher
{

    /**
     * {@inheritdoc}
     */
    public function hash($password)
    {
        return password_hash($password, PASSWORD_DEFAULT);
    }

    /**
     * {@inheritdoc}
     */
    public function verify($password, $hash)
    {
        return password_verify($password, $hash);
    }

    /**
     * {@inheritdoc}
     */
    public function needsRehash($hash)
    {
        return password_needs_rehash($hash, PASSWORD_DEFAULT);
    }
}
