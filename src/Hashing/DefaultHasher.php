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
     * Construct hasher.
     * @throws UnsupportedHashTypeException If tha hash type is not supported by
     * the current PHP installation.
     */
    public function __construct()
    {
        if (!function_exists('password_hash')) {
            throw new UnsupportedHashTypeException(
                'Unsupported password hasher: ' . get_class($this)
            );
        }
    }

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
    public function compare($password, $hash)
    {
        return password_verify($password, $hash);
    }
}
