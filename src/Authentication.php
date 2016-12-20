<?php
// Jivoo
// Copyright (c) 2015 Niels Sonnich Poulsen (http://nielssp.dk)
// Licensed under the MIT license.
// See the LICENSE file or http://opensource.org/licenses/MIT for more information.
namespace Jivoo\Security;

/**
 * A method of authentication.
 */
interface Authentication
{

    /**
     * Attempt to authenticate a user.
     * @param array $data Associative array of authentication data.
     * @param UserModel $userModel User model to use for authentication.
     * @return mixed|null User data (e.g. an {@see Jivoo\Models\BasicRecord})
     * or null on failure.
     */
    public function authenticate($data, UserModel $userModel);

    /**
     * Deauthenticate a user.
     * @param mixed $userData User data.
     * @param UserModel $userModel User model.
     */
    public function deauthenticate($userData, UserModel $userModel);
    
    /**
     * Create user authentication.
     * @param mixed $userData User data.
     * @param UserModel $userModel User model.
     * @return bool True if created, false otherwise.
     */
    public function create($userData, UserModel $userModel);
}
