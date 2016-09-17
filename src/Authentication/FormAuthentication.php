<?php
// Jivoo
// Copyright (c) 2015 Niels Sonnich Poulsen (http://nielssp.dk)
// Licensed under the MIT license.
// See the LICENSE file or http://opensource.org/licenses/MIT for more information.
namespace Jivoo\Security\Authentication;

use Jivoo\Security\Authentication;
use Jivoo\Security\PasswordHasher;
use Jivoo\Security\UserModel;

/**
 * Authentication using a POST-method form. Expects fields named "username" and
 * "password". If a field "remember" is set, a long-lived cookie will be
 * created. The names of the fields can be changed with options "username"
 * and "password".
 */
class FormAuthentication implements Authentication
{

    /**
     * @var string
     */
    private $usernameField;
    
    public function __construct($usernameField = 'username')
    {
        $this->usernameField = $usernameField;
    }

    /**
     * {@inheritdoc}
     */
    public function authenticate($data, UserModel $userModel, PasswordHasher $hasher)
    {
        if (!is_array($data)) {
            return null;
        }
        $idData = array();
        $idData[$this->usernameField] = $data[$this->usernameField];
        $user = $userModel->findUser($idData);
        if (isset($user)) {
            $password = $userModel->getPassword($user);
            if ($hasher->compare($data['password'], $password)) {
                return $user;
            }
        }
        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function deauthenticate($userData, \Jivoo\Security\UserModel $userModel)
    {
    }

    /**
     * {@inheritdoc}
     */
    public function create($userData, \Jivoo\Security\UserModel $userModel)
    {
        return false;
    }
}
