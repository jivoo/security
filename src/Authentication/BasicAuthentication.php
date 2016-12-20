<?php
// Jivoo
// Copyright (c) 2015 Niels Sonnich Poulsen (http://nielssp.dk)
// Licensed under the MIT license.
// See the LICENSE file or http://opensource.org/licenses/MIT for more information.
namespace Jivoo\Security\Authentication;

use Jivoo\Security\Authentication;
use Jivoo\Security\UserModel;

/**
 * Authentication using Basic HTTP authentication.
 */
class BasicAuthentication implements Authentication
{

    /**
     * @var string|null
     */
    private $realm;
    
    /**
     * @var string
     */
    private $usernameField;
    
    public function __construct($realm = null, $usernameField = 'username')
    {
        $this->realm = $realm;
        $this->usernameField = $usernameField;
    }

    /**
     * {@inheritdoc}
     */
    public function authenticate($data, UserModel $userModel)
    {
        if (!isset($this->realm)) {
            $this->realm = $_SERVER['SERVER_NAME'];
        }
        if (isset($_SERVER['PHP_AUTH_USER']) and isset($_SERVER['PHP_AUTH_PW'])) {
            $idData = array();
            $idData[$this->usernameField] = $_SERVER['PHP_AUTH_USER'];
            $user = $userModel->findUser($idData);
            if (isset($user)) {
                if ($userModel->verifyPassword($user, $_SERVER['PHP_AUTH_PW'])) {
                    return $user;
                }
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
