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
 * Authentication using Basic HTTP authentication.
 */
class BasicAuthentication extends Authentication
{

    /**
     * @var array
     */
    private $options = array(
        'realm' => null,
        'usernameField' => 'username'
    );
    
    public function __construct($realm = null, $usernameField = 'username')
    {
        $this->options['realm'] = $realm;
        $this->options['usernameField'] = $usernameField;
    }

    /**
     * {@inheritdoc}
     */
    public function authenticate($data, UserModel $userModel, PasswordHasher $hasher)
    {
        if (!isset($this->options['realm'])) {
            $this->options['realm'] = $_SERVER['SERVER_NAME'];
        }
        if (isset($_SERVER['PHP_AUTH_USER']) and isset($_SERVER['PHP_AUTH_PW'])) {
            $idData = array();
            $idData[$this->options['usernameField']] = $_SERVER['PHP_AUTH_USER'];
            $user = $userModel->findUser($idData);
            if (isset($user)) {
                $password = $userModel->getPassword($user);
                if ($hasher->compare($_SERVER['PHP_AUTH_PW'], $password)) {
                    return $user;
                }
            }
        }
        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function isStateless()
    {
        return true;
    }
}
