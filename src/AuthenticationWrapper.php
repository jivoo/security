<?php
// Jivoo Security
// Copyright (c) 2016 Niels Sonnich Poulsen (http://nielssp.dk)
// Licensed under the MIT license.
// See the LICENSE file or http://opensource.org/licenses/MIT for more information.
namespace Jivoo\Security;

/**
 * Description of АuthenticationWrapper
 */
class AuthenticationWrapper
{
    
    /**
     * @var Auth
     */
    private $auth;
    
    /**
     * @var Authentication
     */
    private $authentication;
    
    public function __construct(Auth $auth, Authentication $authentication)
    {
        $this->auth = $auth;
        $this->authentication = $authentication;
    }
    
    public function authenticate($token)
    {
        $this->auth->authenticate($token, $this->authentication);
    }
    
    public function create()
    {
        $this->authentication->create($this->auth->user, $this->auth->userModel);
    }
}
