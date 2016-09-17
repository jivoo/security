<?php
// Jivoo Security
// Copyright (c) 2016 Niels Sonnich Poulsen (http://nielssp.dk)
// Licensed under the MIT license.
// See the LICENSE file or http://opensource.org/licenses/MIT for more information.
namespace Jivoo\Security\Authentication;

/**
 * Description of SessionAuthentication
 */
class SessionAuthentication implements \Jivoo\Security\Authentication
{
    
    /**
     * @var \Jivoo\Store\Document
     */
    private $session;
    
    private $name = 'auth_session';
    
    private $renewName = 'auth_renew_at';
    
    private $renewAfter = 1800;
    
    private $lifeTime = 3600;
    
    private $sessionId = null;
    
    public function __construct(\Jivoo\Store\Document $session)
    {
        $this->session = $session;
    }
    
    public function authenticate($data, \Jivoo\Security\UserModel $userModel, \Jivoo\Security\PasswordHasher $hasher)
    {
        if (isset($this->session[$this->name])) {
            $sessionId = $this->session[$this->name];
            $user = $userModel->openSession($sessionId);
            if ($user) {
                $this->sessionId = $sessionId;
                if (isset($this->session[$this->renewName])) {
                    if ($this->session[$this->renewName] <= time()) {
                        $this->session[$this->renewName] = time() + $this->renewAfter;
                        $userModel->renewSession($sessionId, time() + $this->lifeTime);
                    }
                }
                return $user;
            }
            unset($this->session[$this->name]);
        }
        return null;
    }

    public function deauthenticate($userData, \Jivoo\Security\UserModel $userModel)
    {
        $userModel->deleteSession($this->sessionId);
        unset($this->sessionId);
        if (isset($this->session[$this->name])) {
            unset($this->session[$this->name]);
            unset($this->session[$this->renewName]);
        }
    }
    
    public function create($user, \Jivoo\Security\UserModel $userModel)
    {
        $sessionId = $userModel->createSession($user, time() + $this->lifeTime);
        $this->session[$this->name] = $sessionId;
        $this->session[$this->renewName] = time() + $this->renewAfter;
        $this->sessionId = $sessionId;
        return true;
    }
}
