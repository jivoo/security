<?php
// Jivoo Security
// Copyright (c) 2016 Niels Sonnich Poulsen (http://nielssp.dk)
// Licensed under the MIT license.
// See the LICENSE file or http://opensource.org/licenses/MIT for more information.
namespace Jivoo\Security\Authentication;

/**
 * Description of SessionAuthentication
 */
class CookieAuthentication implements \Jivoo\Security\Authentication
{
    
    /**
     * @var \Jivoo\Http\Cookie\CookiePool
     */
    private $cookies;
    
    private $name = 'auth_session';
    
    private $renewName = 'auth_renew_at';
    
    private $renewAfter = 1800;
    
    private $lifeTime = 3600;
    
    private $sessionId = null;
    
    public function __construct(\Jivoo\Http\Cookie\CookiePool $cookies)
    {
        $this->cookies = $cookies;
    }
    
    public function authenticate($data, \Jivoo\Security\UserModel $userModel, \Jivoo\Security\PasswordHasher $hasher)
    {
        if (isset($this->cookies[$this->name])) {
            $sessionId = $this->cookies[$this->name];
            $user = $userModel->openSession($sessionId);
            if ($user) {
                $this->sessionId = $sessionId;
                if (isset($this->cookies[$this->renewName])) {
                    if ($this->cookies[$this->renewName] <= time()) {
                        $this->cookies[$this->name]->expiresAfter($this->lifeTime);
                        $this->cookies[$this->renewName]->setValue(time() + $this->renewAfter)
                            ->expiresAfter($this->lifeTime);
                        $userModel->renewSession($sessionId, time() + $this->lifeTime);
                    }
                }
                return $user;
            }
            unset($this->cookies[$this->name]);
        }
        return null;
    }

    public function deauthenticate($userData, \Jivoo\Security\UserModel $userModel)
    {
        $userModel->deleteSession($this->sessionId);
        unset($this->sessionId);
        if (isset($this->cookies[$this->name])) {
            unset($this->cookies[$this->name]);
            unset($this->cookies[$this->renewName]);
        }
    }
    
    public function create($user, \Jivoo\Security\UserModel $userModel)
    {
        $sessionId = $userModel->createSession($user, time() + $this->lifeTime);
        $this->cookies[$this->name]->setValue($sessionId)
            ->expiresAfter($this->lifeTime);
        $this->cookies[$this->renewName]->setValue(time() + $this->renewAfter)
            ->expiresAfter($this->lifeTime);
        $this->sessionId = $sessionId;
        return true;
    }
}
