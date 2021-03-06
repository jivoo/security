<?php
// Jivoo Security
// Copyright (c) 2016 Niels Sonnich Poulsen (http://nielssp.dk)
// Licensed under the MIT license.
// See the LICENSE file or http://opensource.org/licenses/MIT for more information.
namespace Jivoo\Security\Authentication;

/**
 * Cookie authentication.
 */
class CookieAuthentication implements \Jivoo\Security\Authentication
{
    
    /**
     * @var \Jivoo\Http\Cookie\CookiePool
     */
    private $cookies;
    
    /**
     * Name of authentication cookie.
     *
     * @var string
     */
    public $name = 'auth_session';
    
    /**
     * Name of renew cookie.
     *
     * @var string
     */
    public $renewName = 'auth_renew_at';
    
    /**
     * Number of seconds after which the cookie is renewed.
     *
     * @var int
     */
    public $renewAfter = 864000; // 10 days

    /**
     * Life time of cookie in seconds.
     *
     * @var int
     */
    public $lifeTime = 2592000; // 30 days
    
    /**
     * @var string
     */
    private $sessionId = null;
    
    /**
     * Construct cookie authentication object.
     *
     * @param \Jivoo\Http\Cookie\CookiePool $cookies Cookie pool.
     */
    public function __construct(\Jivoo\Http\Cookie\CookiePool $cookies)
    {
        $this->cookies = $cookies;
    }
    
    /**
     * {@inheritdoc}
     */
    public function authenticate($data, \Jivoo\Security\UserModel $userModel)
    {
        if (isset($this->cookies[$this->name])) {
            $sessionId = $this->cookies[$this->name]->get();
            $user = $userModel->openSession($sessionId);
            if ($user) {
                $this->sessionId = $sessionId;
                if (isset($this->cookies[$this->renewName])) {
                    if ($this->cookies[$this->renewName]->get() <= time()) {
                        $this->cookies[$this->name]->expiresAfter($this->lifeTime);
                        $this->cookies[$this->renewName]->set(time() + $this->renewAfter)
                            ->expiresAfter($this->lifeTime);
                        $userModel->renewSession($sessionId, time() + $this->lifeTime);
                    }
                }
                return $user;
            }
            unset($this->cookies[$this->name]);
            unset($this->cookies[$this->renewName]);
        }
        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function deauthenticate($userData, \Jivoo\Security\UserModel $userModel)
    {
        $userModel->deleteSession($this->sessionId);
        unset($this->sessionId);
        if (isset($this->cookies[$this->name])) {
            unset($this->cookies[$this->name]);
            unset($this->cookies[$this->renewName]);
        }
    }
    
    /**
     * {@inheritdoc}
     */
    public function create($user, \Jivoo\Security\UserModel $userModel)
    {
        $sessionId = $userModel->createSession($user, time() + $this->lifeTime);
        $this->cookies[$this->name]->set($sessionId)
            ->expiresAfter($this->lifeTime);
        $this->cookies[$this->renewName]->set(time() + $this->renewAfter)
            ->expiresAfter($this->lifeTime);
        $this->sessionId = $sessionId;
        return true;
    }
}
