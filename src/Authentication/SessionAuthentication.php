<?php
// Jivoo Security
// Copyright (c) 2016 Niels Sonnich Poulsen (http://nielssp.dk)
// Licensed under the MIT license.
// See the LICENSE file or http://opensource.org/licenses/MIT for more information.
namespace Jivoo\Security\Authentication;

/**
 * Session authentication.
 */
class SessionAuthentication implements \Jivoo\Security\Authentication
{
    
    /**
     * @var \Jivoo\Store\Document
     */
    private $session;
    
    /**
     * Name of authentication session key.
     *
     * @var string
     */
    public $name = 'auth_session';
    
    /**
     * Name of renew session key.
     *
     * @var string
     */
    public $renewName = 'auth_renew_at';
    
    /**
     * Number of seconds after which the session is renewed.
     *
     * @var int
     */
    public $renewAfter = 1800; // 30 minutes

    /**
     * Life time of session in seconds.
     *
     * @var int
     */
    public $lifeTime = 3600; // 60 minutes
    
    /**
     * @var string
     */
    private $sessionId = null;
    
    /**
     * Construct session authentication object.
     *
     * @param \Jivoo\Store\Document $session Session data.
     */
    public function __construct(\Jivoo\Store\Document $session)
    {
        $this->session = $session;
    }
    
    /**
     * {@inheritdoc}
     */
    public function authenticate($data, \Jivoo\Security\UserModel $userModel)
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
            unset($this->session[$this->renewName]);
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
        if (isset($this->session[$this->name])) {
            unset($this->session[$this->name]);
            unset($this->session[$this->renewName]);
        }
    }
    
    /**
     * {@inheritdoc}
     */
    public function create($user, \Jivoo\Security\UserModel $userModel)
    {
        $sessionId = $userModel->createSession($user, time() + $this->lifeTime);
        $this->session[$this->name] = $sessionId;
        $this->session[$this->renewName] = time() + $this->renewAfter;
        $this->sessionId = $sessionId;
        return true;
    }
}
