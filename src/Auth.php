<?php
// Jivoo
// Copyright (c) 2015 Niels Sonnich Poulsen (http://nielssp.dk)
// Licensed under the MIT license.
// See the LICENSE file or http://opensource.org/licenses/MIT for more information.
namespace Jivoo\Security;

use Jivoo\Assume;
use Jivoo\InvalidPropertyException;
use Jivoo\Security\Acl\DefaultAcl;
use Jivoo\Security\Hashing\DefaultHasher;
use Jivoo\Utilities;

/**
 * Module for authentication and authorization.
 *
 * @property UserModel $userModel User model.
 * @property array|Linkable|string|null $loginRoute Route for login page, ee
 * {@see Routing}.
 * @property array|Linkable|string|null $unauthorizedRoute Route to redirect to
 * when user unauthorized, see {@see Routing}.
 * @property array|Linkable|string|null $ajaxRoute Route to redirect to for
 * AJAX requests,  see {@see Routing}.
 * @property-read string $sessionId Current session id.
 * @property bool $createSessions Whether or not to create sessions.
 * @property string $sessionPrefix Session prefix.
 * @property int $sessionLifeTime Life time of session in seconds.
 * @property int $sessionRenewAfter Number of seconds after which the session
 * is renewed.
 * @property bool $createCookies Whether or not to create cookies.
 * @property string $cookiePrefix Cookie prefix.
 * @property int $cookieLifeTime Life time of cookies in seconds.
 * @property int $cookieRenewAfter Number of seconds after which the cookie
 * is renewed.
 * @property string $permissionPrefix Prefix for permissions when checking
 * access control lists.
 * @property-read mixed $user User data of current user if logged in, otherwise
 * null.
 * @property-write string|Authentication|string[]|Authentication[]|array[] $authentication
 * Add one or more access control lists. Can be the name of a class (without
 * 'Authentication'-suffix) or a list of names, see
 * {@see LoadableAuthentication}. Can also be an associative array mapping names
 * to options.
 * @property-write string|Authorization|string[]|Authorization[]|array[] $authorization
 * Add one or more access control lists. Can be the name of a class (without
 * 'Authorization'-suffix) or a list of names, see {@see LoadableAuthorization}.
 * Can also be an associative array mapping names to options.
 * @property-write string|Acl|string[]|Acl[]|array[] $acl
 * Add one or more access control lists. Can be the name of a class (without
 * 'Acl'-suffix) or a list of names, see {@see LoadableAcl}. Can also be an
 * associative array mapping names to options.
 */
class Auth
{

    /**
     * @var UserModel User model.
     */
    private $userModel;

    /**
     * @var mixed Current user, if logged in.
     */
    private $user = null;

    /**
     * @var string Prefix for permissions.
     */
    private $permissionPrefix = '';

    /**
     * @var Authentication[] Associative array of authentication methods.
     */
    private $authenticationMethods = [];
    
    /**
     * @var AuthenticationWrapper[]
     */
    private $authenticationWrappers = [];

    /**
     * @var Authorization[] Associative array of authorization methods.
     */
    private $authorizationMethods = [];

    /**
     * @var Acl[] Associative array of ACL handlers.
     */
    private $aclMethods = [];

    /**
     * @var (Authentication|Authorization|Acl)[]
     */
    private $acModules = [];

    /**
     * @var DefaultAcl Default access control list.
     */
    private $defaultAcl = null;

    public function __construct(UserModel $userModel)
    {
        $this->userModel = $userModel;
        $this->defaultAcl = new DefaultAcl();
        $this->addAcl($this->defaultAcl);
    }
    

    /**
     * {@inheritdoc}
     */
    public function __get($property)
    {
        switch ($property) {
            case 'userModel':
            case 'loginRoute':
            case 'unauthorizedRoute':
            case 'ajaxRoute':
            case 'permissionPrefix':
                return $this->$property;
            case 'user':
                return $this->getUser();
        }
        if (isset($this->authenticationWrappers[$property])) {
            return $this->authenticationWrappers[$property];
        }
        throw new InvalidPropertyException('Undefined property: ' . $property);
    }

    /**
     * {@inheritdoc}
     */
    public function __set($property, $value)
    {
        switch ($property) {
            case 'userModel':
            case 'loginRoute':
            case 'unauthorizedRoute':
            case 'ajaxRoute':
            case 'permissionPrefix':
                $this->$property = $value;
                return;
            case 'authentication':
                if (is_array($value)) {
                    foreach ($value as $method) {
                        $this->addAuthorization($method);
                    }
                } else {
                    $this->addAuthorization($value);
                }
                return;
            case 'authorization':
                if (is_array($value)) {
                    foreach ($value as $method) {
                        $this->addAuthorization($method);
                    }
                } else {
                    $this->addAuthorization($value);
                }
                return;
            case 'acl':
                if (is_array($value)) {
                    foreach ($value as $method) {
                        $this->addAcl($method);
                    }
                } else {
                    $this->addAcl($value);
                }
                return;
        }
        if ($value instanceof Authentication) {
            $this->addAuthentication($value, $property);
            return;
        }
        throw new InvalidPropertyException('Undefined property: ' . $property);
    }

    /**
     * Add an authentication module.
     * @param Authentication $authentication Module.
     * @param string $name Name that can be used to later access the module using
     * {@see __get}, default is the class name (without namespace).
     */
    public function addAuthentication(Authentication $authentication, $name = null)
    {
        $this->authenticationMethods[] = $authentication;
        if (!isset($name)) {
            $name = Utilities::getClassName($authentication);
        }
        $this->authenticationWrappers[$name] = new AuthenticationWrapper($this, $authentication);
        $this->acModules[$name] = $authentication;
    }

    /**
     * Add an authorization module.
     * @param Authorization $authorization Module.
     * @param string $name Name that can be used to later access the module using
     * {@see __get}, default is the class name (without namespace).
     */
    public function addAuthorization(Authorization $authorization, $name = null)
    {
        $this->authorizationMethods[] = $authorization;
        if (!isset($name)) {
            $name = Utilities::getClassName($authorization);
        }
        $this->acModules[$name] = $authorization;
    }

    /**
     * Add an ACL module.
     * @param Acl $acl Module.
     * @param string $name Name that can be used to later access the module using
     * {@see __get}, default is the class name (without namespace).
     */
    public function addAcl(Acl $acl, $name = null)
    {
        $this->aclMethods[] = $acl;
        if (!isset($name)) {
            $name = Utilities::getClassName($acl);
        }
        $this->acModules[$name] = $acl;
    }

    /**
     * Add permission to default access control list.
     * @param string $permission Permission string.
     */
    public function allow($permission = null)
    {
        $this->defaultAcl->allow($permission);
    }

    /**
     * Remove a permission from default access control list.
     * @param string $permission Permission string.
     */
    public function deny($permission = null)
    {
        $this->defaultAcl->deny($permission);
    }

    /**
     * Whether or not a user is logged in. Checks both session, cookie, and
     * stateless authentication.
     * @return boolean True if user logged in.
     */
    public function isLoggedIn()
    {
        return isset($this->userModel) and isset($this->user);
    }

    /**
     * Whether or not current user (or guest) has a permission.
     * @param string $permission Permission string.
     * @param string $prefix Prefix for permission, see also {@see $permissionPrefix}.
     * @return boolean True if user has permission, false otherwise.
     */
    public function hasPermission($permission, $prefix = null)
    {
        if (!isset($prefix)) {
            $prefix = $this->permissionPrefix;
        }
        return $this->checkAcl($prefix . $permission);
    }

    /**
     * Check a permission on all access control lists.
     * @param string $permission Permission string.
     * @return boolean True if permission granted, false otherwise.
     */
    private function checkAcl($permission)
    {
        foreach ($this->aclMethods as $method) {
            if ($method->hasPermission($permission, $this->user)) {
                return true;
            }
        }
        if (strpos($permission, '.') !== false) {
            if ($this->checkAcl(preg_replace('/\\.[^\.]+?$/', '', $permission))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check user authorization for a route.
     * @param array|\Jivoo\Routing\Linkable|string|null $route A route,
     * see {@see \Jivoo\Routing\Routing}.
     * @param mixed $user Optional user data, if null the current user is used.
     * @return bool True if user is authorized.
     */
    public function hasAuthorization($route, $user = null)
    {
        if (count($this->authorizationMethods) == 0) {
            return true;
        }
        if (!isset($user)) {
            $user = $this->getUser();
        }
        $route = $this->m->Routing->validateRoute($route);
        if (isset($route['void'])) {
            return true;
        }
        $authRequest = new AuthorizationRequest($route, $user);
        foreach ($this->authorizationMethods as $method) {
            if ($method->authorize($authRequest)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Get current user if logged in.
     * @return mixed User data of current user, null if not logged in.
     */
    public function getUser()
    {
        if (!isset($this->user)) {
            $this->isLoggedIn();
        }
        return $this->user;
    }

    /**
     * Use available authentication methods to log in.
     *
     * @param mixed $token Authentication token.
     * @return boolean True if successfully logged in, false otherwise.
     */
    public function authenticate($token, Authentication $method = null)
    {
        if (isset($method)) {
            $user = $method->authenticate($token, $this->userModel);
            if ($user !== null) {
                $this->user = $user;
            }
        } else {
            foreach ($this->authenticationMethods as $method) {
                $user = $method->authenticate($token, $this->userModel);
                if ($user !== null) {
                    $this->user = $user;
                }
            }
        }
        return isset($this->user);
    }
    
    /**
     * Log out and delete session.
     */
    public function deauthenticate()
    {
        if ($this->isLoggedIn()) {
            foreach ($this->authenticationMethods as $method) {
                $method->deauthenticate($this->user, $this->userModel);
            }
            unset($this->user);
        }
    }
}
