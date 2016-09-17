<?php
// Jivoo
// Copyright (c) 2015 Niels Sonnich Poulsen (http://nielssp.dk)
// Licensed under the MIT license.
// See the LICENSE file or http://opensource.org/licenses/MIT for more information.
namespace Jivoo\Security;

use Jivoo\InvalidPropertyException;

/**
 * Represents a request for authorization
 * @property-read Route $route A route.
 * @property-read mixed $user User data of requesting user.
 */
class AuthorizationRequest
{

    /**
     * @var Route
     */
    private $route;

    /**
     * @var mixed User data.
     */
    private $user;

    /**
     * Construct authorization request.
     * @param Route $route A route.
     * @param mixed $user User data of requesting user.
     */
    public function __construct(\Jivoo\Http\Route\Route $route, $user = null)
    {
        $this->route = $route;
        $this->user = $user;
    }

    /**
     * Get value of a property.
     * @param string $property Property name.
     * @return mixed Value.
     * @throws InvalidPropertyException If property is not defined.
     */
    public function __get($property)
    {
        switch ($property) {
            case 'route':
            case 'user':
                return $this->$property;
        }
        throw new InvalidPropertyException(tr('Invalid property: %1', $property));
    }
}
