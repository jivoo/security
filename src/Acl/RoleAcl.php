<?php
// Jivoo
// Copyright (c) 2015 Niels Sonnich Poulsen (http://nielssp.dk)
// Licensed under the MIT license.
// See the LICENSE file or http://opensource.org/licenses/MIT for more information.
namespace Jivoo\Security\Acl;

use Jivoo\Security\PermissionList;
use Jivoo\Security\PermissionListBuilder;
use Jivoo\Security\InvalidRoleException;

/**
 * An access control list implementation that assumes the user data has a
 * 'role' field (can be changed with the 'field' option) that can be accessed
 * using array access.
 */
class RoleAcl implements \Jivoo\Security\Acl
{

    /**
     * {@inheritdoc}
     */
    protected $options = array(
        'field' => 'role',
        'default' => 'guest'
    );

    /**
     * @var PermissionList[]
     */
    private $roles = array();

    /**
     * {@inheritdoc}
     */
    public function hasPermission($permission, $user = null)
    {
        $role = $this->options['default'];
        $field = $this->options['field'];
        if (isset($user) and isset($user[$field])) {
            $role = $user[$field];
        }
        if (!isset($this->roles[$role])) {
            return false;
        }
        return $this->roles[$role]->hasPermission($permission);
    }

    /**
     * Get permissions of a role, or create the role if it doesn't exist.
     * @param string $role Role name or id.
     * @return PermissionList $permissions Permission list.
     */
    public function __get($role)
    {
        if (!isset($this->roles[$role])) {
            $this->createRole($role);
        }
        return $this->roles[$role];
    }

    /**
     * Get permissions of a role.
     * @param string $role Role name or id.
     * @param PermissionList $permissions Permission list.
     */
    public function __set($role, $permissions)
    {
        $this->roles[$role] = $permissions;
    }

    /**
     * Add a role.
     * @param string $role Role name or id.
     * @param PermissionList $permissions Permission list.
     */
    public function addRole($role, PermissionList $permissions)
    {
        $this->roles[$role] = $permissions;
    }

    /**
     * Create a role (an instance of {@see PermissionList}.
     * @param string $role Role name or id.
     * @param string|null $parent Optional parent role.
     * @return DefaultAcl Permission list for role.
     * @throws InvalidRoleException If the parent role is undefined.
     */
    public function createRole($role, $parent = null)
    {
        $permissions = new PermissionListBuilder($this->app);
        if (isset($parent)) {
            if (!isset($this->roles[$parent])) {
                throw new InvalidRoleException('Undefined role: ' . $parent);
            }
            $permissions->inheritFrom($this->roles[$parent]);
        }
        $this->roles[$role] = $permissions;
        return $permissions;
    }
}
