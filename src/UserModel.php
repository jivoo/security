<?php
// Jivoo
// Copyright (c) 2015 Niels Sonnich Poulsen (http://nielssp.dk)
// Licensed under the MIT license.
// See the LICENSE file or http://opensource.org/licenses/MIT for more information.
namespace Jivoo\Security;

/**
 * A model that can be used with {@see Auth}.
 */
interface UserModel
{

    /**
     * Find a user matching the provided identification data.
     *
     * @param array $data Identification data, e.g. a username.
     * @return mixed|null User data (e.g. a {@see Jivoo\Data\Record}) or null
     * on failure.
     */
    public function findUser(array $data);
    
    /**
     * Verify a user's password.
     *
     * @param array $userData User data, as returned by {@see findUser()} or
     * {@see openSession()}.
     * @param string $password Password.
     * @return bool True if password verification succeeded, false otherwise.
     */
    public function verifyPassword($userData, $password);

    /**
     * Create a session.
     *
     * @param mixed $userData User data, as returned by {@see findUser()} or
     * {@see openSession()}.
     * @param int $validUntil Time at which session is no longer valid.
     * @return string A session id.
     */
    public function createSession($userData, $validUntil);

    /**
     * Open an existing session, i.e. find the user associated with the session id.
     *
     * @param string $sessionId A session id.
     * @return mixed|null User data (e.g. a {@see Jivoo\Data\Record}) or
     * null if session id is invalid.
     */
    public function openSession($sessionId);

    /**
     * Renew a session.
     *
     * @param string $sessionId A session id.
     * @param int $validUntil Time at which session is no longer valid.
     */
    public function renewSession($sessionId, $validUntil);

    /**
     * Delete a session.
     *
     * @param string $sessionId A session id.
     */
    public function deleteSession($sessionId);
}
