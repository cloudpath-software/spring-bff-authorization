/*
 *
 *  * Copyright 2022 the original author or authors.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *      https://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */
package com.snapwise.security.bff.authorization

import org.springframework.lang.Nullable

/**
 * Implementations of this interface are responsible for the management
 * of [OAuth 2.0 Authorization Consent(s)][AuthorizationLogin].
 *
 * @since 0.0.1
 * @see AuthorizationLogin
 */
interface TokenService {
    /**
     * Saves the [AuthorizationLogin].
     *
     * @param authorizationConsent the [AuthorizationLogin]
     */
    fun save(authorizationConsent: com.snapwise.security.bff.authorization.AuthorizationLogin?)

    /**
     * Removes the [AuthorizationLogin].
     *
     * @param authorizationConsent the [AuthorizationLogin]
     */
    fun remove(authorizationConsent: com.snapwise.security.bff.authorization.AuthorizationLogin?)

    /**
     * Returns the [AuthorizationLogin] identified by the provided
     * `registeredClientId` and `principalName`, or `null` if not found.
     *
     * @param registeredClientId the identifier for the [RegisteredClient]
     * @param principalName the name of the [Principal]
     * @return the [AuthorizationLogin] if found, otherwise `null`
     */
    @Nullable
    fun findById(registeredClientId: String?, principalName: String?): com.snapwise.security.bff.authorization.AuthorizationLogin?
}