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
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.OAuth2RefreshToken
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.util.Assert
import reactor.core.publisher.Mono
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.function.Consumer

/**
 * An [UserSessionService] that stores [UserSession]'s in-memory.
 *
 *
 * **NOTE:** This implementation should ONLY be used during development/testing.
 *
 * @since 0.0.1
 * @see UserSessionService
 */
class InMemoryUserSessionService : UserSessionService {
    private var maxInitializedAuthorizations = 100

    /*
	 * Stores "initialized" (uncompleted) authorizations, where an access token has not yet been granted.
	 * This state occurs with the authorization_code grant flow during the user consent step OR
	 * when the code is returned in the authorization response but the access token request is not yet initiated.
	 */
    private var initializedAuthorizations = Collections.synchronizedMap(
        MaxSizeHashMap<String, UserSession>(
            maxInitializedAuthorizations
        )
    )

    /*
	 * Stores "completed" authorizations, where an access token has been granted.
	 */
    private val sessions: MutableMap<String, UserSession> = ConcurrentHashMap()

    /*
	 * Constructor used for testing only.
	 */
    internal constructor(maxInitializedAuthorizations: Int) {
        this.maxInitializedAuthorizations = maxInitializedAuthorizations
        initializedAuthorizations = Collections.synchronizedMap(MaxSizeHashMap(this.maxInitializedAuthorizations))
    }

    /**
     * Constructs an `InMemoryUserSessionService` using the provided parameters.
     *
     * @param userSessions the authorization(s)
     */
    constructor(vararg userSessions: UserSession?) : this(Arrays.asList<UserSession>(*userSessions))
    /**
     * Constructs an `InMemoryUserSessionService` using the provided parameters.
     *
     * @param userSessions the authorization(s)
     */
    /**
     * Constructs an `InMemoryOAuth2AuthorizationService`.
     */
    @JvmOverloads
    constructor(userSessions: List<UserSession> = emptyList()) {
        Assert.notNull(userSessions, "authorizations cannot be null")
        userSessions.forEach(Consumer { userSession: UserSession ->
            Assert.isTrue(
                !this.sessions.containsKey(userSession.sessionId),
                "The authorization must be unique. Found duplicate identifier: " + userSession.sessionId
            )
            this.sessions[userSession.sessionId] = userSession
        })
    }

    override fun save(userSession: UserSession) {
        if (isComplete(userSession)) {
            sessions[userSession.sessionId] = userSession
        } else {
            initializedAuthorizations[userSession.sessionId] = userSession
        }
    }

    override fun remove(userSession: UserSession) {
        if (isComplete(userSession)) {
            sessions.remove(userSession.sessionId, userSession)
        } else {
            initializedAuthorizations.remove(userSession.sessionId, userSession)
        }
    }

    override fun findById(id: String): Mono<UserSession?> {
        return Mono.fromCallable {
            val userSession = sessions[id]
            userSession ?: initializedAuthorizations[id]
        }
    }

    override fun findBy(userId: String, resource: String, scopes: Set<String>): UserSession? {
        val filteredSessions = sessions.values.filter {userSession ->
            userSession.userId == userId &&
                    userSession.resource == resource &&
                    userSession.scopes == scopes
        }

        if(filteredSessions.isEmpty()) {
            return null
        }

        return filteredSessions.first()
    }

    private class MaxSizeHashMap<K, V> (private val maxSize: Int) : LinkedHashMap<K, V>() {
        override fun removeEldestEntry(eldest: Map.Entry<K, V>): Boolean {
            return size > maxSize
        }
    }

    companion object {
        private fun isComplete(userSession: UserSession): Boolean {
            return userSession.accessToken != null
        }

        private fun hasToken(
            authorization: OAuth2Authorization,
            token: String,
            @Nullable tokenType: OAuth2TokenType?
        ): Boolean {
            if (tokenType == null) {
                return matchesState(authorization, token) ||
                        matchesAuthorizationCode(authorization, token) ||
                        matchesAccessToken(authorization, token) ||
                        matchesRefreshToken(authorization, token)
            } else if (OAuth2ParameterNames.STATE == tokenType.value) {
                return matchesState(authorization, token)
            } else if (OAuth2ParameterNames.CODE == tokenType.value) {
                return matchesAuthorizationCode(authorization, token)
            } else if (OAuth2TokenType.ACCESS_TOKEN == tokenType) {
                return matchesAccessToken(authorization, token)
            } else if (OAuth2TokenType.REFRESH_TOKEN == tokenType) {
                return matchesRefreshToken(authorization, token)
            }
            return false
        }

        private fun matchesState(authorization: OAuth2Authorization, token: String): Boolean {
            return token == authorization.getAttribute(OAuth2ParameterNames.STATE)
        }

        private fun matchesAuthorizationCode(authorization: OAuth2Authorization, token: String): Boolean {
            val authorizationCode = authorization.getToken(
                OAuth2AuthorizationCode::class.java
            )
            return authorizationCode != null && authorizationCode.token.tokenValue == token
        }

        private fun matchesAccessToken(authorization: OAuth2Authorization, token: String): Boolean {
            val accessToken = authorization.getToken(
                OAuth2AccessToken::class.java
            )
            return accessToken != null && accessToken.token.tokenValue == token
        }

        private fun matchesRefreshToken(authorization: OAuth2Authorization, token: String): Boolean {
            val refreshToken = authorization.getToken(
                OAuth2RefreshToken::class.java
            )
            return refreshToken != null && refreshToken.token.tokenValue == token
        }
    }
}