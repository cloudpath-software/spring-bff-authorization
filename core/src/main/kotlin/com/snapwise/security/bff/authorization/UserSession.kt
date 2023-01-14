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

import com.snapwise.security.bff.authorization.utils.BffAuthorizationVersion
import org.springframework.lang.Nullable
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.OAuth2RefreshToken
import org.springframework.security.oauth2.core.OAuth2Token
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.util.Assert
import java.io.Serializable
import java.util.*

/**
 * A representation of a bff user session, which holds state related to authorization of a resource owner
 * using the owner's session id to retrieve their [OAuth2AccessToken] and [OAuth2RefreshToken] to access certain
 * resource servers.
 *
 * @since 0.0.1
 * @see OAuth2AccessToken
 *
 * @see OAuth2RefreshToken
 */
data class UserSession(
    /**
     * Returns the user session identifier.
     *
     * @return the identifier for the user session.
     */
    val sessionId: String,

    /**
     *  Expected to be implemented separately.
     *  Returns the identifier for the oauth2 resource owner id.
     *
     * @return the identifier for the resource owner.
     */
    val userId: String,

    /**
     * The identifier of the desired resource server, as
     * defined in [RFC8707](https://datatracker.ietf.org/doc/html/rfc8707).
     *
     * @return an identifier of a resource server
     */
    val resource: String,

    /**
     * The scope of the access request resulting in the desired
     * access token.  This parameter follows the syntax described in
     * section 3.3 of [RFC6749].
     *
     * @return the `Set` of authorized scope(s)
     */
    val scopes: Set<String>,

    /**
     * Resource owner access token value
     *
     * @return the access token value
     */
    val accessToken: String,

    /**
     * Resource owner access token value
     *
     * @return the access token value
     */
    val refreshToken: String,
): Serializable {

    private val tokens: MutableMap<Class<OAuth2Token>, OAuth2Authorization.Token<OAuth2Token>> = mutableMapOf()


    @Nullable
    fun getRefreshToken(): OAuth2Authorization.Token<OAuth2RefreshToken>? {
        return getToken(OAuth2RefreshToken::class.java)
    }


    /**
     * Returns the [Token] of type `tokenType`.
     *
     * @param tokenType the token type
     * @param <T> the type of the token
     * @return the [Token], or `null` if not available
    </T> */
    @Nullable
    fun <T : OAuth2Token> getToken(tokenType: Class<T>): OAuth2Authorization.Token<T>? {
        val token: OAuth2Authorization.Token<*> = this.tokens.getValue(tokenType as Class<OAuth2Token>)
        return if(token != null) token as OAuth2Authorization.Token<T> else null
    }


    /**
     * A builder for [UserSession].
     */
    class Builder() : Serializable {
        private var sessionId: String? = null
        private var userId: String? = null
        private var resource: String? = null
        private var scopes: Set<String> = emptySet()
        private var accessToken: String? = null
        private var refreshToken: String? = null

        /**
         * Sets the identifier for the user session.
         *
         * @param sessionId the identifier for the authorization
         * @return the [Builder]
         */
        fun sessionId(sessionId: String): Builder {
            this.sessionId = sessionId
            return this
        }

        /**
         * Sets the resource owner id.
         *
         * @param userId the resource owner id
         * @return the [Builder]
         */
        fun userId(userId: String): Builder {
            this.userId = userId
            return this
        }

        /**
         * Sets the reference resource server identifier which the session access token has access too.
         *
         * @param resource the reference resource server identifier.
         * @return the [Builder]
         */
        fun withResource(resource: String): Builder {
            this.resource = resource
            return this
        }

        /**
         * Sets the granted scopes of the user session.
         *
         * @param scopes the `Set` of granted scope(s)
         * @return the [Builder]
         */
        fun withScopes(scopes: Set<String>): Builder {
            this.scopes = scopes
            return this
        }

        /**
         * Sets the access token value.
         *
         * @param accessToken the user session access token value.
         * @return the [Builder]
         */
        fun accessToken(accessToken: String): Builder {
            this.accessToken = accessToken
            return this
        }

        /**
         * Sets the [refresh token][OAuth2RefreshToken].
         *
         * @param refreshToken the user session refresh token value.
         * @return the [Builder]
         */
        fun refreshToken(refreshToken: String): Builder {
            this.refreshToken = refreshToken
            return this
        }

        /**
         * Builds a new [UserSession].
         *
         * @return the [UserSession]
         */
        fun build(): UserSession {
            Assert.hasText(sessionId, "sessionId cannot be empty")
            Assert.notNull(userId, "userId cannot be null")
            return UserSession(
                sessionId = this.sessionId!!,
                userId = this.userId!!,
                resource = this.resource!!,
                scopes = this.scopes,
                accessToken = this.accessToken!!,
                refreshToken = this.refreshToken!!
            )
        }

        companion object {
            private val serialVersionUID = BffAuthorizationVersion.SERIAL_VERSION_UID
        }
    }

    companion object {
        private val serialVersionUID = BffAuthorizationVersion.SERIAL_VERSION_UID
    }
}