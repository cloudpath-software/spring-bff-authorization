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

import com.fasterxml.jackson.annotation.JsonProperty
import java.io.Serializable
import java.util.*

/**
 * A representation of a bff user session info linked to the client's session id.
 *
 * Structure outline: https://datatracker.ietf.org/doc/html/draft-bertocci-oauth2-tmi-bff-01#section-5.2
 *
 * @since 0.0.1
 */
data class UserSessionInfo(
    /**
     * @return the identifier for the user's unique identifier.
     */
    @JsonProperty("sub")
    val sub: String,
    /**
     * @return the user's given name.
     */
    @JsonProperty("given_name")
    val givenName: String,
    /**
     * @return the user's family name.
     */
    @JsonProperty("family_name")
    val familyName: String,
    /**
     * @return the user's email.
     */
    @JsonProperty("email_verified")
    val emailVerified: String,
    /**
     * @return the user's preferred username.
     */
    @JsonProperty("preferred_username")
    val preferredUsername: String,
    /**
     * OAuth2 issuer identifier.
     *
     * @return the authorization issuer identifier.
     */
    @JsonProperty("iss")
    val iss: String,
    /**
     * Timestamp when the user session was created.
     *
     * @return created timestamp.
     */
    @JsonProperty("auth_time")
    val authTime: Long,
    /**
     * Timestamp when the user session will expire.
     *
     * @return expiring timestamp.
     */
    @JsonProperty("exp")
    val exp: Long,
): Serializable {

    /**
     * A builder for [UserSessionInfo].
     */
    class Builder : Serializable {
        private var sub: String? = null
        private var givenName: String? = null
        private var familyName: String? = null
        private var emailVerified:  String? = null
        private var preferredUsername: String? = null
        private var iss: String? = null
        private var authTime: Long? = null
        private var exp: Long? = null

        /**
         * Sets the session info user identifier.
         *
         * @param sub the identifier for the session's user.
         * @return the [Builder]
         */
        fun sub(sub: String): Builder {
            this.sub = sub
            return this
        }

        /**
         * Sets the session info user given name.
         *
         * @param givenName user's given name.
         * @return the [Builder]
         */
        fun givenName(givenName: String): Builder {
            this.givenName = givenName
            return this
        }

        /**
         * Sets the session info user family name.
         *
         * @param givenName user's family name.
         * @return the [Builder]
         */
        fun familyName(familyName: String): Builder {
            this.familyName = familyName
            return this
        }

        /**
         * Sets the session info user email.
         *
         * @param emailVerified user's email.
         * @return the [Builder]
         */
        fun emailVerified(emailVerified: String): Builder {
            this.emailVerified = emailVerified
            return this
        }

        /**
         * Sets the session info user preferred username.
         *
         * @param preferredUsername user's preferred username.
         * @return the [Builder]
         */
        fun preferredUsername(preferredUsername: String): Builder {
            this.preferredUsername = preferredUsername
            return this
        }

        /**
         * Sets the session info oauth2 issuer.
         *
         * @param iss authorization issuer identifier.
         * @return the [Builder]
         */
        fun iss(iss: String): Builder {
            this.iss = iss
            return this
        }

        /**
         * Sets the session info's session created timestamp.
         *
         * @param authTime created timestamp.
         * @return the [Builder]
         */
        fun authTime(authTime: Long): Builder {
            this.authTime = authTime
            return this
        }

        /**
         * Sets the session info's session expiration timestamp.
         *
         * @param exp expiring timestamp.
         * @return the [Builder]
         */
        fun expTime(exp: Long): Builder {
            this.exp = exp
            return this
        }

        /**
         * Builds a new [UserSessionInfo].
         *
         * @return the [UserSessionInfo]
         */
        fun build(): UserSessionInfo {
            return UserSessionInfo(
                sub = sub!!,
                givenName = givenName!!,
                familyName = familyName!!,
                emailVerified = emailVerified!!,
                preferredUsername = preferredUsername!!,
                iss = iss!!,
                authTime = authTime!!,
                exp = exp!!
            )
        }
    }
}