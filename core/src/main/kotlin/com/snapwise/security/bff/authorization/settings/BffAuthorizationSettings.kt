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

package com.snapwise.security.bff.authorization.settings

import com.snapwise.security.bff.authorization.TokenEndpointFilter
import com.snapwise.security.bff.authorization.server.SessionAccessTokenWebFilter
import com.snapwise.security.bff.authorization.server.SessionEndWebFilter
import com.snapwise.security.bff.authorization.server.SessionInfoWebFilter


/**
 * A facility for authorization server configuration settings.
 *
 * @since 0.1.0
 * @see AbstractSettings
 *
 * @see ConfigurationSettingNames.BffAuthorization
 */
class BffAuthorizationSettings(override val settings: Map<String, Any> = mapOf()) : AbstractSettings(settings) {
    val tokenEndpoint: String
        /**
         * Returns the bff token endpoint. The default is `/bff/oauth2/bff-token`.
         *
         * @return the token endpoint
         */
        get() = getSetting(ConfigurationSettingNames.BffAuthorization.TOKEN_ENDPOINT)
    val sessionAccessTokenEndpoint: String
        /**
         * Returns the bff session info endpoint. The default is `/bff/oauth2/session-access-token`.
         *
         * @return the SessionInfo endpoint
         */
        get() = getSetting(ConfigurationSettingNames.BffAuthorization.SESSION_ACCESS_TOKEN_ENDPOINT)
    val sessionInfoEndpoint: String
        /**
         * Returns the bff session info endpoint. The default is `/bff/oauth2/session-info`.
         *
         * @return the SessionInfo endpoint
         */
        get() = getSetting(ConfigurationSettingNames.BffAuthorization.SESSION_INFO_ENDPOINT)
    val sessionEndEndpoint: String
        /**
         * Returns the bff session end endpoint. The default is `/bff/oauth2/session-end`.
         *
         * @return the SessionEnd endpoint
         */
        get() = getSetting(ConfigurationSettingNames.BffAuthorization.SESSION_END_ENDPOINT)

    /**
     * A builder for [AuthorizationServerSettings].
     */
    class Builder : AbstractBuilder<BffAuthorizationSettings, Builder>() {

        /**
         * Sets the Bff Token endpoint.
         *
         * @param tokenEndpoint the Token endpoint
         * @return the [Builder] for further configuration
         */
        fun tokenEndpoint(tokenEndpoint: String): Builder {
            return setting(ConfigurationSettingNames.BffAuthorization.TOKEN_ENDPOINT, tokenEndpoint)
        }

        /**
         * Sets the Bff Token endpoint.
         *
         * @param sessionAccessTokenEndpoint the session access token endpoint
         * @return the [Builder] for further configuration
         */
        fun sessionAccessTokenEndpoint(sessionAccessTokenEndpoint: String): Builder {
            return setting(ConfigurationSettingNames.BffAuthorization.SESSION_ACCESS_TOKEN_ENDPOINT, sessionAccessTokenEndpoint)
        }

        /**
         * Sets the Bff session info endpoint.
         *
         * @param sessionInfoEndpoint the session info endpoint
         * @return the [Builder] for further configuration
         */
        fun sessionInfoEndpoint(sessionInfoEndpoint: String): Builder {
            return setting(ConfigurationSettingNames.BffAuthorization.SESSION_INFO_ENDPOINT, sessionInfoEndpoint)
        }

        /**
         * Sets the Bff session end endpoint.
         *
         * @param sessionEndEndpoint the session end endpoint
         * @return the [Builder] for further configuration
         */
        fun sessionEndEndpoint(sessionEndEndpoint: String): Builder {
            return setting(
                ConfigurationSettingNames.BffAuthorization.SESSION_END_ENDPOINT,
                sessionEndEndpoint
            )
        }

        /**
         * Builds the [BffAuthorizationSettings].
         *
         * @return the [BffAuthorizationSettings]
         */
        override fun build(): BffAuthorizationSettings {
            return BffAuthorizationSettings(settings)
        }
    }

    companion object {
        /**
         * Constructs a new [Builder] with the default settings.
         *
         * @return the [Builder]
         */
        fun builder(): Builder {
            return Builder()
                .tokenEndpoint(TokenEndpointFilter.DEFAULT_TOKEN_ENDPOINT_URI)
                .sessionAccessTokenEndpoint(SessionAccessTokenWebFilter.DEFAULT_USER_SESSION_ACCESS_TOKEN_ENDPOINT_URI)
                .sessionInfoEndpoint(SessionInfoWebFilter.DEFAULT_SESSION_INFO_ENDPOINT_URI)
                .sessionEndEndpoint(SessionEndWebFilter.DEFAULT_SESSION_END_ENDPOINT_URI)
        }

        /**
         * Constructs a new [Builder] with the provided settings.
         *
         * @param settings the settings to initialize the builder
         * @return the [Builder]
         */
        fun withSettings(settings: Map<String, Any>): Builder {
            return Builder()
                .settings { s: Map<String, Any> -> s.toMutableMap().putAll(settings) }
        }
    }
}