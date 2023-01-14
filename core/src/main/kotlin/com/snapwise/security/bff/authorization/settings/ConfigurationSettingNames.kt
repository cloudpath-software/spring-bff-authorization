package com.snapwise.security.bff.authorization.settings


/**
 * The names for all the configuration settings.
 *
 */
object ConfigurationSettingNames {
    private const val SETTINGS_NAMESPACE = "settings."

    /**
     * The names for authorization server configuration settings.
     */
    object BffAuthorization {
        private const val BFF_AUTHORIZATION_SETTINGS_NAMESPACE = SETTINGS_NAMESPACE + "bff-authorization."

        /**
         * Set the Bff Token endpoint.
         */
        const val TOKEN_ENDPOINT = BFF_AUTHORIZATION_SETTINGS_NAMESPACE + "token-endpoint"

        /**
         * Set the Bff session access token endpoint.
         */
        const val SESSION_ACCESS_TOKEN_ENDPOINT = BFF_AUTHORIZATION_SETTINGS_NAMESPACE + "session-access-token-endpoint"

        /**
         * Set the JWK Set endpoint.
         */
        const val SESSION_INFO_ENDPOINT = BFF_AUTHORIZATION_SETTINGS_NAMESPACE + "session-info-endpoint"

        /**
         * Set the Bff session end endpoint.
         */
        const val SESSION_END_ENDPOINT = BFF_AUTHORIZATION_SETTINGS_NAMESPACE + "session-end-endpoint"
    }
}