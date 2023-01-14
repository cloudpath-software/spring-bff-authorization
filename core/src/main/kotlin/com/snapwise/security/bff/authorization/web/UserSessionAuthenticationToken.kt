package com.snapwise.security.bff.authorization.web

import org.springframework.security.core.Authentication
import java.io.Serializable

interface UserSessionAuthenticationToken: Serializable {
    /**
     * Gets the HTTP header that the UserSessionToken is populated on the response and can be placed
     * on requests instead of the parameter. Cannot be null.
     * @return the HTTP header that the UserSessionToken is populated on the response and can be
     * placed on requests instead of the parameter
     */
    fun getHeaderName(): String

    /**
     * Gets the HTTP parameter name that should contain the token. Cannot be null.
     * @return the HTTP parameter name that should contain the token.
     */
    fun getParameterName(): String

    /**
     * Gets the token value. Cannot be null.
     * @return the token value
     */
    fun getToken(): String
}