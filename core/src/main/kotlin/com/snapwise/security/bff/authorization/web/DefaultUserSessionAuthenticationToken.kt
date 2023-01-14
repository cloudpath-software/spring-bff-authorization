package com.snapwise.security.bff.authorization.web

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.core.OAuth2Token

/**
 * A UserSession token that is used to abstract the [OAuth2Token] management and
 * keep token references within the BFF (backend for frontend) instance.
 * @param headerName the HTTP header name to use
 * @param parameterName the HTTP parameter name to use
 * @param token the value of the token (i.e. expected value of the HTTP parameter of
 * parametername).
 */
class DefaultUserSessionAuthenticationToken(
    private val headerName: String,
    private val parameterName: String,
    private val token: String
): UserSessionAuthenticationToken {

    override fun getHeaderName(): String {
        return headerName
    }

    override fun getParameterName(): String {
        return parameterName
    }

    override fun getToken(): String {
        return token
    }
}