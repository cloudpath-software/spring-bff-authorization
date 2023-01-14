package com.snapwise.security.bff.authorization.web

import com.snapwise.security.bff.authorization.web.oauth2.BffOAuth2AuthenticationToken

interface DeferredUserSessionToken {

    /**
     * Gets the [BffOAuth2AuthenticationToken]
     * @return a non-null [BffOAuth2AuthenticationToken]
     */
    fun get(): UserSessionAuthenticationToken?

    /**
     * Returns true if [.get] refers to a generated [BffOAuth2AuthenticationToken] or false if
     * it already existed.
     * @return true if [.get] refers to a generated [BffOAuth2AuthenticationToken] or false if
     * it already existed.
     */
    fun isGenerated(): Boolean
}