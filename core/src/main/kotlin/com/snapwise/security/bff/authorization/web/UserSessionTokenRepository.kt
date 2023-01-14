package com.snapwise.security.bff.authorization.web

import com.snapwise.security.bff.authorization.web.oauth2.BffOAuth2AuthenticationToken
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse

/**
 * An API to allow changing the method in which the expected {@link UserSessionToken} is
 * associated to the {@link HttpServletRequest}.
 */
interface UserSessionTokenRepository {
    /**
     * Generates a [UserSessionAuthenticationToken]
     * @param request the [HttpServletRequest] to use
     * @return the [UserSessionAuthenticationToken] that was generated. Cannot be null.
     */
    fun generateToken(request: HttpServletRequest): UserSessionAuthenticationToken

    /**
     * Saves the [UserSessionAuthenticationToken] using the [HttpServletRequest] and
     * [HttpServletResponse]. If the [UserSessionAuthenticationToken] is null, it is the same as
     * deleting it.
     * @param token the [UserSessionAuthenticationToken] to save or null to delete
     * @param request the [HttpServletRequest] to use
     * @param response the [HttpServletResponse] to use
     */
    fun saveToken(token: UserSessionAuthenticationToken?, request: HttpServletRequest, response: HttpServletResponse)

    /**
     * Loads the expected [UserSessionAuthenticationToken] from the [HttpServletRequest]
     * @param request the [HttpServletRequest] to use
     * @return the [UserSessionAuthenticationToken] or null if none exists
     */
    fun loadToken(request: HttpServletRequest): UserSessionAuthenticationToken?

    /**
     * Defers loading the [UserSessionAuthenticationToken] using the [HttpServletRequest] and
     * [HttpServletResponse] until it is needed by the application.
     *
     *
     * The returned [DeferredUserSessionToken] is cached to allow subsequent calls to
     * [DeferredUserSessionToken.get] to return the same [UserSessionAuthenticationToken] without the
     * cost of loading or generating the token again.
     * @param request the [HttpServletRequest] to use
     * @param response the [HttpServletResponse] to use
     * @return a [DeferredUserSessionToken] that will load the [UserSessionAuthenticationToken]
     */
    fun loadDeferredToken(request: HttpServletRequest, response: HttpServletResponse): DeferredUserSessionToken {
        return RepositoryDeferredUserSessionToken(this, request, response)
    }
}