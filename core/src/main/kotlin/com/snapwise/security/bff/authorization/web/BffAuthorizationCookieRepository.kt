package com.snapwise.security.bff.authorization.web

import jakarta.servlet.ServletRequest
import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.util.Assert
import org.springframework.util.StringUtils
import org.springframework.web.util.WebUtils
import java.util.*

/**
 * A [UserSessionTokenRepository] that persists the UserSession token in a cookie named "BFF-UST-TOKEN"
 * and reads from the header "X-US-TOKEN".
 */
class BffAuthorizationCookieRepository: UserSessionTokenRepository {
    companion object {
        const val DEFAULT_USER_SESSION_TOKEN_COOKIE_NAME = "cloud.session.token"
        private const val DEFAULT_BFF_UST_PARAMETER_NAME = "_ust"
        const val DEFAULT_USER_SESSION_TOKEN_HEADER_NAME = "X-US-TOKEN"
        private val USER_SESSION_TOKEN_REMOVED_ATTRIBUTE_NAME = "${Companion::class.java.name}.REMOVED"
    }

    private var parameterName = DEFAULT_BFF_UST_PARAMETER_NAME

    private var headerName = DEFAULT_USER_SESSION_TOKEN_HEADER_NAME

    private var cookieName = DEFAULT_USER_SESSION_TOKEN_COOKIE_NAME

    private var cookieHttpOnly = true

    private var cookiePath: String? = null

    private var cookieDomain: String? = null

    private var secure: Boolean? = null

    private var cookieMaxAge = -1

    override fun generateToken(request: HttpServletRequest): UserSessionAuthenticationToken {
        return DefaultUserSessionAuthenticationToken(this.headerName, this.parameterName, createNewToken())
    }

    override fun saveToken(token: UserSessionAuthenticationToken?, request: HttpServletRequest, response: HttpServletResponse) {
        val tokenValue = token?.getToken() ?: ""
        val cookie = Cookie(cookieName, tokenValue)
        cookie.secure = secure ?: request.isSecure
        cookie.path = if (StringUtils.hasLength(cookiePath)) cookiePath else this.getRequestContext(request)
        cookie.maxAge = if (token != null) cookieMaxAge else 0
        cookie.isHttpOnly = cookieHttpOnly
        if (StringUtils.hasLength(cookieDomain)) {
            cookie.domain = cookieDomain
        }
        response.addCookie(cookie)

        // Set request attribute to signal that response has blank cookie value,
        // which allows loadToken to return null when token has been removed

        // Set request attribute to signal that response has blank cookie value,
        // which allows loadToken to return null when token has been removed
        if (!StringUtils.hasLength(tokenValue)) {
            request.setAttribute(USER_SESSION_TOKEN_REMOVED_ATTRIBUTE_NAME, java.lang.Boolean.TRUE)
        } else {
            request.removeAttribute(USER_SESSION_TOKEN_REMOVED_ATTRIBUTE_NAME)
        }
    }

    override fun loadToken(request: HttpServletRequest): UserSessionAuthenticationToken? {
        // Return null when token has been removed during the current request
        // which allows loadDeferredToken to re-generate the token

        // Return null when token has been removed during the current request
        // which allows loadDeferredToken to re-generate the token
        if (java.lang.Boolean.TRUE == request.getAttribute(USER_SESSION_TOKEN_REMOVED_ATTRIBUTE_NAME)) {
            return null
        }
        val cookie = WebUtils.getCookie(request, cookieName) ?: return null
        val token = cookie.value
        return if (!StringUtils.hasLength(token)) {
            null
        } else DefaultUserSessionAuthenticationToken(headerName, parameterName, token)
    }

    /**
     * Sets the name of the HTTP request parameter that should be used to provide a token.
     * @param parameterName the name of the HTTP request parameter that should be used to
     * provide a token
     */
    fun setParameterName(parameterName: String) {
        this.parameterName = parameterName
    }

    /**
     * Sets the name of the HTTP header that should be used to provide the token.
     * @param headerName the name of the HTTP header that should be used to provide the
     * token
     */
    fun setHeaderName(headerName: String) {
        this.headerName = headerName
    }

    /**
     * Sets the name of the cookie that the expected UserSession token is saved to and read from.
     * @param cookieName the name of the cookie that the expected UserSession token is saved to
     * and read from
     */
    fun setCookieName(cookieName: String) {
        this.cookieName = cookieName
    }

    /**
     * Sets the HttpOnly attribute on the cookie containing the UserSession token. Defaults to
     * `true`.
     * @param cookieHttpOnly `true` sets the HttpOnly attribute,
     * `false` does not set it
     */
    fun setCookieHttpOnly(cookieHttpOnly: Boolean) {
        this.cookieHttpOnly = cookieHttpOnly
    }

    private fun getRequestContext(request: HttpServletRequest): String? {
        val contextPath = request.contextPath
        return contextPath.ifEmpty { "/" }
    }

    /**
     * Factory method to conveniently create an instance that has
     * [.setCookieHttpOnly] set to false.
     * @return an instance of CookieCsrfTokenRepository with
     * [.setCookieHttpOnly] set to false
     */
    fun withHttpOnlyFalse(): BffAuthorizationCookieRepository {
        val result = BffAuthorizationCookieRepository()
        result.setCookieHttpOnly(false)
        return result
    }

    private fun createNewToken(): String {
        return UUID.randomUUID().toString()
    }

    /**
     * Set the path that the Cookie will be created with. This will override the default
     * functionality which uses the request context as the path.
     * @param path the path to use
     */
    fun setCookiePath(path: String?) {
        cookiePath = path
    }

    /**
     * Get the path that the UserSession cookie will be set to.
     * @return the path to be used.
     */
    fun getCookiePath(): String? {
        return cookiePath
    }

    /**
     * Sets the domain of the cookie that the expected UserSession token is saved to and read
     * from.
     * @param cookieDomain the domain of the cookie that the expected UserSession token is saved
     * to and read from
     */
    fun setCookieDomain(cookieDomain: String?) {
        this.cookieDomain = cookieDomain
    }

    /**
     * Sets secure flag of the cookie that the expected UserSession token is saved to and read
     * from. By default secure flag depends on [ServletRequest.isSecure]
     * @param secure the secure flag of the cookie that the expected UserSession token is saved
     * to and read from
     */
    fun setSecure(secure: Boolean) {
        this.secure = secure
    }

    /**
     * Sets maximum age in seconds for the cookie that the expected UserSession token is saved to
     * and read from. By default maximum age value is -1.
     *
     *
     *
     * A positive value indicates that the cookie will expire after that many seconds have
     * passed. Note that the value is the *maximum* age when the cookie will expire,
     * not the cookie's current age.
     *
     *
     *
     * A negative value means that the cookie is not stored persistently and will be
     * deleted when the Web browser exits.
     *
     *
     *
     * A zero value causes the cookie to be deleted immediately therefore it is not a
     * valid value and in that case an [IllegalArgumentException] will be thrown.
     * @param cookieMaxAge an integer specifying the maximum age of the cookie in seconds;
     * if negative, means the cookie is not stored; if zero, the method throws an
     * [IllegalArgumentException]
     */
    fun setCookieMaxAge(cookieMaxAge: Int) {
        Assert.isTrue(cookieMaxAge != 0, "cookieMaxAge cannot be zero")
        this.cookieMaxAge = cookieMaxAge
    }
}