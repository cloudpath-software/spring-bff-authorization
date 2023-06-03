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
package com.snapwise.security.bff.authorization.web.server

import com.snapwise.security.bff.authorization.utils.ReactiveWebUtils
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.ResponseCookie
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.http.server.reactive.ServerHttpResponse
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository
import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.util.Assert
import org.springframework.util.SerializationUtils
import org.springframework.util.StringUtils
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import reactor.core.scheduler.Schedulers
import java.time.Duration
import java.util.*

/**
 * An implementation of an [AuthorizationRequestRepository] that stores
 * [OAuth2AuthorizationRequest] in the `HttpSession`.
 *
 * @see AuthorizationRequestRepository
 * @see OAuth2AuthorizationRequest
 */
open class BffCookieOAuth2ServerAuthorizationRequestRepository: ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest?> {
    private var cookieName = DEFAULT_COOKIE_NAME

    private var cookieHttpOnly = true

    private var cookiePath: String? = null

    private var cookieDomain: String? = null

    private var secure: Boolean? = null

    private var cookieMaxAge = -1

    /**
     * Gets the state parameter from the [ServerWebExchange]
     * @param exchange the request to use
     * @return the state parameter or null if not found
     */
    private fun getStateParameter(exchange: ServerWebExchange): String {
        return exchange.request.queryParams.getValue(OAuth2ParameterNames.STATE).first()
    }

    private fun getAuthorizationRequest(exchange: ServerWebExchange): Mono<OAuth2AuthorizationRequest?> {
        return loadToken(exchange.request)
    }

    fun setCookiePath(path: String) {
        this.cookiePath = path
    }

    fun setCookieDomain(domain: String) {
        this.cookieDomain = domain
    }

    fun setCookieSecure(secure: Boolean) {
        this.secure = secure
    }

    companion object {
        private const val DEFAULT_COOKIE_NAME = "c2e2885e4da9ce085cc5796899198bb"
    }

    override fun loadAuthorizationRequest(exchange: ServerWebExchange): Mono<OAuth2AuthorizationRequest?> {
        return getAuthorizationRequest(exchange).mapNotNull { authorizationRequest ->
            authorizationRequest
        }
    }

    override fun removeAuthorizationRequest(exchange: ServerWebExchange): Mono<OAuth2AuthorizationRequest?> {
        return loadAuthorizationRequest(exchange).flatMap { authorizationRequest ->
           Mono.justOrEmpty(authorizationRequest)
        }
    }

    override fun saveAuthorizationRequest(
        authorizationRequest: OAuth2AuthorizationRequest?,
        exchange: ServerWebExchange
    ): Mono<Void> {
        if(authorizationRequest == null) {
            return removeAuthorizationRequest(exchange).then().ignoreElement()
        }

        return Mono.just(authorizationRequest).publishOn(Schedulers.boundedElastic()).flatMap {
            val state = authorizationRequest.state
            Assert.hasText(state, "authorizationRequest.state cannot be empty")
            save(authorizationRequest, exchange).then()
        }
    }


    fun save(oAuth2AuthorizationRequest: OAuth2AuthorizationRequest?, exchange: ServerWebExchange): Mono<Unit> {
        return Mono.fromCallable {
            val request = exchange.request
            val response = exchange.response

            val tokenValue = if(oAuth2AuthorizationRequest != null) { serialize(oAuth2AuthorizationRequest) } else { "" }
            val maxAge = if (oAuth2AuthorizationRequest != null) cookieMaxAge else 0

            val cookie = ResponseCookie.from(cookieName, tokenValue)
                .secure(secure ?: (request.sslInfo != null))
                .path(if (StringUtils.hasLength(cookiePath)) cookiePath else this.getRequestContext(request))
                .maxAge(Duration.ofSeconds(maxAge.toLong()))
                .httpOnly(cookieHttpOnly)
                .domain(cookieDomain)

                .build()

            response.addCookie(cookie)

            // Set request attribute to signal that response has blank cookie value,
            // which allows loadToken to return null when token has been removed

            // Set request attribute to signal that response has blank cookie value,
            // which allows loadToken to return null when token has been removed
            if (!StringUtils.hasLength(tokenValue)) {
//            request.setAttribute(USER_SESSION_TOKEN_REMOVED_ATTRIBUTE_NAME, java.lang.Boolean.TRUE)
            } else {
//            request.removeAttribute(USER_SESSION_TOKEN_REMOVED_ATTRIBUTE_NAME)
            }
        }
    }

    fun deleteCookie(exchange: ServerWebExchange, response: HttpServletResponse, name: String) {
        val request = exchange.request

        request.cookies.map {
            val entryCookies = it.value

            for(cookie in entryCookies) {
//                if(cookie.name == name) {
//
//                    cookie.name
//
//                    response.addCookie()
//                }
            }
        }
    }


    private fun getRequestContext(request: ServerHttpRequest): String {
        val contextPath = request.path.contextPath().value()
        return contextPath.ifEmpty { "/" }
    }

    private fun loadToken(request: ServerHttpRequest): Mono<OAuth2AuthorizationRequest?> {
        val cookie = ReactiveWebUtils.getHttpCookie(request, cookieName)
        val value = cookie?.value

        return Mono.fromCallable {
            if (!StringUtils.hasLength(value)) {
                null
            } else if(value != null) { deserialize(value, OAuth2AuthorizationRequest::class.java)} else { null }
        }
    }

    private fun serialize(`object`: Any): String {
        return Base64.getUrlEncoder()
            .encodeToString(SerializationUtils.serialize(`object`))
    }

    private fun <T> deserialize(value: String, cls: Class<T>): T {
        return cls.cast(
            SerializationUtils.deserialize(Base64.getUrlDecoder().decode(value)))
    }
}