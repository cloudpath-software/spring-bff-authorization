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

package com.snapwise.security.bff.authorization.authentication.reactive

import com.snapwise.security.bff.authorization.oauth2.core.BffOAuth2User
import com.snapwise.security.bff.authorization.web.DefaultUserSessionAuthenticationToken
import com.snapwise.security.bff.authorization.web.oauth2.BffOAuth2AuthenticationToken
import com.snapwise.security.bff.authorization.web.reactive.BffReactiveAuthorizationCookieRepository
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.web.server.DefaultServerRedirectStrategy
import org.springframework.security.web.server.ServerRedirectStrategy
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler
import org.springframework.security.web.server.savedrequest.ServerRequestCache
import org.springframework.security.web.server.savedrequest.WebSessionServerRequestCache
import reactor.core.publisher.Mono
import java.net.URI
import java.time.Duration
import java.time.Instant


/**
 * An authentication success strategy which builds on top of the [OAuth2LoginConfigurer].
 * Following a successful authorization execution flow (ex: confidential client with
 * authorization code grant type), the expectation is a [OAuth2ClientAuthenticationToken] instance will be
 * returned by the authorization server back to the BFF service instance. These tokens will
 * be persisted and cached for future client requests.
 */
open class BffReactiveAuthenticationSuccessHandler: ServerAuthenticationSuccessHandler {

    private var location = URI.create("/")

    private var redirectStrategy: ServerRedirectStrategy = DefaultServerRedirectStrategy()

    private var requestCache: ServerRequestCache = WebSessionServerRequestCache()

    private val bffAuthorizationCookieRepository: BffReactiveAuthorizationCookieRepository =
        BffReactiveAuthorizationCookieRepository()

    init {
        bffAuthorizationCookieRepository.setCookieDomain("127.0.0.1")
        bffAuthorizationCookieRepository.setCookiePath("/")
    }

    override fun onAuthenticationSuccess(
        webFilterExchange: WebFilterExchange,
        authentication: Authentication
    ): Mono<Void> {
        val exchange = webFilterExchange.exchange

        val oAuth2AuthenticationToken = authentication as OAuth2AuthenticationToken

        val principal = oAuth2AuthenticationToken.principal as BffOAuth2User

        val accessToken = principal.accessToken!!
        val duration = Duration.between(Instant.now(), accessToken.expiresAt)

        bffAuthorizationCookieRepository.setCookieMaxAge(duration.toSeconds().toInt())
        val userSessionAuthenticationToken = DefaultUserSessionAuthenticationToken(
            "",
            "",
            token = principal.userSessionId.toString())

        val request = exchange.request
        val response = exchange.response

        bffAuthorizationCookieRepository.saveToken(userSessionAuthenticationToken, request, response)

        return this.requestCache.getRedirectUri(exchange).defaultIfEmpty(this.location)
            .flatMap { location: URI ->
                this.redirectStrategy.sendRedirect(
                    exchange,
                    location
                )
            }
    }

    fun setRequestCache(requestCache: ServerRequestCache) {
        this.requestCache = requestCache
    }

    /**
     * Where the user is redirected to upon authentication success
     * @param location the location to redirect to. The default is "/"
     */
    fun setLocation(location: URI) {
        this.location = location
    }

    /**
     * The RedirectStrategy to use.
     * @param redirectStrategy the strategy to use. Default is DefaultRedirectStrategy.
     */
    fun setRedirectStrategy(redirectStrategy: ServerRedirectStrategy) {
        this.redirectStrategy = redirectStrategy
    }
}