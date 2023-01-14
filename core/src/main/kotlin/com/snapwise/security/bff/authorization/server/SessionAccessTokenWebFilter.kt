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

package com.snapwise.security.bff.authorization.server

import com.snapwise.security.bff.authorization.UserSessionService
import com.snapwise.security.bff.authorization.utils.ReactiveWebUtils
import com.snapwise.security.bff.authorization.web.BffAuthorizationCookieRepository.Companion.DEFAULT_USER_SESSION_TOKEN_COOKIE_NAME
import org.apache.commons.logging.LogFactory
import org.springframework.core.io.buffer.DataBuffer
import org.springframework.core.io.buffer.DefaultDataBufferFactory
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.web.server.ServerAuthenticationEntryPoint
import org.springframework.security.web.server.authentication.*
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository
import org.springframework.security.web.server.context.ServerSecurityContextRepository
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono
import java.nio.charset.StandardCharsets

class SessionAccessTokenWebFilter(
    private val userSessionService: UserSessionService,
    userSessionAccessTokenEndpointUri: String = DEFAULT_USER_SESSION_ACCESS_TOKEN_ENDPOINT_URI
): WebFilter {

    private val logger = LogFactory.getLog(javaClass)

    private val userSessionAccessTokenEndpointMatcher: ServerWebExchangeMatcher =
        PathPatternParserServerWebExchangeMatcher(userSessionAccessTokenEndpointUri)

    private var authenticationEntryPoint: ServerAuthenticationEntryPoint = HttpBasicServerAuthenticationEntryPoint()

    private val authenticationManagerResolver: ReactiveAuthenticationManagerResolver<ServerWebExchange>? = null

    private val authenticationSuccessHandler: ServerAuthenticationSuccessHandler =
        WebFilterChainServerAuthenticationSuccessHandler()

    private val authenticationConverter: ServerAuthenticationConverter = ServerHttpBasicAuthenticationConverter()

    private val authenticationFailureHandler: ServerAuthenticationFailureHandler =
        ServerAuthenticationEntryPointFailureHandler(HttpBasicServerAuthenticationEntryPoint())

    private val securityContextRepository: ServerSecurityContextRepository = NoOpServerSecurityContextRepository
        .getInstance()

    private val requiresAuthenticationMatcher = ServerWebExchangeMatchers.anyExchange()

    override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> {
        return userSessionAccessTokenEndpointMatcher.matches(exchange).flatMap {
            logger.info("filter called -> $this")

            val serverHttpRequest = exchange.request
            val serverHttpResponse = exchange.response

            val userSessionCookie = ReactiveWebUtils.getHttpCookie(serverHttpRequest, DEFAULT_USER_SESSION_TOKEN_COOKIE_NAME)
            val userSession = userSessionCookie?.let { userSessionService.findBySessionId(it.value) }

            if(userSession != null) {
                val userSessionAccessToken = userSession.accessToken

                serverHttpResponse.statusCode = HttpStatus.OK
                serverHttpResponse.headers.contentType = MediaType.APPLICATION_JSON

                val dataBuffer: DataBuffer = DefaultDataBufferFactory().wrap(
                    userSessionAccessToken.toByteArray(StandardCharsets.UTF_8))

                serverHttpResponse.headers.accessControlAllowOrigin = "http://127.0.0.1:3004"
                serverHttpResponse.headers.accessControlAllowCredentials = true

                serverHttpResponse.writeWith(Mono.just(dataBuffer))
            } else {
                serverHttpResponse.statusCode = HttpStatus.FORBIDDEN
                serverHttpResponse.headers.contentType = MediaType.APPLICATION_JSON

                serverHttpResponse.writeWith(Mono.empty())
            }
        }
    }

    /**
     * Sets the authentication entry point used when authentication is required
     * @param authenticationEntryPoint the authentication entry point to use. Default is
     * [HttpBasicServerAuthenticationEntryPoint]
     */
    fun setAuthenticationEntryPoint(authenticationEntryPoint: ServerAuthenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint
    }

    companion object {
        /**
         * The default endpoint `URI` for access token requests.
         */
        const val DEFAULT_USER_SESSION_ACCESS_TOKEN_ENDPOINT_URI = "/bff/oauth2/session-access-token"
        private const val DEFAULT_ERROR_URI =
            "https://datatracker.ietf.org/doc/html/draft-bertocci-oauth2-tmi-bff-01#section-4.3.2"

        private fun throwError(errorCode: String, parameterName: String) {
            val error = OAuth2Error(errorCode, "OAuth 2.0 Parameter: $parameterName", DEFAULT_ERROR_URI)
            throw OAuth2AuthenticationException(error)
        }
    }
}