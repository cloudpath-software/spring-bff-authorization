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

package com.snapwise.security.gateway.filters

import com.snapwise.security.bff.authorization.UserSession
import com.snapwise.security.bff.authorization.UserSessionService
import com.snapwise.security.bff.authorization.oauth2.services.OAuth2TokenService
import com.snapwise.security.bff.authorization.web.BffAuthorizationCookieRepository
import org.slf4j.LoggerFactory
import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory
import org.springframework.cloud.gateway.support.GatewayToStringStyler
import org.springframework.core.style.ToStringCreator
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

class UserSessionGatewayFilterFactory(
    private val oAuth2TokenService: OAuth2TokenService,
    private val userSessionService: UserSessionService,
): AbstractGatewayFilterFactory<UserSessionGatewayFilterFactory.Config>(Config::class.java) {

    private val logger = LoggerFactory.getLogger(javaClass)
    override fun apply(config: Config): GatewayFilter {
        return object : GatewayFilter {
            override fun filter(exchange: ServerWebExchange, chain: GatewayFilterChain): Mono<Void> {
                val request = exchange.request
                val userSessionCookie = request.cookies[config.getCookieName()]?.first()
                    ?: return chain.filter(exchange)

                val userSession = userSessionService.findBySessionId(userSessionCookie.value)
                return if(userSession != null) {
                    validateSessionAccessToken(userSession).flatMap { isAccessTokenValid ->
                        if(isAccessTokenValid) {
                            val accessToken = userSession.accessToken

                            logger.info("session id -> ${userSession.sessionId}, added bearer authorization header")

                            val modifiedExchange = exchange.mutate().request { request ->
                                request.headers {
                                    it.remove("Cookie")
                                    it.setBearerAuth(accessToken)
                                }
                            }.build()

                            chain.filter(modifiedExchange)
                        } else {
                            val modifiedExchange = exchange.mutate().request { request ->
                                request.headers {
                                    it.remove("Cookie")
                                }
                            }.build()

                            chain.filter(modifiedExchange)
                        }
                    }
                } else {
                    chain.filter(exchange)
                }
            }

            override fun toString(): String {
                return GatewayToStringStyler.filterToStringCreator(this).append("cookieName", config.getCookieName()) .toString()
            }
        }
    }

    /**
     *  Check if user session tokens are valid. If the access token is no longer active,
     *  an attempt to refresh it using the refresh token will execute, if that fails, the
     *  user is expected to be redirected to the authorization screen to re-login.
     */
    private fun validateSessionAccessToken(userSession: UserSession): Mono<Boolean> {
        logger.info("validating tokens for session id: ${userSession.sessionId}")

        val accessToken = userSession.accessToken

        logger.info("introspecting accessToken")

        return oAuth2TokenService.introspectToken(accessToken).flatMap { accessTokenMap ->
            logger.info("introspected accessToken -> $accessTokenMap")

            val isAccessTokenActive = accessTokenMap["active"] as Boolean

            logger.info("accessToken isActive: $isAccessTokenActive")

            if(isAccessTokenActive.not()) {
                val refreshToken = userSession.refreshToken

                logger.info("introspecting refreshToken")

                oAuth2TokenService.introspectToken(refreshToken).flatMap { refreshTokenMap ->
                    logger.info("introspected refreshToken -> $refreshTokenMap")

                    val isRefreshTokenActive = refreshTokenMap["active"] as Boolean

                    logger.info("refreshToken isActive: $isRefreshTokenActive")


                    Mono.just(false)
                }
            } else {
                Mono.just(isAccessTokenActive)
            }
        }
    }

    class Config {
        private var cookieName: String = BffAuthorizationCookieRepository.DEFAULT_USER_SESSION_TOKEN_COOKIE_NAME

        fun getCookieName(): String {
            return cookieName
        }

        fun setCookieName(cookieName: String): Config {
            this.cookieName = cookieName
            return this
        }

        override fun toString(): String {
            return ToStringCreator(this).append("cookieName", cookieName).toString()
        }
    }
}