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

package com.snapwise.security.gateway.perdicates

import com.snapwise.security.bff.authorization.UserSessionService
import com.snapwise.security.bff.authorization.oauth2.services.SessionOAuth2TokenService
import com.snapwise.security.bff.authorization.web.BffAuthorizationCookieRepository
import jakarta.validation.constraints.NotEmpty
import org.slf4j.LoggerFactory
import org.springframework.cloud.gateway.handler.AsyncPredicate
import org.springframework.cloud.gateway.handler.predicate.AbstractRoutePredicateFactory
import org.springframework.http.HttpCookie
import org.springframework.validation.annotation.Validated
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import java.util.function.Predicate

/**
 * @deprecated Predicate.
 *
 * The idea was to use this predicate to manage automatically refreshing access tokens, but
 * it comes into conflict with webSecurity configurations. (ex: Routes that don't require authentication or require a different type
 * of authentication)
 */

@Deprecated(message = "Kept only temporarily, refresh access token logic was moved to UserSessionGatewayFilterFactory")
class UserSessionTokenValidatorPredicateFactory(
    private val sessionOAuth2TokenService: SessionOAuth2TokenService,
    private val userSessionService: UserSessionService
): AbstractRoutePredicateFactory<UserSessionTokenValidatorPredicateFactory.Config>(Config::class.java) {

    private val logger = LoggerFactory.getLogger(javaClass)

    override fun applyAsync(config: Config): AsyncPredicate<ServerWebExchange> {
        return AsyncPredicate<ServerWebExchange> { serverWebExchange ->
            val cookies: List<HttpCookie>? = serverWebExchange.request.cookies[config.getName()]

            if (cookies.isNullOrEmpty()) {
                logger.info("no user session cookie found.")
                return@AsyncPredicate Mono.just(false)
            }

            val userSessionId: String = cookies.first().value
            val userSession = userSessionService.findById(userSessionId).block()

            if(userSession != null) {
                logger.info("validating tokens for session id: ${userSession.sessionId}")

                val accessToken = userSession.accessToken

                logger.info("introspecting accessToken")

                sessionOAuth2TokenService.introspectToken(accessToken).flatMap { accessTokenMap ->
                    logger.info("introspected accessToken -> $accessTokenMap")

                    val isAccessTokenActive = accessTokenMap["active"] as Boolean

                    logger.info("accessToken isActive: $isAccessTokenActive")

                    if(isAccessTokenActive.not()) {
                        val refreshToken = userSession.refreshToken

                        logger.info("introspecting refreshToken")

                        sessionOAuth2TokenService.introspectToken(refreshToken).flatMap { refreshTokenMap ->
                            logger.info("introspected refreshToken -> $refreshTokenMap")

                            val isRefreshTokenActive = refreshTokenMap["active"] as Boolean

                            logger.info("refreshToken isActive: $isRefreshTokenActive")


                            Mono.just(false)
                        }
                    } else {
                        Mono.just(isAccessTokenActive)
                    }
                }
            } else {
                logger.info("no user session found.")

                Mono.just(false)
            }
        }
    }

    override fun apply(config: Config): Predicate<ServerWebExchange> {
        throw UnsupportedOperationException("TokenValidatorPredicateFactory is only async.");
    }

    @Validated
    class Config {
        private var name: @NotEmpty String = BffAuthorizationCookieRepository.DEFAULT_USER_SESSION_TOKEN_COOKIE_NAME
        private var regexp: @NotEmpty String = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"

        fun getName(): String {
            return name
        }

        fun setName(name: String): Config {
            this.name = name
            return this
        }

        fun getRegexp(): String {
            return regexp
        }

        fun setRegexp(regexp: String): Config {
            this.regexp = regexp
            return this
        }
    }
}