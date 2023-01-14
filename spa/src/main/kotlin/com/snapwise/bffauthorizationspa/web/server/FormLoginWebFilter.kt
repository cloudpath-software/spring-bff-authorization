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

package com.snapwise.bffauthorizationspa.web.server

import org.apache.commons.logging.LogFactory
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver
import org.springframework.security.web.server.ServerAuthenticationEntryPoint
import org.springframework.security.web.server.authentication.*
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository
import org.springframework.security.web.server.context.ServerSecurityContextRepository
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono

class FormLoginWebFilter: WebFilter {

    private val logger = LogFactory.getLog(javaClass)

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
        logger.info("filter called -> $this")

        return Mono.just(null)
    }

    /**
     * Sets the authentication entry point used when authentication is required
     * @param authenticationEntryPoint the authentication entry point to use. Default is
     * [HttpBasicServerAuthenticationEntryPoint]
     */
    fun setAuthenticationEntryPoint(authenticationEntryPoint: ServerAuthenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint
    }
}