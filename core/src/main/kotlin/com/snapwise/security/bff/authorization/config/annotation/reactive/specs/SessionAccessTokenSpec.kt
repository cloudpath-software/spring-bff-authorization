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

package com.snapwise.security.bff.authorization.config.annotation.reactive.specs

import com.snapwise.security.bff.authorization.UserSessionService
import com.snapwise.security.bff.authorization.config.annotation.reactive.configurers.AbstractServerConfigurer
import com.snapwise.security.bff.authorization.server.SessionAccessTokenWebFilter
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter
import org.springframework.security.web.server.context.ServerSecurityContextRepository
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher

class SessionAccessTokenSpec(private val configurer: AbstractServerConfigurer): AbstractBffServerSpec() {

    private var securityContextRepository: ServerSecurityContextRepository? = null

    private val authenticationConverter: ServerAuthenticationConverter? = null

    private var userSessionService: UserSessionService? = null

    override var requestMatcher: ServerWebExchangeMatcher = PathPatternParserServerWebExchangeMatcher("/bff/oauth2/session-access-token")
        private set

    /**
     * The [ServerSecurityContextRepository] used to save the
     * `Authentication`. Defaults to
     * [WebSessionServerSecurityContextRepository].
     * @param securityContextRepository the repository to use
     * @return the [SessionAccessTokenSpec] to continue configuring
     */
    fun securityContextRepository(securityContextRepository: ServerSecurityContextRepository): SessionAccessTokenSpec {
        this.securityContextRepository = securityContextRepository
        return this
    }

    /**
     * Sets the [matcher][ServerWebExchangeMatcher] used for determining if the
     * request is an authentication request.
     * @param requestMatcher the [matcher][ServerWebExchangeMatcher] used
     * for determining if the request is an authentication request
     * @return the [SessionAccessTokenSpec] for further configuration
     * @since 5.2
     */
    fun authenticationMatcher(requestMatcher: ServerWebExchangeMatcher): SessionAccessTokenSpec {
        this.requestMatcher = requestMatcher
        return this
    }

    /**
     * Sets the [UserSessionService] used to retrieve the access token linked
     * to a user session id.
     * @param userSessionService the [UserSessionService] used
     * for determining if the request is an authentication request
     * @return the [SessionAccessTokenSpec] for further configuration
     */
    fun withUserSessionService(userSessionService: UserSessionService): SessionAccessTokenSpec {
        this.userSessionService = userSessionService
        return this
    }

    override fun init(httpSecurity: ServerHttpSecurity) {
        val userSessionService  = this.userSessionService ?: return

        val sessionAccessTokenWebFilter = SessionAccessTokenWebFilter(userSessionService)

        val securityContextRepository = this.securityContextRepository
        if(securityContextRepository != null) {
            securityContextRepository(securityContextRepository)
        } else {
            securityContextRepository(WebSessionServerSecurityContextRepository())
        }


        httpSecurity.addFilterAt(sessionAccessTokenWebFilter, SecurityWebFiltersOrder.FIRST)
    }

    override fun configure(httpSecurity: ServerHttpSecurity) {
//            val clientRegistrationRepository: ReactiveClientRegistrationRepository = getClientRegistrationRepository()




    }

    /**
     * Allows method chaining to continue configuring the [ServerHttpSecurity]
     * @return the [ServerHttpSecurity] to continue configuring
     */
    fun and(): AbstractServerConfigurer {
        return configurer
    }
}