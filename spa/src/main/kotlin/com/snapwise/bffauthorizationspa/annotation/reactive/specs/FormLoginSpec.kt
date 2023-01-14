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

package com.snapwise.bffauthorizationspa.annotation.reactive.specs

import com.snapwise.security.bff.authorization.config.annotation.reactive.configurers.AbstractServerConfigurer
import com.snapwise.security.bff.authorization.config.annotation.reactive.specs.AbstractBffServerSpec
import com.snapwise.bffauthorizationspa.web.server.FormLoginWebFilter
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter
import org.springframework.security.web.server.context.ServerSecurityContextRepository
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher

class FormLoginSpec(private val configurer: AbstractServerConfigurer): AbstractBffServerSpec() {

    private var securityContextRepository: ServerSecurityContextRepository? = null
    private val authenticationConverter: ServerAuthenticationConverter? = null
    override var requestMatcher: ServerWebExchangeMatcher = PathPatternParserServerWebExchangeMatcher("/bff/authentication/login")
        private set

    /**
     * The [ServerSecurityContextRepository] used to save the
     * `Authentication`. Defaults to
     * [WebSessionServerSecurityContextRepository].
     * @param securityContextRepository the repository to use
     * @return the [FormLoginSpec] to continue configuring
     */
    fun securityContextRepository(securityContextRepository: ServerSecurityContextRepository): FormLoginSpec {
        this.securityContextRepository = securityContextRepository
        return this
    }

    /**
     * Sets the [matcher][ServerWebExchangeMatcher] used for determining if the
     * request is an authentication request.
     * @param requestMatcher the [matcher][ServerWebExchangeMatcher] used
     * for determining if the request is an authentication request
     * @return the [FormLoginSpec] for further configuration
     * @since 5.2
     */
    fun authenticationMatcher(requestMatcher: ServerWebExchangeMatcher): FormLoginSpec {
        this.requestMatcher = requestMatcher
        return this
    }

    override fun init(httpSecurity: ServerHttpSecurity) {
        val formLoginWebFilter = FormLoginWebFilter()

        val securityContextRepository = this.securityContextRepository
        if(securityContextRepository != null) {
            securityContextRepository(securityContextRepository)
        } else {
            securityContextRepository(WebSessionServerSecurityContextRepository())
        }

        httpSecurity.addFilterAt(formLoginWebFilter, SecurityWebFiltersOrder.LAST)
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