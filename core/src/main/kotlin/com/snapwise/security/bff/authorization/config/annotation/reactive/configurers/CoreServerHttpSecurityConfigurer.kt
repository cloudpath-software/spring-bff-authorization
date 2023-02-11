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

package com.snapwise.security.bff.authorization.config.annotation.reactive.configurers

import com.snapwise.security.bff.authorization.config.annotation.reactive.specs.AbstractBffServerSpec
import com.snapwise.security.bff.authorization.config.annotation.reactive.specs.SessionAccessTokenSpec
import com.snapwise.security.bff.authorization.config.annotation.reactive.specs.SessionEndSpec
import com.snapwise.security.bff.authorization.config.annotation.reactive.specs.SessionInfoSpec
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.config.Customizer
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.util.matcher.OrServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher
import org.springframework.security.web.util.matcher.RequestMatcher

open class CoreServerHttpSecurityConfigurer(private val httpSecurity: ServerHttpSecurity): AbstractServerConfigurer() {
    private var endpointsMatcher: ServerWebExchangeMatcher? = null

    private var authenticationManager: ReactiveAuthenticationManager? = null

    private var sessionAccessTokenSpec: SessionAccessTokenSpec? = null

    private var sessionInfoSpec: SessionInfoSpec? = null

    private var sessionEndSpec: SessionEndSpec? = null

    /**
     * Returns a [RequestMatcher] for the authorization server endpoints.
     *
     * @return a [RequestMatcher] for the authorization server endpoints
     */
    fun getEndpointsMatcher(): ServerWebExchangeMatcher {
        return ServerWebExchangeMatcher { request ->
            endpointsMatcher?.matches(request)
        }
    }

    /**
     * Configures the bff session info.
     * @param customizer the [Customizer] to provide more options for the
     * [SessionInfoSpec]
     * @return the [CoreServerHttpSecurityConfigurer] to customize
     */
    fun sessionInfo(customizer: Customizer<SessionInfoSpec>? = null): CoreServerHttpSecurityConfigurer {
        if (this.sessionInfoSpec == null) {
            this.sessionInfoSpec = SessionInfoSpec(this)
        }
        customizer?.customize(this.sessionInfoSpec)
        return this
    }

    fun sessionEnd(customizer: Customizer<SessionEndSpec>): CoreServerHttpSecurityConfigurer {
        if (this.sessionEndSpec == null) {
            this.sessionEndSpec = SessionEndSpec(this)
        }
        customizer.customize(this.sessionEndSpec)
        return this
    }

    fun sessionAccessToken(customizer: Customizer<SessionAccessTokenSpec>): CoreServerHttpSecurityConfigurer {
        if (this.sessionAccessTokenSpec == null) {
           this.sessionAccessTokenSpec = SessionAccessTokenSpec(this)
        }
        customizer.customize(this.sessionAccessTokenSpec)
        return this
    }

    /**
     * Configure the default authentication manager.
     * @param manager the authentication manager to use
     * @return the [CoreServerHttpSecurityConfigurer] to customize
     */
    fun authenticationManager(manager: ReactiveAuthenticationManager?): CoreServerHttpSecurityConfigurer {
        this.authenticationManager = manager
        return this
    }

    private fun getSpecs(): MutableMap<Class<out AbstractBffServerSpec>, AbstractBffServerSpec> {
        val configurers: MutableMap<Class<out AbstractBffServerSpec>, AbstractBffServerSpec> = LinkedHashMap()

        val sessionAccessTokenSpec = this.sessionAccessTokenSpec
        if(sessionAccessTokenSpec != null) {
            configurers[SessionAccessTokenSpec::class.java] = sessionAccessTokenSpec
        }

        val sessionInfoSpec = this.sessionInfoSpec
        if(sessionInfoSpec != null) {
            configurers[SessionInfoSpec::class.java] = sessionInfoSpec
        }

        val sessionEndSpec = this.sessionEndSpec
        if(sessionEndSpec != null) {
            configurers[SessionEndSpec::class.java] = sessionEndSpec
        }

        return configurers
    }

    /**
     * Creates a new instance.
     * @return the new [CoreServerHttpSecurityConfigurer] instance
     */
    open fun http(): CoreServerHttpSecurityConfigurer {
        return CoreServerHttpSecurityConfigurer(httpSecurity)
    }

    /**
     * Allows method chaining to continue configuring the [CoreServerHttpSecurityConfigurer]
     * @return the [CoreServerHttpSecurityConfigurer] to continue configuring
     */
    fun and(): CoreServerHttpSecurityConfigurer {
        return this
    }

    /**
     * Builds the [SecurityWebFilterChain]
     * @return the [SecurityWebFilterChain]
     */
    open fun build(): SecurityWebFilterChain {
        val requestMatchers: MutableList<ServerWebExchangeMatcher> = mutableListOf()

        val specs = getSpecs()
        specs.values.forEach { configurer: AbstractBffServerSpec ->
            configurer.init(httpSecurity)
            requestMatchers.add(configurer.requestMatcher)
        }

        endpointsMatcher = OrServerWebExchangeMatcher(requestMatchers)

        return httpSecurity.build()
    }
}