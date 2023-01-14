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

    private val specs: MutableMap<Class<out AbstractBffServerSpec>, AbstractBffServerSpec> = mutableMapOf()

    private var authenticationManager: ReactiveAuthenticationManager? = null

    private var sessionAccessToken: SessionAccessTokenSpec? = null

    private var sessionInfo: SessionInfoSpec? = null

    private var sessionEnd: SessionEndSpec? = null

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
    fun sessionInfo(customizer: Customizer<SessionInfoSpec>): CoreServerHttpSecurityConfigurer {
        if (this.sessionInfo == null) {
            this.sessionInfo = SessionInfoSpec(this)
        }
        customizer.customize(this.sessionInfo)
        return this
    }

    fun sessionEnd(customizer: Customizer<SessionEndSpec>): CoreServerHttpSecurityConfigurer {
        if (this.sessionEnd == null) {
            this.sessionEnd = SessionEndSpec(this)
        }
        customizer.customize(this.sessionEnd)
        return this
    }

    fun sessionAccessToken(customizer: Customizer<SessionAccessTokenSpec>): CoreServerHttpSecurityConfigurer {
        if (this.sessionAccessToken == null) {
           this.sessionAccessToken = SessionAccessTokenSpec(this)
        }

        customizer.customize(this.sessionAccessToken)
        specs[SessionAccessTokenSpec::class.java] =  this.sessionAccessToken!!

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

//    private fun createSpecs(): MutableMap<Class<out AbstractBffServerSpec>, AbstractBffServerSpec> {
//        val configurers: MutableMap<Class<out AbstractBffServerSpec>, AbstractBffServerSpec> = LinkedHashMap()
//
//        configurers[SessionAccessTokenSpec::class.java] = SessionAccessTokenSpec(this)
//        configurers[SessionInfoSpec::class.java] = SessionInfoSpec(this)
//        configurers[SessionEndSpec::class.java] = SessionEndSpec(this)
//
//        return configurers
//    }

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

        specs.values.forEach { configurer: AbstractBffServerSpec ->
            configurer.init(httpSecurity)
            requestMatchers.add(configurer.requestMatcher)
        }

        endpointsMatcher = OrServerWebExchangeMatcher(requestMatchers)

        return httpSecurity.build()
    }
}