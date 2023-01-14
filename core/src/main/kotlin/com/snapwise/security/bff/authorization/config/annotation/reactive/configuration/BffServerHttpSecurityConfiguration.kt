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

package com.snapwise.security.bff.authorization.config.annotation.reactive.configuration

import com.snapwise.security.bff.authorization.config.annotation.reactive.configurers.CoreServerHttpSecurityConfigurer
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher
import java.util.*


/**
 * [Configuration] for bff authorization support.
 *
 * @since 0.0.1
 * @see CoreServerHttpSecurityConfigurer
 */
@Configuration(proxyBeanMethods = false)
open class BffServerHttpSecurityConfiguration {

    private val authenticationManager: ReactiveAuthenticationManager? = null

//    @Bean(BFF_HTTPSECURITY_BEAN_NAME)
//    @Scope("prototype")
//    open fun bffHttpSecurity(): BffServerHttpSecurityConfigurer {
//        val http = ContextAwareServerHttpSecurityConfigurer()
//        return http.authenticationManager(authenticationManager())
//            .sessionInfo()
//            .and()
//    }

    private fun authenticationManager(): ReactiveAuthenticationManager? {
        if (authenticationManager != null) {
            return authenticationManager
        }
        return null
    }

    companion object {
        private const val BEAN_NAME_PREFIX =
            "com.snapwise.security.bff.authorization.config.annotation.reactive.configuration.BffHttpSecurityConfiguration."

        private const val BFF_HTTPSECURITY_BEAN_NAME = BEAN_NAME_PREFIX + "bffHttpSecurity"

        @Throws(Exception::class)
        fun applyDefaultSecurity(http: ServerHttpSecurity) {
            val bffAuthorizationConfigurer = CoreServerHttpSecurityConfigurer(http)
            val endpointsMatcher: ServerWebExchangeMatcher = bffAuthorizationConfigurer
                .getEndpointsMatcher()

            http.logout().disable()
                .anonymous().disable()
                .csrf().disable()
                .securityMatcher(endpointsMatcher)
        }
    }
}