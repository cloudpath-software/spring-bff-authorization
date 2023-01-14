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

package com.snapwise.security.bff.authorization.config.annotation.web.configuration

import com.snapwise.security.bff.authorization.config.annotation.web.configurers.BffAuthorizationConfigurer
import com.snapwise.security.bff.authorization.settings.BffAuthorizationSettings
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.util.matcher.RequestMatcher
import java.util.*


/**
 * [Configuration] for bff authorization support.
 *
 * @since 0.0.1
 * @see BffAuthorizationConfigurer
 */
@Configuration(proxyBeanMethods = false)
open class BffAuthorizationConfiguration {
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    @Throws(Exception::class)
    open fun bffAuthorizationSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        applyDefaultSecurity(http)
        return http.build()
    }

    @Bean
    open fun registerMissingBeanPostProcessor(): RegisterMissingBeanPostProcessor {
        val postProcessor = RegisterMissingBeanPostProcessor()
        postProcessor.addBeanDefinition(BffAuthorizationSettings::class.java) {
            BffAuthorizationSettings.builder().build()
        }
        return postProcessor
    }

    companion object {

        @Throws(Exception::class)
        fun applyDefaultSecurity(http: HttpSecurity) {
            val bffAuthorizationConfigurer = BffAuthorizationConfigurer()
            val endpointsMatcher: RequestMatcher = bffAuthorizationConfigurer
                .getEndpointsMatcher()
            http
                .securityMatcher(endpointsMatcher)
                .authorizeHttpRequests { authorize -> authorize.anyRequest().authenticated() }
                .csrf { csrf -> csrf.ignoringRequestMatchers(endpointsMatcher) }
                .apply(bffAuthorizationConfigurer)
        }
    }
}