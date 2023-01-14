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

package com.snapwise.bffauthorizationspa.annotation.reactive.configuration

import com.snapwise.security.bff.authorization.config.annotation.reactive.configurers.CoreServerHttpSecurityConfigurer
import org.springframework.context.annotation.Configuration
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
open class SpaServerHttpSecurityConfiguration {

    companion object {
        @Throws(Exception::class)
        fun applyDefaultSecurity(http: ServerHttpSecurity): SpaServerHttpSecurityConfigurer {
            val serverHttpSecurityConfigurer = SpaServerHttpSecurityConfigurer(http)

            val endpointsMatcher: ServerWebExchangeMatcher = serverHttpSecurityConfigurer
                .getEndpointsMatcher()

            http.logout().disable()
                .anonymous().disable()
                .csrf().disable()
                .cors().disable()
                .securityMatcher(endpointsMatcher)

            return serverHttpSecurityConfigurer
        }
    }
}