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

package sample.config.security

import com.snapwise.bffauthorizationspa.annotation.reactive.configuration.SpaServerHttpSecurityConfiguration
import com.snapwise.security.bff.authorization.JdbcUserSessionService
import com.snapwise.security.bff.authorization.UserSessionService
import com.snapwise.security.bff.authorization.settings.BffAuthorizationSettings
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.jdbc.core.JdbcOperations
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.server.SecurityWebFilterChain

@Configuration(proxyBeanMethods = false)
class BffAuthorizationConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    fun bffHttpSecurity(
        http: ServerHttpSecurity,
        userSessionService: UserSessionService
    ): SecurityWebFilterChain {
        return SpaServerHttpSecurityConfiguration.applyDefaultSecurity(http)
            .sessionAccessToken {
                it.withUserSessionService(userSessionService)
            }
            .sessionInfo {
                it.withUserSessionService(userSessionService)
            }
            .build()
    }

    @Bean
    fun userSessionService(jdbcOperations: JdbcOperations): UserSessionService {
        return JdbcUserSessionService(jdbcOperations)
    }

    @Bean
    fun bffAuthorizationSettings(): BffAuthorizationSettings {
        return BffAuthorizationSettings.builder()
            .build()
    }
}