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

package sample.config

import com.snapwise.security.bff.authorization.InMemoryUserSessionService
import com.snapwise.security.bff.authorization.JdbcUserSessionService
import com.snapwise.security.bff.authorization.UserSessionService
import com.snapwise.security.bff.authorization.config.annotation.web.configuration.BffAuthorizationConfiguration
import com.snapwise.security.bff.authorization.config.annotation.web.configurers.BffAuthorizationConfigurer
import com.snapwise.security.bff.authorization.settings.BffAuthorizationSettings
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.jdbc.core.JdbcOperations
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.SecurityFilterChain

@Configuration(proxyBeanMethods = false)
class BffAuthorizationConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    @Throws(Exception::class)
    fun bffAuthorizationSecurityFilterChain(
        http: HttpSecurity,
        bffAuthorizationSettings: BffAuthorizationSettings): SecurityFilterChain {
        BffAuthorizationConfiguration.applyDefaultSecurity(http)

        http.getConfigurer(BffAuthorizationConfigurer::class.java)

        return http.build()
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