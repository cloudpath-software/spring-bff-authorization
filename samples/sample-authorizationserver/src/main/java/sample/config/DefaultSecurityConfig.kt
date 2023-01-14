/*
 * Copyright 2020-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.config

import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Profile
import org.springframework.core.Ordered
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.UrlBasedCorsConfigurationSource
import org.springframework.web.filter.CorsFilter

@EnableWebSecurity(debug = true)
@Configuration(proxyBeanMethods = false)
class DefaultSecurityConfig {

    companion object {
        val ALLOWED_ORIGINS = listOf(
            "http://localhost:3004"
        )
    }

    @Bean
    fun corsFilterRegistrationBean(): FilterRegistrationBean<*> {
        val source = UrlBasedCorsConfigurationSource()

        val publicConfig = CorsConfiguration()
        publicConfig.applyPermitDefaultValues()
        publicConfig.allowCredentials = false
        publicConfig.allowedOrigins = listOf("*")
        publicConfig.allowedHeaders = listOf("*")
        publicConfig.allowedMethods = listOf("*")
        publicConfig.exposedHeaders = listOf("content-length")
        publicConfig.maxAge = 3600L

        source.registerCorsConfiguration("/**", publicConfig)

        val bean: FilterRegistrationBean<*> = FilterRegistrationBean(CorsFilter(source))
        bean.order = Ordered.HIGHEST_PRECEDENCE
        return bean
    }


    @Bean
    @Throws(Exception::class)
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeHttpRequests { authorize ->
                authorize.anyRequest().authenticated()
            }
            .formLogin(Customizer.withDefaults())
        return http.build()
    }

    // @formatter:on
    // @formatter:off
    @Bean
    fun users(): UserDetailsService {
        val user = User.withDefaultPasswordEncoder()
            .username("user")
            .password("password")
            .roles("USER")
            .build()
        return InMemoryUserDetailsManager(user)
    } // @formatter:on
}