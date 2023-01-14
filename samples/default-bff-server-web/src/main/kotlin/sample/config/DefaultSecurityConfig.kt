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

import com.snapwise.security.bff.authorization.web.oauth2.BffOAuth2AuthenticationToken
import org.slf4j.LoggerFactory
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.security.config.annotation.ObjectPostProcessor
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.UrlBasedCorsConfigurationSource
import org.springframework.web.filter.CorsFilter
import sample.authentication.SampleOAuth2AuthenticationSuccessHandler
import sample.oauth2.login.authorization.SampleHttpSessionOAuth2AuthorizationRequestRepository
import sample.oauth2.login.endpoint.SampleOAuth2AccessTokenResponseClient
import sample.services.OAuth2UserService

@EnableWebSecurity(debug = true)
@Configuration(proxyBeanMethods = false)
class DefaultSecurityConfig {

    private val logger = LoggerFactory.getLogger(javaClass)

    private fun createAuthenticationResult(authenticationResult: OAuth2LoginAuthenticationToken): BffOAuth2AuthenticationToken {

        logger.info("createAuthenticationResult -> $authenticationResult")

        return BffOAuth2AuthenticationToken(
            authenticationResult.principal, authenticationResult.authorities,
            authenticationResult.clientRegistration.registrationId
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
    fun defaultSecurityFilterChain(
        http: HttpSecurity,
        oAuth2UserService: OAuth2UserService,
        oAuth2AccessTokenResponseClient: SampleOAuth2AccessTokenResponseClient,
        httpSessionOAuth2AuthorizationRequestRepository: SampleHttpSessionOAuth2AuthorizationRequestRepository,
        oAuth2AuthenticationSuccessHandler: SampleOAuth2AuthenticationSuccessHandler,
    ): SecurityFilterChain {
        http.authorizeHttpRequests { authorize ->
            authorize
                .requestMatchers("/actuator/**").permitAll()
                .anyRequest().authenticated()
        }.oauth2Login { oAuth2LoginConfigurer ->
            oAuth2LoginConfigurer.authorizationEndpoint {
                it.authorizationRequestRepository(httpSessionOAuth2AuthorizationRequestRepository)
            }
            oAuth2LoginConfigurer.redirectionEndpoint {
                it.baseUri("/oauth2/callback/*")
            }
            oAuth2LoginConfigurer.userInfoEndpoint {
                it.userService(oAuth2UserService)
            }
            oAuth2LoginConfigurer.tokenEndpoint {
                it.accessTokenResponseClient(oAuth2AccessTokenResponseClient)
            }

            oAuth2LoginConfigurer.successHandler(oAuth2AuthenticationSuccessHandler)
            oAuth2LoginConfigurer.addObjectPostProcessor(object: ObjectPostProcessor<OAuth2LoginAuthenticationFilter> {
                override fun <O : OAuth2LoginAuthenticationFilter> postProcess(filter: O): O {
                    filter.setAuthenticationResultConverter(::createAuthenticationResult)
                    return filter
                }

            })
        }
        return http.build()
    }
}