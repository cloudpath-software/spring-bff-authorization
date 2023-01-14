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

import com.snapwise.security.bff.authorization.oauth2.client.endpoint.reactive.BffReactiveWebClientOAuth2AccessTokenResponseClient
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.DelegatingReactiveAuthenticationManager
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.oauth2.client.authentication.OAuth2LoginReactiveAuthenticationManager
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeReactiveAuthenticationManager
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.AuthenticationWebFilter
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher
import org.springframework.web.reactive.config.WebFluxConfigurer
import sample.authentication.SampleOAuth2AuthenticationSuccessHandler
import sample.oauth2.login.authorization.SampleHttpSessionOAuth2AuthorizationRequestRepository
import sample.oauth2.login.endpoint.SampleOAuth2AccessTokenResponseClient
import sample.services.oauth2.OAuth2UserService
import sample.services.oauth2.ReactiveOAuth2UserService

@EnableWebFluxSecurity
@Configuration(proxyBeanMethods = false)
class DefaultSecurityConfig: WebFluxConfigurer {

    @Bean
    fun reactiveOAuth2AccessTokenResponseClient(): ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {
        return BffReactiveWebClientOAuth2AccessTokenResponseClient()
    }

    /**
     * Required do to an unexpected behaviour within the [AuthenticationWebFilter] defined by
     * the spring webflux oauth2 login security logic. Since the [OidcAuthorizationCodeReactiveAuthenticationManager]
     * returns without data due to the oidc scope not being present within the token exchange request,
     * the switchIfEmpty within [AuthenticationWebFilter] is called which throws an error.
     */
    @Bean
    fun oauth2LoginReactiveAuthenticationManager(
        client: ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>,
        oAuth2UserService: ReactiveOAuth2UserService
    ): ReactiveAuthenticationManager {
        val oauth2Manager = OAuth2LoginReactiveAuthenticationManager(client,oAuth2UserService)
        return DelegatingReactiveAuthenticationManager(oauth2Manager)
    }

    @Bean
    @Throws(Exception::class)
    fun defaultSecurityFilterChain(
        http: ServerHttpSecurity,
        oAuth2UserService: OAuth2UserService,
        reactiveAuthenticationManager: ReactiveAuthenticationManager,
        oAuth2AccessTokenResponseClient: SampleOAuth2AccessTokenResponseClient,
        httpSessionOAuth2AuthorizationRequestRepository: SampleHttpSessionOAuth2AuthorizationRequestRepository,
        oAuth2AuthenticationSuccessHandler: SampleOAuth2AuthenticationSuccessHandler,
    ): SecurityWebFilterChain {
        http
            .logout().disable()
            .anonymous().disable()
            .csrf().disable()
            .authorizeExchange { authorize ->
                authorize
//                    .pathMatchers("/actuator/**").permitAll()
                    .pathMatchers("/sample-webflux/**").permitAll()
                    .anyExchange().authenticated()
            }
            .oauth2Login { oAuth2LoginConfigurer ->
                oAuth2LoginConfigurer.authenticationMatcher(PathPatternParserServerWebExchangeMatcher("/oauth2/callback/{registrationId}"))
                oAuth2LoginConfigurer.authenticationManager(reactiveAuthenticationManager)
                oAuth2LoginConfigurer.authenticationSuccessHandler(oAuth2AuthenticationSuccessHandler)
            }

        return http.build()
    }
}