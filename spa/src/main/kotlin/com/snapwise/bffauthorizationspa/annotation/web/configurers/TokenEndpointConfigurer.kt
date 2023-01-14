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
package com.snapwise.security.bff.authorization.config.annotation.web.configurers

import com.snapwise.security.bff.authorization.settings.BffAuthorizationSettings
import com.snapwise.security.bff.authorization.TokenEndpointFilter
import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.HttpMethod
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.config.annotation.ObjectPostProcessor
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.authentication.AuthenticationConverter
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher
import org.springframework.security.web.access.intercept.AuthorizationFilter
import java.util.function.Consumer

/**
 * Configurer for the Login Endpoint.
 *
 * @since 0.0.1
 * @see OAuth2AuthorizationServerConfigurer.tokenEndpoint
 *
 * @see OAuth2TokenEndpointFilter
 */
class TokenEndpointConfigurer
/**
 * Restrict for internal use only.
 */
internal constructor(objectPostProcessor: ObjectPostProcessor<Any>) : AbstractBffConfigurer(objectPostProcessor) {
    override lateinit var requestMatcher: RequestMatcher
        private set
    private val accessTokenRequestConverters: MutableList<AuthenticationConverter> =
        ArrayList<AuthenticationConverter>()
    private var accessTokenRequestConvertersConsumer: Consumer<List<AuthenticationConverter>> =
        Consumer<List<AuthenticationConverter>> { accessTokenRequestConverters: List<AuthenticationConverter>? -> }
    private val authenticationProviders: MutableList<AuthenticationProvider> = ArrayList<AuthenticationProvider>()
    private var authenticationProvidersConsumer: Consumer<List<AuthenticationProvider>> =
        Consumer<List<AuthenticationProvider>> { authenticationProviders: List<AuthenticationProvider>? -> }
    private var accessTokenResponseHandler: AuthenticationSuccessHandler? = null
    private var errorResponseHandler: AuthenticationFailureHandler? = null

    /**
     * Adds an [AuthenticationConverter] used when attempting to extract an Access Token Request from [HttpServletRequest]
     * to an instance of [OAuth2AuthorizationGrantAuthenticationToken] used for authenticating the authorization grant.
     *
     * @param accessTokenRequestConverter an [AuthenticationConverter] used when attempting to extract an Access Token Request from [HttpServletRequest]
     * @return the [OAuth2TokenEndpointConfigurer] for further configuration
     */
    fun accessTokenRequestConverter(accessTokenRequestConverter: AuthenticationConverter): TokenEndpointConfigurer {
        accessTokenRequestConverters.add(accessTokenRequestConverter)
        return this
    }

    /**
     * Sets the `Consumer` providing access to the `List` of default
     * and (optionally) added [AuthenticationConverter][.accessTokenRequestConverter]'s
     * allowing the ability to add, remove, or customize a specific [AuthenticationConverter].
     *
     * @param accessTokenRequestConvertersConsumer the `Consumer` providing access to the `List` of default and (optionally) added [AuthenticationConverter]'s
     * @return the [OAuth2TokenEndpointConfigurer] for further configuration
     * @since 0.4.0
     */
    fun accessTokenRequestConverters(
        accessTokenRequestConvertersConsumer: Consumer<List<AuthenticationConverter>>
    ): TokenEndpointConfigurer {
        this.accessTokenRequestConvertersConsumer = accessTokenRequestConvertersConsumer
        return this
    }

    /**
     * Adds an [AuthenticationProvider] used for authenticating a type of [OAuth2AuthorizationGrantAuthenticationToken].
     *
     * @param authenticationProvider an [AuthenticationProvider] used for authenticating a type of [OAuth2AuthorizationGrantAuthenticationToken]
     * @return the [OAuth2TokenEndpointConfigurer] for further configuration
     */
    fun authenticationProvider(authenticationProvider: AuthenticationProvider): TokenEndpointConfigurer {
        authenticationProviders.add(authenticationProvider)
        return this
    }

    /**
     * Sets the `Consumer` providing access to the `List` of default
     * and (optionally) added [AuthenticationProvider][.authenticationProvider]'s
     * allowing the ability to add, remove, or customize a specific [AuthenticationProvider].
     *
     * @param authenticationProvidersConsumer the `Consumer` providing access to the `List` of default and (optionally) added [AuthenticationProvider]'s
     * @return the [OAuth2TokenEndpointConfigurer] for further configuration
     * @since 0.4.0
     */
    fun authenticationProviders(
        authenticationProvidersConsumer: Consumer<List<AuthenticationProvider>>
    ): TokenEndpointConfigurer {
        this.authenticationProvidersConsumer = authenticationProvidersConsumer
        return this
    }

    /**
     * Sets the [AuthenticationSuccessHandler] used for handling an [OAuth2AccessTokenAuthenticationToken]
     * and returning the [Access Token Response][OAuth2AccessTokenResponse].
     *
     * @param accessTokenResponseHandler the [AuthenticationSuccessHandler] used for handling an [OAuth2AccessTokenAuthenticationToken]
     * @return the [OAuth2TokenEndpointConfigurer] for further configuration
     */
    fun accessTokenResponseHandler(accessTokenResponseHandler: AuthenticationSuccessHandler): TokenEndpointConfigurer {
        this.accessTokenResponseHandler = accessTokenResponseHandler
        return this
    }

    /**
     * Sets the [AuthenticationFailureHandler] used for handling an [OAuth2AuthenticationException]
     * and returning the [Error Response][OAuth2Error].
     *
     * @param errorResponseHandler the [AuthenticationFailureHandler] used for handling an [OAuth2AuthenticationException]
     * @return the [OAuth2TokenEndpointConfigurer] for further configuration
     */
    fun errorResponseHandler(errorResponseHandler: AuthenticationFailureHandler): TokenEndpointConfigurer {
        this.errorResponseHandler = errorResponseHandler
        return this
    }

    override fun init(httpSecurity: HttpSecurity) {
        val authorizationServerSettings: BffAuthorizationSettings =
            BffAuthorizationConfigurerUtils.getAuthorizationSettings(httpSecurity)
        requestMatcher = AntPathRequestMatcher(
            authorizationServerSettings.tokenEndpoint, HttpMethod.POST.name()
        )
        val authenticationProviders: MutableList<AuthenticationProvider> =
            createDefaultAuthenticationProviders(httpSecurity)
        if (!this.authenticationProviders.isEmpty()) {
            authenticationProviders.addAll(0, this.authenticationProviders)
        }
        authenticationProvidersConsumer.accept(authenticationProviders)
        authenticationProviders.forEach(Consumer { authenticationProvider: AuthenticationProvider? ->
            httpSecurity.authenticationProvider(
                postProcess(authenticationProvider)
            )
        })
    }

    override fun configure(httpSecurity: HttpSecurity) {
        val authenticationManager: AuthenticationManager =
            httpSecurity.getSharedObject(AuthenticationManager::class.java)
        val bffAuthorizationSettings: BffAuthorizationSettings =
            BffAuthorizationConfigurerUtils.getAuthorizationSettings(httpSecurity)
        val tokenEndpointFilter = TokenEndpointFilter(
            authenticationManager,
            bffAuthorizationSettings.tokenEndpoint
        )
        val authenticationConverters: MutableList<AuthenticationConverter> = createDefaultAuthenticationConverters()
        if (!accessTokenRequestConverters.isEmpty()) {
            authenticationConverters.addAll(0, accessTokenRequestConverters)
        }
        accessTokenRequestConvertersConsumer.accept(authenticationConverters)
//        tokenEndpointFilter.setAuthenticationConverter(
//            DelegatingAuthenticationConverter(authenticationConverters)
//        )
        if (accessTokenResponseHandler != null) {
            tokenEndpointFilter.setAuthenticationSuccessHandler(accessTokenResponseHandler!!)
        }
        if (errorResponseHandler != null) {
            tokenEndpointFilter.setAuthenticationFailureHandler(errorResponseHandler!!)
        }
        httpSecurity.addFilterAfter(postProcess(tokenEndpointFilter), AuthorizationFilter::class.java)
    }

    companion object {
        private fun createDefaultAuthenticationConverters(): MutableList<AuthenticationConverter> {
            val authenticationConverters: MutableList<AuthenticationConverter> = ArrayList<AuthenticationConverter>()
//            authenticationConverters.add(OAuth2AuthorizationCodeAuthenticationConverter())
//            authenticationConverters.add(OAuth2RefreshTokenAuthenticationConverter())
//            authenticationConverters.add(OAuth2ClientCredentialsAuthenticationConverter())
            return authenticationConverters
        }

        private fun createDefaultAuthenticationProviders(httpSecurity: HttpSecurity): MutableList<AuthenticationProvider> {
            val authenticationProviders: MutableList<AuthenticationProvider> = ArrayList<AuthenticationProvider>()
//            val authorizationService: OAuth2AuthorizationService =
//                OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity)
//            val tokenGenerator: OAuth2TokenGenerator<out OAuth2Token?> =
//                OAuth2ConfigurerUtils.getTokenGenerator(httpSecurity)
//            val authorizationCodeAuthenticationProvider =
//                OAuth2AuthorizationCodeAuthenticationProvider(authorizationService, tokenGenerator)
//            authenticationProviders.add(authorizationCodeAuthenticationProvider)
//            val refreshTokenAuthenticationProvider =
//                OAuth2RefreshTokenAuthenticationProvider(authorizationService, tokenGenerator)
//            authenticationProviders.add(refreshTokenAuthenticationProvider)
//            val clientCredentialsAuthenticationProvider =
//                OAuth2ClientCredentialsAuthenticationProvider(authorizationService, tokenGenerator)
//            authenticationProviders.add(clientCredentialsAuthenticationProvider)
            return authenticationProviders
        }
    }
}