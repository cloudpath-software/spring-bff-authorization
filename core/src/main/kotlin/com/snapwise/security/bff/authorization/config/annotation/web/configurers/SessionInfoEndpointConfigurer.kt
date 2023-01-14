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
import com.snapwise.security.bff.authorization.SessionInfoEndpointFilter
import com.snapwise.security.bff.authorization.UserSessionService
import com.snapwise.security.bff.authorization.authentication.UserSessionAuthenticationProvider
import com.snapwise.security.bff.authorization.web.authentication.UserSessionAuthenticationConverter
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
class SessionInfoEndpointConfigurer
/**
 * Restrict for internal use only.
 */
internal constructor(objectPostProcessor: ObjectPostProcessor<Any>) : AbstractBffConfigurer(objectPostProcessor) {
    override lateinit var requestMatcher: RequestMatcher
        private set
    private val accessTokenRequestConverters: MutableList<AuthenticationConverter> = mutableListOf()
    private var accessTokenRequestConvertersConsumer: Consumer<List<AuthenticationConverter>> =
        Consumer<List<AuthenticationConverter>> { accessTokenRequestConverters: List<AuthenticationConverter>? -> }
    private val authenticationProviders: MutableList<AuthenticationProvider> = mutableListOf()
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
    fun accessTokenRequestConverter(accessTokenRequestConverter: AuthenticationConverter): SessionInfoEndpointConfigurer {
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
    ): SessionInfoEndpointConfigurer {
        this.accessTokenRequestConvertersConsumer = accessTokenRequestConvertersConsumer
        return this
    }

    /**
     * Adds an [AuthenticationProvider] used for authenticating a type of [OAuth2AuthorizationGrantAuthenticationToken].
     *
     * @param authenticationProvider an [AuthenticationProvider] used for authenticating a type of [OAuth2AuthorizationGrantAuthenticationToken]
     * @return the [OAuth2TokenEndpointConfigurer] for further configuration
     */
    fun authenticationProvider(authenticationProvider: AuthenticationProvider): SessionInfoEndpointConfigurer {
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
    ): SessionInfoEndpointConfigurer {
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
    fun accessTokenResponseHandler(accessTokenResponseHandler: AuthenticationSuccessHandler): SessionInfoEndpointConfigurer {
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
    fun errorResponseHandler(errorResponseHandler: AuthenticationFailureHandler): SessionInfoEndpointConfigurer {
        this.errorResponseHandler = errorResponseHandler
        return this
    }

    override fun init(httpSecurity: HttpSecurity) {
        val authorizationServerSettings: BffAuthorizationSettings =
            BffAuthorizationConfigurerUtils.getAuthorizationSettings(httpSecurity)
        requestMatcher = AntPathRequestMatcher(
            authorizationServerSettings.sessionInfoEndpoint, HttpMethod.GET.name()
        )
        val authenticationProviders: MutableList<AuthenticationProvider> =
            createDefaultAuthenticationProviders(httpSecurity)
        if (this.authenticationProviders.isNotEmpty()) {
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
        val authorizationServerSettings: BffAuthorizationSettings =
            BffAuthorizationConfigurerUtils.getAuthorizationSettings(httpSecurity)
        val sessionInfoEndpointFilter = SessionInfoEndpointFilter(
            authenticationManager,
            authorizationServerSettings.sessionInfoEndpoint
        )
        val authenticationConverters: MutableList<AuthenticationConverter> = createDefaultAuthenticationConverters()
        if (accessTokenRequestConverters.isNotEmpty()) {
            authenticationConverters.addAll(0, accessTokenRequestConverters)
        }
        accessTokenRequestConvertersConsumer.accept(authenticationConverters)
//        tokenEndpointFilter.setAuthenticationConverter(
//            DelegatingAuthenticationConverter(authenticationConverters)
//        )
        if (accessTokenResponseHandler != null) {
            sessionInfoEndpointFilter.setAuthenticationSuccessHandler(accessTokenResponseHandler!!)
        }
        if (errorResponseHandler != null) {
            sessionInfoEndpointFilter.setAuthenticationFailureHandler(errorResponseHandler!!)
        }
        httpSecurity.addFilterBefore(postProcess(sessionInfoEndpointFilter), AuthorizationFilter::class.java)
    }

    companion object {
        private fun createDefaultAuthenticationConverters(): MutableList<AuthenticationConverter> {
            val authenticationConverters: MutableList<AuthenticationConverter> = mutableListOf()
            authenticationConverters.add(UserSessionAuthenticationConverter())
            return authenticationConverters
        }

        private fun createDefaultAuthenticationProviders(httpSecurity: HttpSecurity): MutableList<AuthenticationProvider> {
            val authenticationProviders: MutableList<AuthenticationProvider> = mutableListOf()
            val userSessionService: UserSessionService = BffAuthorizationConfigurerUtils.getUserSessionService(httpSecurity)
            val userSessionAuthenticationProvider = UserSessionAuthenticationProvider(userSessionService)
            authenticationProviders.add(userSessionAuthenticationProvider)
            return authenticationProviders
        }
    }
}