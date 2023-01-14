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

import com.snapwise.security.bff.authorization.TokenService
import com.snapwise.security.bff.authorization.settings.BffAuthorizationSettings
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.ObjectPostProcessor
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2ClientAuthenticationConfigurer
import org.springframework.security.web.util.matcher.OrRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher
import java.util.function.Consumer

/**
 *
 *  https://datatracker.ietf.org/doc/html/draft-bertocci-oauth2-tmi-bff-01
 *
 * An [AbstractHttpConfigurer] for OAuth 2.0 Authorization Server support.
 *
 * @since 0.0.1
 * @see AbstractHttpConfigurer
 *
 * @see OAuth2ClientAuthenticationConfigurer
 *
 * @see OAuth2AuthorizationServerMetadataEndpointConfigurer
 *
 * @see OAuth2AuthorizationEndpointConfigurer
 *
 * @see OAuth2TokenEndpointConfigurer
 *
 * @see OAuth2TokenIntrospectionEndpointConfigurer
 *
 * @see OAuth2TokenRevocationEndpointConfigurer
 *
 * @see OidcConfigurer
 *
 * @see RegisteredClientRepository
 *
 * @see OAuth2AuthorizationService
 *
 * @see OAuth2AuthorizationConsentService
 *
 * @see NimbusJwkSetEndpointFilter
 */
class BffAuthorizationConfigurer : AbstractHttpConfigurer<BffAuthorizationConfigurer, HttpSecurity>() {
    private val configurers: MutableMap<Class<out AbstractBffConfigurer>, AbstractBffConfigurer> =
        createConfigurers()
    private var endpointsMatcher: RequestMatcher? = null

    /**
     * Sets the repository of registered clients.
     *
     * @param registeredClientRepository the repository of registered clients
     * @return the [BffAuthorizationConfigurer] for further configuration
     */
//    fun registeredClientRepository(registeredClientRepository: RegisteredClientRepository): BffAuthorizationConfigurer {
//        getBuilder().setSharedObject(RegisteredClientRepository::class.java, registeredClientRepository)
//        return this
//    }

    /**
     * Sets the authorization service.
     *
     * @param authorizationService the authorization service
     * @return the [BffAuthorizationConfigurer] for further configuration
     */
//    fun authorizationService(authorizationService: OAuth2AuthorizationService?): BffAuthorizationConfigurer {
//        Assert.notNull(authorizationService, "authorizationService cannot be null")
//        getBuilder().setSharedObject(OAuth2AuthorizationService::class.java, authorizationService)
//        return this
//    }

    /**
     * Sets the authorization consent service.
     *
     * @param authorizationConsentService the authorization consent service
     * @return the [BffAuthorizationConfigurer] for further configuration
     */
    fun loginService(loginService: TokenService): BffAuthorizationConfigurer {
        builder.setSharedObject(TokenService::class.java, loginService)
        return this
    }

    /**
     * Sets the authorization settings.
     *
     * @param authorizationSettings the authorization server settings
     * @return the [BffAuthorizationConfigurer] for further configuration
     */
    fun authorizationSettings(authorizationSettings: BffAuthorizationSettings): BffAuthorizationConfigurer {
        builder.setSharedObject(BffAuthorizationSettings::class.java, authorizationSettings)
        return this
    }

    /**
     * Configures the bff login endpoint.
     *
     * @param loginEndpointCustomizer the [Customizer] providing access to the [TokenEndpointConfigurer]
     * @return the [BffAuthorizationConfigurer] for further configuration
     */
    fun tokenEndpoint(loginEndpointCustomizer: Customizer<TokenEndpointConfigurer>): BffAuthorizationConfigurer {
        loginEndpointCustomizer.customize(getConfigurer(TokenEndpointConfigurer::class.java))
        return this
    }

    /**
     * Configures the bff logout endpoint.
     *
     * @param sessionEndEndpointConfigurer the [Customizer] providing access to the [LogoutEndpointConfigurer]
     * @return the [BffAuthorizationConfigurer] for further configuration
     */
    fun sessionEndEndpoint(sessionEndEndpointConfigurer: Customizer<SessionEndEndpointConfigurer>): BffAuthorizationConfigurer {
        sessionEndEndpointConfigurer.customize(getConfigurer(SessionEndEndpointConfigurer::class.java))
        return this
    }

    /**
     * Configures the bff session information endpoint.
     *
     * @param sessionInfoEndpointCustomizer the [Customizer] providing access to the [SessionInfoEndpointConfigurer]
     * @return the [BffAuthorizationConfigurer] for further configuration
     * @since 0.2.3
     */
    fun sessionInfoEndpoint(sessionInfoEndpointCustomizer: Customizer<SessionInfoEndpointConfigurer>): BffAuthorizationConfigurer {
        sessionInfoEndpointCustomizer.customize(getConfigurer(SessionInfoEndpointConfigurer::class.java))
        return this
    }

    /**
     * Returns a [RequestMatcher] for the authorization server endpoints.
     *
     * @return a [RequestMatcher] for the authorization server endpoints
     */
    fun getEndpointsMatcher(): RequestMatcher {
        // Return a deferred RequestMatcher
        // since endpointsMatcher is constructed in init(HttpSecurity).
        return RequestMatcher { request -> endpointsMatcher!!.matches(request) }
    }

    override fun init(httpSecurity: HttpSecurity) {
        val bffAuthorizationSettings = BffAuthorizationConfigurerUtils.getAuthorizationSettings(httpSecurity)
        validateAuthorizationServerSettings(bffAuthorizationSettings)
        val requestMatchers: MutableList<RequestMatcher> = mutableListOf()

//        httpSecurity.oauth2Login { configurer ->
//            configurer.successHandler(BffAuthenticationSuccessHandler())
//            configurer.userInfoEndpoint {
//                it.userService(BffOAuth2UserService())
//            }
//            configurer.tokenEndpoint {
//                it.accessTokenResponseClient(accessTokenResponseClient())
//            }
//        }

        configurers.values.forEach { configurer: AbstractBffConfigurer ->
            configurer.init(httpSecurity)
            requestMatchers.add(configurer.requestMatcher)
        }
        endpointsMatcher = OrRequestMatcher(requestMatchers)

//        val exceptionHandling = httpSecurity.getConfigurer(
//            ExceptionHandlingConfigurer::javaClass
//        )
//        if (exceptionHandling != null) {
//            exceptionHandling.defaultAuthenticationEntryPointFor(
//                HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
//                OrRequestMatcher(
////                    getRequestMatcher(TokenEndpointConfigurer::class.java),
//                    getRequestMatcher(SessionInfoEndpointConfigurer::class.java),
////                    getRequestMatcher(SessionEndEndpointConfigurer::class.java),
//                )
//            )
//        }
    }

    override fun configure(httpSecurity: HttpSecurity) {
        configurers.values.forEach(Consumer { configurer: AbstractBffConfigurer ->
            configurer.configure(
                httpSecurity
            )
        })

//        val authorizationServerSettings: AuthorizationSettings =
//            OAuth2ConfigurerUtils.getAuthorizationServerSettings(httpSecurity)
//        val authorizationServerContextFilter = AuthorizationServerContextFilter(authorizationServerSettings)
//        httpSecurity.addFilterAfter(
//            postProcess(authorizationServerContextFilter),
//            SecurityContextHolderFilter::class.java
//        )
    }

    private fun createConfigurers(): MutableMap<Class<out AbstractBffConfigurer>, AbstractBffConfigurer> {
        val configurers: MutableMap<Class<out AbstractBffConfigurer>, AbstractBffConfigurer> = LinkedHashMap()

        val postProcess =  object: ObjectPostProcessor<Any> {
            override fun <O : Any> postProcess(process: O): O {
                return this@BffAuthorizationConfigurer.postProcess(process)
            }
        }

//        configurers[TokenEndpointConfigurer::class.java] = TokenEndpointConfigurer(postProcess)
        configurers[SessionInfoEndpointConfigurer::class.java] = SessionInfoEndpointConfigurer(postProcess)
        configurers[SessionEndEndpointConfigurer::class.java] = SessionEndEndpointConfigurer(postProcess)

        return configurers
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T: AbstractBffConfigurer> getConfigurer(type: Class<T>): T {
        return configurers.getValue(type) as T
    }
    private fun <T : AbstractBffConfigurer> addConfigurer(configurerType: Class<T>, configurer: T) {
        configurers[configurerType] = configurer
    }

    private fun <T : AbstractBffConfigurer> getRequestMatcher(configurerType: Class<T>): RequestMatcher {
        val configurer = getConfigurer(configurerType)
        return configurer.requestMatcher
    }

    companion object {
        private fun validateAuthorizationServerSettings(authorizationServerSettings: BffAuthorizationSettings) {
//            if (authorizationServerSettings.getIssuer() != null) {
//                val issuerUri: URI
//                try {
//                    issuerUri = URI(authorizationServerSettings.getIssuer())
//                    issuerUri.toURL()
//                } catch (ex: Exception) {
//                    throw IllegalArgumentException("issuer must be a valid URL", ex)
//                }
//                // rfc8414 https://datatracker.ietf.org/doc/html/rfc8414#section-2
//                require(!(issuerUri.query != null || issuerUri.fragment != null)) { "issuer cannot contain query or fragment component" }
//            }
        }
    }
}