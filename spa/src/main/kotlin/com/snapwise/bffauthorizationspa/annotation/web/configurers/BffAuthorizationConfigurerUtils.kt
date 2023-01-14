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

import com.snapwise.security.bff.authorization.InMemoryUserSessionService
import com.snapwise.security.bff.authorization.UserSessionService
import com.snapwise.security.bff.authorization.settings.BffAuthorizationSettings
import org.springframework.beans.factory.BeanFactoryUtils
import org.springframework.beans.factory.NoSuchBeanDefinitionException
import org.springframework.beans.factory.NoUniqueBeanDefinitionException
import org.springframework.context.ApplicationContext
import org.springframework.core.ResolvableType
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.oauth2.core.OAuth2Token
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.token.*
import org.springframework.util.StringUtils

/**
 * Utility methods for the Bff Authorization Configurers.
 *
 * @since 0.0.1
 */
internal object BffAuthorizationConfigurerUtils {
    fun getRegisteredClientRepository(httpSecurity: HttpSecurity): RegisteredClientRepository? {
        var registeredClientRepository = httpSecurity.getSharedObject(
            RegisteredClientRepository::class.java
        )
        if (registeredClientRepository == null) {
            registeredClientRepository = getBean(httpSecurity, RegisteredClientRepository::class.java)
            httpSecurity.setSharedObject(RegisteredClientRepository::class.java, registeredClientRepository)
        }
        return registeredClientRepository
    }

    fun getAuthorizationService(httpSecurity: HttpSecurity): OAuth2AuthorizationService {
        var authorizationService = httpSecurity.getSharedObject(
            OAuth2AuthorizationService::class.java
        )
        if (authorizationService == null) {
            authorizationService = getOptionalBean(httpSecurity, OAuth2AuthorizationService::class.java)
            if (authorizationService == null) {
                authorizationService = InMemoryOAuth2AuthorizationService()
            }
            httpSecurity.setSharedObject(OAuth2AuthorizationService::class.java, authorizationService)
        }
        return authorizationService
    }

    fun getUserSessionService(httpSecurity: HttpSecurity): UserSessionService {
        var authorizationService = httpSecurity.getSharedObject(
            UserSessionService::class.java
        )
        if (authorizationService == null) {
            authorizationService = getOptionalBean(httpSecurity, UserSessionService::class.java)
            if (authorizationService == null) {
                authorizationService = InMemoryUserSessionService()
            }
            httpSecurity.setSharedObject(UserSessionService::class.java, authorizationService)
        }
        return authorizationService
    }

    fun getTokenGenerator(httpSecurity: HttpSecurity): OAuth2TokenGenerator<out OAuth2Token?> {
        var tokenGenerator = httpSecurity.getSharedObject(
            OAuth2TokenGenerator::class.java
        )
        if (tokenGenerator == null) {
            tokenGenerator = getOptionalBean(httpSecurity, OAuth2TokenGenerator::class.java)
            if (tokenGenerator == null) {
//                val jwtGenerator = getJwtGenerator(httpSecurity)
                val accessTokenGenerator = OAuth2AccessTokenGenerator()
                val accessTokenCustomizer = getAccessTokenCustomizer(httpSecurity)
                if (accessTokenCustomizer != null) {
                    accessTokenGenerator.setAccessTokenCustomizer(accessTokenCustomizer)
                }
                val refreshTokenGenerator = OAuth2RefreshTokenGenerator()
//                tokenGenerator = jwtGenerator?.let {
//                    DelegatingOAuth2TokenGenerator(
//                        it,
//                        accessTokenGenerator,
//                        refreshTokenGenerator
//                    )
//                }
//                    ?: DelegatingOAuth2TokenGenerator(
//                        accessTokenGenerator, refreshTokenGenerator
//                    )
            }
            httpSecurity.setSharedObject(OAuth2TokenGenerator::class.java, tokenGenerator)
        }
        return tokenGenerator
    }

    private fun getJwtCustomizer(httpSecurity: HttpSecurity): OAuth2TokenCustomizer<JwtEncodingContext> {
        val type = ResolvableType.forClassWithGenerics(
            OAuth2TokenCustomizer::class.java, JwtEncodingContext::class.java
        )
        return getOptionalBean<OAuth2TokenCustomizer<JwtEncodingContext>>(httpSecurity, type)!!
    }

    private fun getAccessTokenCustomizer(httpSecurity: HttpSecurity): OAuth2TokenCustomizer<OAuth2TokenClaimsContext> {
        val type = ResolvableType.forClassWithGenerics(
            OAuth2TokenCustomizer::class.java, OAuth2TokenClaimsContext::class.java
        )
        return getOptionalBean<OAuth2TokenCustomizer<OAuth2TokenClaimsContext>>(httpSecurity, type)!!
    }

    fun getAuthorizationSettings(httpSecurity: HttpSecurity): BffAuthorizationSettings {
        var authorizationServerSettings = httpSecurity.getSharedObject(
            BffAuthorizationSettings::class.java
        )
        if (authorizationServerSettings == null) {
            authorizationServerSettings = getBean(httpSecurity, BffAuthorizationSettings::class.java)
            httpSecurity.setSharedObject(BffAuthorizationSettings::class.java, authorizationServerSettings)
        }
        return authorizationServerSettings
    }

    private fun <T> getBean(httpSecurity: HttpSecurity, type: Class<T>): T {
        return httpSecurity.getSharedObject(ApplicationContext::class.java).getBean(type)
    }

    fun <T> getBean(httpSecurity: HttpSecurity, type: ResolvableType?): T {
        val context = httpSecurity.getSharedObject(ApplicationContext::class.java)
        val names = context.getBeanNamesForType(type!!)
        if (names.size == 1) {
            return context.getBean(names[0]) as T
        }
        if (names.size > 1) {
            throw NoUniqueBeanDefinitionException(type, *names)
        }
        throw NoSuchBeanDefinitionException(type)
    }

    fun <T> getOptionalBean(httpSecurity: HttpSecurity, type: Class<T>): T? {
        val beansMap = BeanFactoryUtils.beansOfTypeIncludingAncestors(
            httpSecurity.getSharedObject(ApplicationContext::class.java), type
        )
        if (beansMap.size > 1) {
            throw NoUniqueBeanDefinitionException(
                type, beansMap.size,
                "Expected single matching bean of type '" + type.name + "' but found " +
                        beansMap.size + ": " + StringUtils.collectionToCommaDelimitedString(beansMap.keys)
            )
        }
        return if (!beansMap.isEmpty()) beansMap.values.iterator().next() else null
    }

    fun <T> getOptionalBean(httpSecurity: HttpSecurity, type: ResolvableType?): T? {
        val context = httpSecurity.getSharedObject(ApplicationContext::class.java)
        val names = context.getBeanNamesForType(type!!)
        if (names.size > 1) {
            throw NoUniqueBeanDefinitionException(type, *names)
        }
        return if (names.size == 1) context.getBean(names[0]) as T else null
    }
}