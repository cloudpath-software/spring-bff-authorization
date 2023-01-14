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

package com.snapwise.security.bff.authorization.authentication

import com.snapwise.security.bff.authorization.UserSessionService
import com.snapwise.security.bff.authorization.web.UserSessionAuthenticationToken
import org.apache.commons.logging.LogFactory
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.core.*
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator


/**
 * An [AuthenticationProvider] implementation for the OAuth 2.0 Refresh Token Grant.
 *
 * @since 0.0.1
 * @see OAuth2RefreshTokenAuthenticationToken
 *
 * @see OAuth2AccessTokenAuthenticationToken
 *
 * @see OAuth2AuthorizationService
 *
 * @see OAuth2TokenGenerator
 *
 * @see [Section 1.5 Refresh Token Grant](https://datatracker.ietf.org/doc/html/rfc6749.section-1.5)
 *
 * @see [Section 6 Refreshing an Access Token](https://datatracker.ietf.org/doc/html/rfc6749.section-6)
 */
class UserSessionAuthenticationProvider(
    val userSessionService: UserSessionService,
) : AuthenticationProvider {
    private val logger = LogFactory.getLog(javaClass)

    @Throws(AuthenticationException::class)
    override fun authenticate(authentication: Authentication): Authentication {
        val userSessionTokenAuthentication = authentication as UserSessionAuthenticationToken
//        val clientPrincipal =
//            OAuth2AuthenticationProviderUtils.getAuthenticatedClientElseThrowInvalidClient(userSessionTokenAuthentication)
//        val registeredClient = clientPrincipal.registeredClient
        if (logger.isTraceEnabled) {
            logger.trace("Retrieved registered client")
        }
        var authorization = userSessionService.findBySessionId(userSessionTokenAuthentication.getToken())
            ?: throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT)
        if (logger.isTraceEnabled) {
            logger.trace("Retrieved authorization with refresh token")
        }
//        if (registeredClient.id != authorization.registeredClientId) {
//            throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT)
//        }
//        if (!registeredClient.authorizationGrantTypes.contains(AuthorizationGrantType.REFRESH_TOKEN)) {
//            throw OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT)
//        }
        val refreshToken = authorization.refreshToken
//        if (!refreshToken.isActive) {
//            // As per https://tools.ietf.org/html/rfc6749#section-5.2
//            // invalid_grant: The provided authorization grant (e.g., authorization code,
//            // resource owner credentials) or refresh token is invalid, expired, revoked [...].
//            throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT)
//        }

        // As per https://tools.ietf.org/html/rfc6749#section-6
        // The requested scope MUST NOT include any scope not originally granted by the resource owner,
        // and if omitted is treated as equal to the scope originally granted by the resource owner.
//        var scopes = userSessionTokenAuthentication.scopes
//        val authorizedScopes = authorization.authorizedScopes
//        if (!authorizedScopes.containsAll(scopes)) {
//            throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE)
//        }
        if (logger.isTraceEnabled) {
            logger.trace("Validated token request parameters")
        }
//        if (scopes.isEmpty()) {
//            scopes = authorizedScopes
//        }

        // @formatter:off
//        val tokenContextBuilder = DefaultOAuth2TokenContext.builder()
//            .registeredClient(registeredClient)
//            .principal(authorization.getAttribute(Principal::class.java.name))
//            .authorizationServerContext(AuthorizationServerContextHolder.getContext())
//            .authorization(authorization)
//            .authorizedScopes(scopes)
//            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//            .authorizationGrant(userSessionTokenAuthentication)
//        // @formatter:on
//        val authorizationBuilder = OAuth2Authorization.from(authorization)

        // ----- Access token -----
//        var tokenContext: OAuth2TokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build()
//        val generatedAccessToken = tokenGenerator.generate(tokenContext)
//        if (generatedAccessToken == null) {
//            val error = OAuth2Error(
//                OAuth2ErrorCodes.SERVER_ERROR,
//                "The token generator failed to generate the access token.", ERROR_URI
//            )
//            throw OAuth2AuthenticationException(error)
//        }
        if (logger.isTraceEnabled) {
            logger.trace("Generated user session token")
        }
//        val accessToken = OAuth2AccessToken(
//            OAuth2AccessToken.TokenType.BEARER,
//            generatedAccessToken.tokenValue, generatedAccessToken.issuedAt,
//            generatedAccessToken.expiresAt, tokenContext.authorizedScopes
//        )
//        if (generatedAccessToken is ClaimAccessor) {
//            authorizationBuilder.token(
//                accessToken
//            ) { metadata: MutableMap<String?, Any?> ->
//                metadata[OAuth2Authorization.Token.CLAIMS_METADATA_NAME] =
//                    (generatedAccessToken as ClaimAccessor).claims
//                metadata[OAuth2Authorization.Token.INVALIDATED_METADATA_NAME] = false
//            }
//        } else {
//            authorizationBuilder.accessToken(accessToken)
//        }

        // ----- Refresh token -----
//        var currentRefreshToken = refreshToken.token
//        if (!registeredClient.tokenSettings.isReuseRefreshTokens) {
//            tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build()
//            val generatedRefreshToken = tokenGenerator.generate(tokenContext)
//            if (generatedRefreshToken !is OAuth2RefreshToken) {
//                val error = OAuth2Error(
//                    OAuth2ErrorCodes.SERVER_ERROR,
//                    "The token generator failed to generate the refresh token.", ERROR_URI
//                )
//                throw OAuth2AuthenticationException(error)
//            }
//            if (logger.isTraceEnabled) {
//                logger.trace("Generated refresh token")
//            }
//            currentRefreshToken = generatedRefreshToken
//            authorizationBuilder.refreshToken(currentRefreshToken)
//        }


//        authorization = authorizationBuilder.build()
        userSessionService.save(authorization)
        if (logger.isTraceEnabled) {
            logger.trace("Saved user session")
        }
        var additionalParameters: Map<String?, Any?> = emptyMap<String?, Any>()
        if (logger.isTraceEnabled) {
            logger.trace("Authenticated token request")
        }
        return object: AbstractAuthenticationToken(mutableListOf<GrantedAuthority>()) {
            override fun getCredentials(): Any {
                TODO("Not yet implemented")
            }

            override fun getPrincipal(): Any {
                TODO("Not yet implemented")
            }

        }
    }

    override fun supports(authentication: Class<*>): Boolean {
        return OAuth2RefreshTokenAuthenticationToken::class.java.isAssignableFrom(authentication)
    }

    companion object {
        private const val ERROR_URI = "https://datatracker.ietf.org/doc/html/draft-bertocci-oauth2-tmi-bff-01#name-errors"
//        private val ID_TOKEN_TOKEN_TYPE = OAuth2TokenType(OidcParameterNames.ID_TOKEN)
    }
}