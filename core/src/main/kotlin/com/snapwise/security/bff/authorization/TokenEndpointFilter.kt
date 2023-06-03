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
package com.snapwise.security.bff.authorization

import jakarta.servlet.FilterChain
import jakarta.servlet.ServletException
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.core.log.LogMessage
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.http.converter.HttpMessageConverter
import org.springframework.http.server.ServletServerHttpResponse
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.authentication.AuthenticationDetailsSource
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken
import org.springframework.security.oauth2.server.authorization.web.authentication.DelegatingAuthenticationConverter
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeAuthenticationConverter
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2ClientCredentialsAuthenticationConverter
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2RefreshTokenAuthenticationConverter
import org.springframework.security.web.authentication.AuthenticationConverter
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher
import org.springframework.util.Assert
import org.springframework.util.CollectionUtils
import org.springframework.web.filter.OncePerRequestFilter
import java.io.IOException
import java.time.temporal.ChronoUnit
import java.util.*

/**
 * A `Filter` for the Bff token endpoint,
 * which handles the processing of an OAuth 2.0 Authorization Grant.
 *
 *
 *
 * It converts the OAuth 2.0 Authorization Grant request to an [Authentication],
 * which is then authenticated by the [AuthenticationManager].
 * If the authentication succeeds, the [AuthenticationManager] returns an
 * [OAuth2AccessTokenAuthenticationToken], which is returned in the OAuth 2.0 Access Token response.
 * In case of any error, an [OAuth2Error] is returned in the OAuth 2.0 Error response.
 *
 *
 *
 * By default, this `Filter` responds to authorization grant requests
 * at the `URI` `/oauth2/bff-token` and `HttpMethod` `POST`.
 *
 *
 *
 * The default endpoint `URI` `/oauth2/bff-token` may be overridden
 * via the constructor [.TokenEndpointFilter].
 *
 * @since 0.0.1
 * @see AuthenticationManager
 *
 * @see OAuth2AuthorizationCodeAuthenticationProvider
 *
 * @see OAuth2RefreshTokenAuthenticationProvider
 *
 * @see OAuth2ClientCredentialsAuthenticationProvider
 *
 * @see [Section 3.1 The bff-token Endpoint](https://datatracker.ietf.org/doc/html/draft-bertocci-oauth2-tmi-bff-01.section-3.1)
 */
class TokenEndpointFilter @JvmOverloads constructor(
    authenticationManager: AuthenticationManager,
    tokenEndpointUri: String? = DEFAULT_TOKEN_ENDPOINT_URI
) : OncePerRequestFilter() {
    private val authenticationManager: AuthenticationManager
    private val tokenEndpointMatcher: RequestMatcher
    private val accessTokenHttpResponseConverter: HttpMessageConverter<OAuth2AccessTokenResponse> =
        OAuth2AccessTokenResponseHttpMessageConverter()
    private val errorHttpResponseConverter: HttpMessageConverter<OAuth2Error> = OAuth2ErrorHttpMessageConverter()
    private var authenticationDetailsSource: AuthenticationDetailsSource<HttpServletRequest, *> =
        WebAuthenticationDetailsSource()
    private var authenticationConverter: AuthenticationConverter
    private var authenticationSuccessHandler =
        AuthenticationSuccessHandler { request, response, authentication ->
            sendAccessTokenResponse(
                request,
                response,
                authentication
            )
        }
    private var authenticationFailureHandler =
        AuthenticationFailureHandler { request: HttpServletRequest, response: HttpServletResponse, exception: AuthenticationException ->
            sendErrorResponse(
                request,
                response,
                exception
            )
        }
    /**
     * Constructs an `OAuth2TokenEndpointFilter` using the provided parameters.
     *
     * @param authenticationManager the authentication manager
     * @param tokenEndpointUri the endpoint `URI` for access token requests
     */
    /**
     * Constructs an `OAuth2TokenEndpointFilter` using the provided parameters.
     *
     * @param authenticationManager the authentication manager
     */
    init {
        Assert.notNull(authenticationManager, "authenticationManager cannot be null")
        Assert.hasText(tokenEndpointUri, "tokenEndpointUri cannot be empty")
        this.authenticationManager = authenticationManager
        tokenEndpointMatcher = AntPathRequestMatcher(tokenEndpointUri, HttpMethod.POST.name())
        authenticationConverter = DelegatingAuthenticationConverter(
            Arrays.asList(
                OAuth2AuthorizationCodeAuthenticationConverter(),
                OAuth2RefreshTokenAuthenticationConverter(),
                OAuth2ClientCredentialsAuthenticationConverter()
            )
        )
    }

    @Throws(ServletException::class, IOException::class)
    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        if (!tokenEndpointMatcher.matches(request)) {
            filterChain.doFilter(request, response)
            return
        }
        try {
            val grantTypes = request.getParameterValues(OAuth2ParameterNames.GRANT_TYPE)
            if (grantTypes == null || grantTypes.size != 1) {
                throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.GRANT_TYPE)
            }
            val authorizationGrantAuthentication = authenticationConverter.convert(request)
            if (authorizationGrantAuthentication == null) {
                throwError(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE, OAuth2ParameterNames.GRANT_TYPE)
            }
            if (authorizationGrantAuthentication is AbstractAuthenticationToken) {
                authorizationGrantAuthentication.details = authenticationDetailsSource.buildDetails(request)
            }
            val accessTokenAuthentication =
                authenticationManager.authenticate(authorizationGrantAuthentication) as OAuth2AccessTokenAuthenticationToken
            authenticationSuccessHandler.onAuthenticationSuccess(request, response, accessTokenAuthentication)
        } catch (ex: OAuth2AuthenticationException) {
            SecurityContextHolder.clearContext()
            if (logger.isTraceEnabled) {
                logger.trace(LogMessage.format("Token request failed: %s", ex.error), ex)
            }
            authenticationFailureHandler.onAuthenticationFailure(request, response, ex)
        }
    }

    /**
     * Sets the [AuthenticationDetailsSource] used for building an authentication details instance from [HttpServletRequest].
     *
     * @param authenticationDetailsSource the [AuthenticationDetailsSource] used for building an authentication details instance from [HttpServletRequest]
     */
    fun setAuthenticationDetailsSource(authenticationDetailsSource: AuthenticationDetailsSource<HttpServletRequest, *>) {
        Assert.notNull(authenticationDetailsSource, "authenticationDetailsSource cannot be null")
        this.authenticationDetailsSource = authenticationDetailsSource
    }

    /**
     * Sets the [AuthenticationConverter] used when attempting to extract an Access Token Request from [HttpServletRequest]
     * to an instance of [OAuth2AuthorizationGrantAuthenticationToken] used for authenticating the authorization grant.
     *
     * @param authenticationConverter the [AuthenticationConverter] used when attempting to extract an Access Token Request from [HttpServletRequest]
     */
    fun setAuthenticationConverter(authenticationConverter: AuthenticationConverter) {
        Assert.notNull(authenticationConverter, "authenticationConverter cannot be null")
        this.authenticationConverter = authenticationConverter
    }

    /**
     * Sets the [AuthenticationSuccessHandler] used for handling an [OAuth2AccessTokenAuthenticationToken]
     * and returning the [Access Token Response][OAuth2AccessTokenResponse].
     *
     * @param authenticationSuccessHandler the [AuthenticationSuccessHandler] used for handling an [OAuth2AccessTokenAuthenticationToken]
     */
    fun setAuthenticationSuccessHandler(authenticationSuccessHandler: AuthenticationSuccessHandler) {
        Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null")
        this.authenticationSuccessHandler = authenticationSuccessHandler
    }

    /**
     * Sets the [AuthenticationFailureHandler] used for handling an [OAuth2AuthenticationException]
     * and returning the [Error Response][OAuth2Error].
     *
     * @param authenticationFailureHandler the [AuthenticationFailureHandler] used for handling an [OAuth2AuthenticationException]
     */
    fun setAuthenticationFailureHandler(authenticationFailureHandler: AuthenticationFailureHandler) {
        Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null")
        this.authenticationFailureHandler = authenticationFailureHandler
    }

    @Throws(IOException::class)
    private fun sendAccessTokenResponse(
        request: HttpServletRequest, response: HttpServletResponse,
        authentication: Authentication
    ) {
        val accessTokenAuthentication = authentication as OAuth2AccessTokenAuthenticationToken
        val accessToken = accessTokenAuthentication.accessToken
        val refreshToken = accessTokenAuthentication.refreshToken
        val additionalParameters = accessTokenAuthentication.additionalParameters
        val builder = OAuth2AccessTokenResponse.withToken(accessToken.tokenValue)
            .tokenType(accessToken.tokenType)
            .scopes(accessToken.scopes)
        if (accessToken.issuedAt != null && accessToken.expiresAt != null) {
            builder.expiresIn(ChronoUnit.SECONDS.between(accessToken.issuedAt, accessToken.expiresAt))
        }
        if (refreshToken != null) {
            builder.refreshToken(refreshToken.tokenValue)
        }
        if (!CollectionUtils.isEmpty(additionalParameters)) {
            builder.additionalParameters(additionalParameters)
        }
        val accessTokenResponse = builder.build()
        val httpResponse = ServletServerHttpResponse(response)
        accessTokenHttpResponseConverter.write(accessTokenResponse, null, httpResponse)
    }

    @Throws(IOException::class)
    private fun sendErrorResponse(
        request: HttpServletRequest, response: HttpServletResponse,
        exception: AuthenticationException
    ) {
        val error = (exception as OAuth2AuthenticationException).error
        val httpResponse = ServletServerHttpResponse(response)
        httpResponse.setStatusCode(HttpStatus.BAD_REQUEST)
        errorHttpResponseConverter.write(error, null, httpResponse)
    }

    companion object {
        /**
         * The default endpoint `URI` for access token requests.
         */
        const val DEFAULT_TOKEN_ENDPOINT_URI = "/oauth2/token"
        private const val DEFAULT_ERROR_URI =
            "https://datatracker.ietf.org/doc/html/draft-bertocci-oauth2-tmi-bff-01#section-4.3.1"

        private fun throwError(errorCode: String, parameterName: String) {
            val error = OAuth2Error(errorCode, "OAuth 2.0 Parameter: $parameterName", DEFAULT_ERROR_URI)
            throw OAuth2AuthenticationException(error)
        }
    }
}