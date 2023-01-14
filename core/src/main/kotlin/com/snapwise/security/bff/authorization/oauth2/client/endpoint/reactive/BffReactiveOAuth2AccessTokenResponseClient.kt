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

package com.snapwise.security.bff.authorization.oauth2.client.endpoint.reactive

import com.snapwise.security.bff.authorization.oauth2.client.userinfo.BffOReactiveAuth2UserService
import org.springframework.core.convert.converter.Converter
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.http.ReactiveHttpInputMessage
import org.springframework.security.oauth2.client.endpoint.AbstractOAuth2AuthorizationGrantRequest
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.core.web.reactive.function.OAuth2BodyExtractors
import org.springframework.util.*
import org.springframework.web.reactive.function.BodyExtractor
import org.springframework.web.reactive.function.BodyInserters
import org.springframework.web.reactive.function.client.ClientResponse
import org.springframework.web.reactive.function.client.WebClient
import reactor.core.publisher.Mono
import java.io.UnsupportedEncodingException
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

abstract class BffReactiveOAuth2AccessTokenResponseClient<T: AbstractOAuth2AuthorizationGrantRequest>: ReactiveOAuth2AccessTokenResponseClient<T> {

    private var webClient: WebClient = WebClient.builder().build()

    private var headersConverter =
        Converter<T, HttpHeaders> { grantRequest: T ->
            this.populateTokenRequestHeaders(
                grantRequest
            )
        }

    private var parametersConverter =
        Converter<T, MultiValueMap<String, String>> { grantRequest: T ->
            this.populateTokenRequestParameters(
                grantRequest
            )
        }

    private var bodyExtractor: BodyExtractor<Mono<OAuth2AccessTokenResponse>, ReactiveHttpInputMessage> =
        OAuth2BodyExtractors
            .oauth2AccessTokenResponse()

    override fun getTokenResponse(grantRequest: T): Mono<OAuth2AccessTokenResponse> {
        return Mono.defer {
            webClient.post()
                .uri(clientRegistration(grantRequest).providerDetails.tokenUri)
                .headers { headers: HttpHeaders ->
                    val headersToAdd =
                        getHeadersConverter().convert(grantRequest)
                    if (headersToAdd != null) {
                        headers.addAll(headersToAdd)
                    }
                }
                .body(createTokenRequestBody(grantRequest))
                .exchangeToMono { response: ClientResponse ->
                    readTokenResponse(
                        grantRequest,
                        response
                    )
                }
        }
    }

    /**
     * Returns the [ClientRegistration] for the given `grantRequest`.
     * @param grantRequest the grant request
     * @return the [ClientRegistration] for the given `grantRequest`.
     */
    abstract fun clientRegistration(grantRequest: T): ClientRegistration

    /**
     * Populates the headers for the token request.
     * @param grantRequest the grant request
     * @return the headers populated for the token request
     */
    private fun populateTokenRequestHeaders(grantRequest: T): HttpHeaders? {
        val headers = HttpHeaders()
        val clientRegistration = clientRegistration(grantRequest)
        headers.contentType = MediaType.APPLICATION_FORM_URLENCODED
        headers.accept = listOf(MediaType.APPLICATION_JSON)
        if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC == clientRegistration.clientAuthenticationMethod) {
            val clientId = encodeClientCredential(clientRegistration.clientId)
            val clientSecret = encodeClientCredential(clientRegistration.clientSecret)
            headers.setBasicAuth(clientId, clientSecret)
        }
        return headers
    }

    private fun encodeClientCredential(clientCredential: String): String {
        return try {
            URLEncoder.encode(clientCredential, StandardCharsets.UTF_8.toString())
        } catch (ex: UnsupportedEncodingException) {
            // Will not happen since UTF-8 is a standard charset
            throw IllegalArgumentException(ex)
        }
    }

    /**
     * Populates default parameters for the token request.
     * @param grantRequest the grant request
     * @return the parameters populated for the token request.
     */
    private fun populateTokenRequestParameters(grantRequest: T): MultiValueMap<String, String>? {
        val parameters: MultiValueMap<String, String> = LinkedMultiValueMap()
        parameters.add(OAuth2ParameterNames.GRANT_TYPE, grantRequest.grantType.value)
        return parameters
    }

    /**
     * Combine the results of `parametersConverter` and
     * [.populateTokenRequestBody].
     *
     *
     *
     * This method pre-populates the body with some standard properties, and then
     * delegates to
     * [.populateTokenRequestBody]
     * for subclasses to further populate the body before returning.
     *
     * @param grantRequest the grant request
     * @return the body for the token request.
     */
    private fun createTokenRequestBody(grantRequest: T): BodyInserters.FormInserter<String> {
        val parameters = getParametersConverter().convert(grantRequest)!!
        return populateTokenRequestBody(grantRequest, BodyInserters.fromFormData(parameters))
    }

    /**
     * Populates the body of the token request.
     *
     *
     *
     * By default, populates properties that are common to all grant types. Subclasses can
     * extend this method to populate grant type specific properties.
     *
     * @param grantRequest the grant request
     * @param body the body to populate
     * @return the populated body
     */
    open fun populateTokenRequestBody(
        grantRequest: T,
        body: BodyInserters.FormInserter<String>
    ): BodyInserters.FormInserter<String> {
        val clientRegistration = clientRegistration(grantRequest)
        if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC != clientRegistration.clientAuthenticationMethod) {
            body.with(OAuth2ParameterNames.CLIENT_ID, clientRegistration.clientId)
        }
        if (ClientAuthenticationMethod.CLIENT_SECRET_POST == clientRegistration.clientAuthenticationMethod) {
            body.with(OAuth2ParameterNames.CLIENT_SECRET, clientRegistration.clientSecret)
        }
        val scopes = scopes(grantRequest)
        if (!CollectionUtils.isEmpty(scopes)) {
            body.with(OAuth2ParameterNames.SCOPE, StringUtils.collectionToDelimitedString(scopes, " "))
        }

        return body
    }

    /**
     * Returns the scopes to include as a property in the token request.
     * @param grantRequest the grant request
     * @return the scopes to include as a property in the token request.
     */
    abstract fun scopes(grantRequest: T): Set<String?>

    /**
     * Returns the scopes to include in the response if the authorization server returned
     * no scopes in the response.
     *
     *
     *
     * As per [RFC-6749 Section
 * 5.1 Successful Access Token Response](https://tools.ietf.org/html/rfc6749#section-5.1), if AccessTokenResponse.scope is empty,
     * then default to the scope originally requested by the client in the Token Request.
     *
     * @param grantRequest the grant request
     * @return the scopes to include in the response if the authorization server returned
     * no scopes.
     */
    fun defaultScopes(grantRequest: T): Set<String> {
        return emptySet()
    }

    /**
     * Reads the token response from the response body.
     * @param grantRequest the request for which the response was received.
     * @param response the client response from which to read
     * @return the token response from the response body.
     */
    private fun readTokenResponse(grantRequest: T, response: ClientResponse): Mono<OAuth2AccessTokenResponse?>? {
        return response.body(bodyExtractor)
            .map<OAuth2AccessTokenResponse> { tokenResponse: OAuth2AccessTokenResponse ->
                populateTokenResponse(
                    grantRequest,
                    tokenResponse
                )
            }
    }

    /**
     * Populates the given [OAuth2AccessTokenResponse] with additional details from
     * the grant request.
     *
     * Additionally, injects the refresh token with the additional parameters in order
     * to be able to retrieve it within the [BffOReactiveAuth2UserService]
     *
     * @param grantRequest the request for which the response was received.
     * @param tokenResponse the original token response
     * @return a token response optionally populated with additional details from the
     * request.
     */
    fun populateTokenResponse(grantRequest: T, tokenResponse: OAuth2AccessTokenResponse): OAuth2AccessTokenResponse {
        var tokenResponse = tokenResponse
        val scopes = if (CollectionUtils.isEmpty(tokenResponse.accessToken.scopes)) {
            defaultScopes(grantRequest)
        } else { tokenResponse.accessToken.scopes }

        val additionalParameters: MutableMap<String, Any> = HashMap()
        additionalParameters[OAuth2ParameterNames.REFRESH_TOKEN] = tokenResponse.refreshToken!!.tokenValue

        tokenResponse = OAuth2AccessTokenResponse
            .withResponse(tokenResponse)
            .scopes(scopes)
            .additionalParameters(additionalParameters)
            .build()
        return tokenResponse
    }

    /**
     * Sets the [WebClient] used when requesting the OAuth 2.0 Access Token
     * Response.
     * @param webClient the [WebClient] used when requesting the Access Token
     * Response
     */
    fun setWebClient(webClient: WebClient) {
        Assert.notNull(webClient, "webClient cannot be null")
        this.webClient = webClient
    }

    /**
     * Returns the [Converter] used for converting the
     * [AbstractOAuth2AuthorizationGrantRequest] instance to a [HttpHeaders]
     * used in the OAuth 2.0 Access Token Request headers.
     * @return the [Converter] used for converting the
     * [AbstractOAuth2AuthorizationGrantRequest] to [HttpHeaders]
     */
    fun getHeadersConverter(): Converter<T, HttpHeaders> {
        return headersConverter
    }

    /**
     * Sets the [Converter] used for converting the
     * [AbstractOAuth2AuthorizationGrantRequest] instance to a [HttpHeaders]
     * used in the OAuth 2.0 Access Token Request headers.
     * @param headersConverter the [Converter] used for converting the
     * [AbstractOAuth2AuthorizationGrantRequest] to [HttpHeaders]
     * @since 5.6
     */
    fun setHeadersConverter(headersConverter: Converter<T, HttpHeaders>) {
        Assert.notNull(headersConverter, "headersConverter cannot be null")
        this.headersConverter = headersConverter
    }

    /**
     * Add (compose) the provided `headersConverter` to the current
     * [Converter] used for converting the
     * [AbstractOAuth2AuthorizationGrantRequest] instance to a [HttpHeaders]
     * used in the OAuth 2.0 Access Token Request headers.
     * @param headersConverter the [Converter] to add (compose) to the current
     * [Converter] used for converting the
     * [AbstractOAuth2AuthorizationGrantRequest] to a [HttpHeaders]
     * @since 5.6
     */
    fun addHeadersConverter(headersConverter: Converter<T, HttpHeaders?>) {
        Assert.notNull(headersConverter, "headersConverter cannot be null")
        val currentHeadersConverter = this.headersConverter
        this.headersConverter = Converter { authorizationGrantRequest: T ->
            // Append headers using a Composite Converter
            var headers = currentHeadersConverter.convert(authorizationGrantRequest)
            if (headers == null) {
                headers = HttpHeaders()
            }
            val headersToAdd = headersConverter.convert(authorizationGrantRequest)
            if (headersToAdd != null) {
                headers.addAll(headersToAdd)
            }
            headers
        }
    }

    /**
     * Returns the [Converter] used for converting the
     * [AbstractOAuth2AuthorizationGrantRequest] instance to a [MultiValueMap]
     * used in the OAuth 2.0 Access Token Request body.
     * @return the [Converter] used for converting the
     * [AbstractOAuth2AuthorizationGrantRequest] to [MultiValueMap]
     */
    fun getParametersConverter(): Converter<T, MultiValueMap<String, String>> {
        return parametersConverter
    }

    /**
     * Sets the [Converter] used for converting the
     * [AbstractOAuth2AuthorizationGrantRequest] instance to a [MultiValueMap]
     * used in the OAuth 2.0 Access Token Request body.
     * @param parametersConverter the [Converter] used for converting the
     * [AbstractOAuth2AuthorizationGrantRequest] to [MultiValueMap]
     * @since 5.6
     */
    fun setParametersConverter(parametersConverter: Converter<T, MultiValueMap<String, String>>) {
        this.parametersConverter = parametersConverter
    }

    /**
     * Add (compose) the provided `parametersConverter` to the current
     * [Converter] used for converting the
     * [AbstractOAuth2AuthorizationGrantRequest] instance to a [MultiValueMap]
     * used in the OAuth 2.0 Access Token Request body.
     * @param parametersConverter the [Converter] to add (compose) to the current
     * [Converter] used for converting the
     * [AbstractOAuth2AuthorizationGrantRequest] to a [MultiValueMap]
     * @since 5.6
     */
    fun addParametersConverter(parametersConverter: Converter<T, MultiValueMap<String, String>?>) {
        Assert.notNull(parametersConverter, "parametersConverter cannot be null")
        val currentParametersConverter = this.parametersConverter
        this.parametersConverter =
            Converter { authorizationGrantRequest: T ->
                var parameters =
                    currentParametersConverter.convert(authorizationGrantRequest)
                if (parameters == null) {
                    parameters = LinkedMultiValueMap()
                }
                val parametersToAdd =
                    parametersConverter.convert(authorizationGrantRequest)
                if (parametersToAdd != null) {
                    parameters.addAll(parametersToAdd)
                }
                parameters
            }
    }

    /**
     * Sets the [BodyExtractor] that will be used to decode the
     * [OAuth2AccessTokenResponse]
     * @param bodyExtractor the [BodyExtractor] that will be used to decode the
     * [OAuth2AccessTokenResponse]
     * @since 5.6
     */
    fun setBodyExtractor(
        bodyExtractor: BodyExtractor<Mono<OAuth2AccessTokenResponse>, ReactiveHttpInputMessage>
    ) {
        Assert.notNull(bodyExtractor, "bodyExtractor cannot be null")
        this.bodyExtractor = bodyExtractor
    }
}