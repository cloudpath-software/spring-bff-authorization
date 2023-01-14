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

package com.snapwise.security.bff.authorization.oauth2.client.endpoint

import org.springframework.core.convert.converter.Converter
import org.springframework.http.RequestEntity
import org.springframework.http.ResponseEntity
import org.springframework.http.converter.FormHttpMessageConverter
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler
import org.springframework.security.oauth2.core.OAuth2AuthorizationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter
import org.springframework.web.client.RestClientException
import org.springframework.web.client.RestOperations
import org.springframework.web.client.RestTemplate
import java.util.*

open class BffOAuth2AccessTokenResponseClient: OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {

    private var requestEntityConverter: Converter<OAuth2AuthorizationCodeGrantRequest, RequestEntity<*>> =
        OAuth2AuthorizationCodeGrantRequestEntityConverter()
    private val tokenResponseHttpMessageConverter = OAuth2AccessTokenResponseHttpMessageConverter()

    private var restOperations: RestOperations

    init {
        tokenResponseHttpMessageConverter.setAccessTokenResponseConverter(BffOAuth2AccessTokenResponseHttpMessageConverter())

        val restTemplate = RestTemplate(
            listOf(FormHttpMessageConverter(), tokenResponseHttpMessageConverter)
        )
        restTemplate.errorHandler = OAuth2ErrorResponseErrorHandler()
        restOperations = restTemplate
    }

    override fun getTokenResponse(
        authorizationCodeGrantRequest: OAuth2AuthorizationCodeGrantRequest
    ): OAuth2AccessTokenResponse? {
        val request = requestEntityConverter.convert(authorizationCodeGrantRequest)!!
        val response = getResponse(request)
        // As per spec, in Section 5.1 Successful Access Token Response
        // https://tools.ietf.org/html/rfc6749#section-5.1
        // If AccessTokenResponse.scope is empty, then we assume all requested scopes were
        // granted.
        // However, we use the explicit scopes returned in the response (if any).
        return response.body
    }

    private fun getResponse(request: RequestEntity<*>): ResponseEntity<OAuth2AccessTokenResponse> {
        try {
            return restOperations.exchange(request, OAuth2AccessTokenResponse::class.java)
        } catch (ex: RestClientException) {
            val oauth2Error = OAuth2Error(
                INVALID_TOKEN_RESPONSE_ERROR_CODE,
                "An error occurred while attempting to retrieve the OAuth 2.0 Access Token Response: "
                        + ex.message,
                null
            )
            throw OAuth2AuthorizationException(oauth2Error, ex)
        }
    }

    /**
     * Sets the [Converter] used for converting the
     * [OAuth2AuthorizationCodeGrantRequest] to a [RequestEntity]
     * representation of the OAuth 2.0 Access Token Request.
     * @param requestEntityConverter the [Converter] used for converting to a
     * [RequestEntity] representation of the Access Token Request
     */
    fun setRequestEntityConverter(
        requestEntityConverter: Converter<OAuth2AuthorizationCodeGrantRequest, RequestEntity<*>>
    ) {
        this.requestEntityConverter = requestEntityConverter
    }

    /**
     * Sets the [RestOperations] used when requesting the OAuth 2.0 Access Token
     * Response.
     *
     *
     * **NOTE:** At a minimum, the supplied `restOperations` must be configured
     * with the following:
     *
     *  1. [HttpMessageConverter]'s - [FormHttpMessageConverter] and
     * [OAuth2AccessTokenResponseHttpMessageConverter]
     *  1. [ResponseErrorHandler] - [OAuth2ErrorResponseErrorHandler]
     *
     * @param restOperations the [RestOperations] used when requesting the Access
     * Token Response
     */
    fun setRestOperations(restOperations: RestOperations) {
        this.restOperations = restOperations
    }


    companion object {
        private const val INVALID_TOKEN_RESPONSE_ERROR_CODE = "invalid_token_response"
    }
}