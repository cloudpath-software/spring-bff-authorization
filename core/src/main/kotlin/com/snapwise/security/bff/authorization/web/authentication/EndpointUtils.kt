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
package com.snapwise.security.bff.authorization.web.authentication

import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap

/**
 * Utility methods for the OAuth 2.0 Protocol Endpoints.
 */
internal object EndpointUtils {
    const val ACCESS_TOKEN_REQUEST_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2"
    fun getParameters(request: HttpServletRequest): MultiValueMap<String, String> {
        val parameterMap = request.parameterMap
        val parameters: MultiValueMap<String, String> = LinkedMultiValueMap(parameterMap.size)
        parameterMap.forEach { (key: String, values: Array<String>) ->
            if (values.size > 0) {
                for (value in values) {
                    parameters.add(key, value)
                }
            }
        }
        return parameters
    }

    fun getParametersIfMatchesAuthorizationCodeGrantRequest(
        request: HttpServletRequest,
        vararg exclusions: String
    ): Map<String, Any> {
        if (!matchesAuthorizationCodeGrantRequest(request)) {
            return emptyMap()
        }
        val parameters: MutableMap<String, Any> = HashMap(getParameters(request).toSingleValueMap())
        for (exclusion in exclusions) {
            parameters.remove(exclusion)
        }
        return parameters
    }

    fun matchesAuthorizationCodeGrantRequest(request: HttpServletRequest): Boolean {
        return AuthorizationGrantType.AUTHORIZATION_CODE.value ==
                request.getParameter(OAuth2ParameterNames.GRANT_TYPE) &&
                request.getParameter(OAuth2ParameterNames.CODE) != null
    }

    fun matchesPkceTokenRequest(request: HttpServletRequest): Boolean {
        return matchesAuthorizationCodeGrantRequest(request) &&
                request.getParameter(PkceParameterNames.CODE_VERIFIER) != null
    }

    fun throwError(errorCode: String?, parameterName: String, errorUri: String?) {
        val error = OAuth2Error(errorCode, "OAuth 2.0 Parameter: $parameterName", errorUri)
        throw OAuth2AuthenticationException(error)
    }
}