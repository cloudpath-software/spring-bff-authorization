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

import com.snapwise.security.bff.authorization.oauth2.client.userinfo.BffOAuth2UserService
import org.springframework.core.convert.converter.Converter
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.util.StringUtils
import java.util.*
import java.util.stream.Collectors

/**
 * Adds the refresh token to the additional params map in order to retrieve it in
 * the [BffOAuth2UserService]. This seems like the least overriding path to obtaining the
 * desired execution since within the [OAuth2LoginAuthenticationFilter], the instance
 * of [OAuth2LoginAuthenticationToken], which contains the refresh token, is converted to
 * a [OAuth2AuthenticationToken] which does not contain the refresh token.
 */
class BffOAuth2AccessTokenResponseHttpMessageConverter: Converter<Map<String, Any>, OAuth2AccessTokenResponse> {

    override fun convert(tokenResponseParameters: Map<String, Any>): OAuth2AccessTokenResponse {
        val accessToken: String = tokenResponseParameters[OAuth2ParameterNames.ACCESS_TOKEN] as String
        val refreshToken: String = tokenResponseParameters[OAuth2ParameterNames.REFRESH_TOKEN] as String
        val expiresIn: Long = (tokenResponseParameters[OAuth2ParameterNames.EXPIRES_IN] as Int).toLong()

        var scopes: Set<String> = emptySet()
        if (tokenResponseParameters.containsKey(OAuth2ParameterNames.SCOPE)) {
            val scope: String = tokenResponseParameters[OAuth2ParameterNames.SCOPE] as String
            scopes = Arrays.stream(StringUtils.delimitedListToStringArray(scope, " "))
                .collect(Collectors.toSet())
        }

        val additionalParameters: MutableMap<String, Any> = HashMap()
        additionalParameters[OAuth2ParameterNames.REFRESH_TOKEN] = refreshToken

        return OAuth2AccessTokenResponse.withToken(accessToken)
            .tokenType(OAuth2AccessToken.TokenType.BEARER)
            .expiresIn(expiresIn)
            .scopes(scopes)
            .refreshToken(refreshToken)
            .additionalParameters(Collections.unmodifiableMap(additionalParameters))
            .build()
    }
}