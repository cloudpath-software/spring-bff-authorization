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

import com.snapwise.security.bff.authorization.oauth2.core.BffOAuth2User
import com.snapwise.security.bff.authorization.web.BffAuthorizationCookieRepository
import com.snapwise.security.bff.authorization.web.DefaultUserSessionAuthenticationToken
import com.snapwise.security.bff.authorization.web.oauth2.BffOAuth2AuthenticationToken
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler


/**
 * An authentication success strategy which builds on top of the [OAuth2LoginConfigurer].
 * Following a successful authorization execution flow (ex: confidential client with
 * authorization code grant type), the expectation is a [OAuth2ClientAuthenticationToken] instance will be
 * returned by the authorization server back to the BFF service instance. These tokens will
 * be persisted and cached for future client requests.
 */
open class BffAuthenticationSuccessHandler: SimpleUrlAuthenticationSuccessHandler() {

    private val bffAuthorizationCookieRepository: BffAuthorizationCookieRepository =
        BffAuthorizationCookieRepository()

    init {
        bffAuthorizationCookieRepository.setCookieDomain("127.0.0.1")
        bffAuthorizationCookieRepository.setCookiePath("/")
    }

    override fun onAuthenticationSuccess(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authentication: Authentication
    ) {
        val oAuth2AuthenticationToken = authentication as BffOAuth2AuthenticationToken

        val principal = oAuth2AuthenticationToken.principal as BffOAuth2User

        bffAuthorizationCookieRepository.setCookieMaxAge(9600)
        val userSessionAuthenticationToken = DefaultUserSessionAuthenticationToken("", "", token = principal.userSessionId.toString())

        bffAuthorizationCookieRepository.saveToken(userSessionAuthenticationToken, request, response)

        redirectStrategy.sendRedirect(request, response, "http://127.0.0.1:4001/actuator")
    }
}