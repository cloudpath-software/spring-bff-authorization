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

package sample.oauth2.login.authorization

import com.snapwise.security.bff.authorization.web.BffHttpSessionOAuth2AuthorizationRequestRepository
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.stereotype.Component

@Component
class SampleHttpSessionOAuth2AuthorizationRequestRepository: BffHttpSessionOAuth2AuthorizationRequestRepository() {

    private val logger = LoggerFactory.getLogger(javaClass)

    override fun loadAuthorizationRequest(request: HttpServletRequest): OAuth2AuthorizationRequest? {
        val authorization = super.loadAuthorizationRequest(request)

        logger.info("loadAuthorizationRequest authorization: $authorization")

        return authorization
    }

    override fun saveAuthorizationRequest(
        authorizationRequest: OAuth2AuthorizationRequest?,
        request: HttpServletRequest,
        response: HttpServletResponse
    ) {
        super.saveAuthorizationRequest(authorizationRequest, request, response)
        logger.info("saveAuthorizationRequest authorizationRequest: $authorizationRequest")
    }

    override fun removeAuthorizationRequest(
        request: HttpServletRequest,
        response: HttpServletResponse
    ): OAuth2AuthorizationRequest? {
        val authorizationRequest = super.removeAuthorizationRequest(request, response)

        logger.info("removeAuthorizationRequest authorizationRequest: $authorizationRequest")

        return authorizationRequest
    }
}