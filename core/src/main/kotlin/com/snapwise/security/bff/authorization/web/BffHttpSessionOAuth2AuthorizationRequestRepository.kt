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
package com.snapwise.security.bff.authorization.web

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.util.Assert

/**
 * An implementation of an [AuthorizationRequestRepository] that stores
 * [OAuth2AuthorizationRequest] in the `HttpSession`.
 *
 * @see AuthorizationRequestRepository
 * @see OAuth2AuthorizationRequest
 */
open class BffHttpSessionOAuth2AuthorizationRequestRepository: AuthorizationRequestRepository<OAuth2AuthorizationRequest?> {
    private val sessionAttributeName = DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME

    override fun loadAuthorizationRequest(request: HttpServletRequest): OAuth2AuthorizationRequest? {
        val stateParameter = getStateParameter(request)
        val authorizationRequest = getAuthorizationRequest(request)
        return if (authorizationRequest != null && stateParameter == authorizationRequest.state) authorizationRequest else null
    }

    override fun saveAuthorizationRequest(
        authorizationRequest: OAuth2AuthorizationRequest?, request: HttpServletRequest,
        response: HttpServletResponse
    ) {
        if (authorizationRequest == null) {
            removeAuthorizationRequest(request, response)
            return
        }
        val state = authorizationRequest.state
        Assert.hasText(state, "authorizationRequest.state cannot be empty")
        request.session.setAttribute(sessionAttributeName, authorizationRequest)
    }

    override fun removeAuthorizationRequest(
        request: HttpServletRequest,
        response: HttpServletResponse
    ): OAuth2AuthorizationRequest? {
        val authorizationRequest = loadAuthorizationRequest(request)

        if (authorizationRequest != null) {
            request.session.removeAttribute(sessionAttributeName)
        }
        return authorizationRequest
    }

    /**
     * Gets the state parameter from the [HttpServletRequest]
     * @param request the request to use
     * @return the state parameter or null if not found
     */
    private fun getStateParameter(request: HttpServletRequest): String {
        return request.getParameter(OAuth2ParameterNames.STATE)
    }

    private fun getAuthorizationRequest(request: HttpServletRequest): OAuth2AuthorizationRequest? {
        val session = request.getSession(false)
        return if (session != null) session.getAttribute(sessionAttributeName) as OAuth2AuthorizationRequest else null
    }

    companion object {
        private val DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME =
            BffHttpSessionOAuth2AuthorizationRequestRepository::class.java
                .name + ".AUTHORIZATION_REQUEST"
    }
}