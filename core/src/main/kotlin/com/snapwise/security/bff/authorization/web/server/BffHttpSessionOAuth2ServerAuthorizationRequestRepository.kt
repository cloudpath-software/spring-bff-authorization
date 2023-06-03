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
package com.snapwise.security.bff.authorization.web.server

import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository
import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.util.Assert
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import reactor.core.scheduler.Schedulers

/**
 * An implementation of an [AuthorizationRequestRepository] that stores
 * [OAuth2AuthorizationRequest] in the `HttpSession`.
 *
 * @see AuthorizationRequestRepository
 * @see OAuth2AuthorizationRequest
 */
open class BffHttpSessionOAuth2ServerAuthorizationRequestRepository: ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest?> {
    private val sessionAttributeName = DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME

    /**
     * Gets the state parameter from the [ServerWebExchange]
     * @param exchange the request to use
     * @return the state parameter or null if not found
     */
    private fun getStateParameter(exchange: ServerWebExchange): String {
        return exchange.request.queryParams.getValue(OAuth2ParameterNames.STATE).first()
    }

    private fun getAuthorizationRequest(exchange: ServerWebExchange): Mono<OAuth2AuthorizationRequest?> {
        return exchange.session.mapNotNull { session ->
            session.getAttribute<OAuth2AuthorizationRequest>(sessionAttributeName)
        }
    }

    companion object {
        private val DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME =
            BffHttpSessionOAuth2ServerAuthorizationRequestRepository::class.java
                .name + ".AUTHORIZATION_REQUEST"
    }

    override fun loadAuthorizationRequest(exchange: ServerWebExchange): Mono<OAuth2AuthorizationRequest?> {
        val stateParameter = getStateParameter(exchange)
        return getAuthorizationRequest(exchange).mapNotNull { authorizationRequest ->
            if (authorizationRequest != null && stateParameter == authorizationRequest.state) authorizationRequest else null
        }
    }

    override fun removeAuthorizationRequest(exchange: ServerWebExchange): Mono<OAuth2AuthorizationRequest?> {
        return loadAuthorizationRequest(exchange).flatMap { authorizationRequest ->
            exchange.session.mapNotNull {
                it.attributes.remove(sessionAttributeName)
            }.mapNotNull {
                authorizationRequest
            }
        }
    }

    override fun saveAuthorizationRequest(
        authorizationRequest: OAuth2AuthorizationRequest?,
        exchange: ServerWebExchange
    ): Mono<Void> {
        if(authorizationRequest == null) {
            return removeAuthorizationRequest(exchange).then().ignoreElement()
        }

        return Mono.just(authorizationRequest).publishOn(Schedulers.boundedElastic()).flatMap {
            val state = authorizationRequest.state
            Assert.hasText(state, "authorizationRequest.state cannot be empty")
            exchange.session.flatMap {
                it.attributes[sessionAttributeName] = authorizationRequest
                it.save()
            }
        }
    }
}