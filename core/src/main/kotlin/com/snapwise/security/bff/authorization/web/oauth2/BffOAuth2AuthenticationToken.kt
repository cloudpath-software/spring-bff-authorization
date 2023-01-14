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
package com.snapwise.security.bff.authorization.web.oauth2

import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.user.OAuth2User

/**
 * An implementation of an [AbstractAuthenticationToken] that represents an OAuth
 * 2.0 [Authentication].
 *
 *
 * The [Authentication] associates an [OAuth2User] `Principal` to the
 * identifier of the [Authorized Client][.getAuthorizedClientRegistrationId], which
 * the End-User (`Principal`) granted authorization to so that it can access it's
 * protected resources at the UserInfo Endpoint.
 *
 * @see AbstractAuthenticationToken
 *
 * @see OAuth2User
 *
 * @see OAuth2AuthorizedClient
 */
class BffOAuth2AuthenticationToken(
    principal: OAuth2User, authorities: Collection<GrantedAuthority>,
    authorizedClientRegistrationId: String?
) : OAuth2AuthenticationToken(principal, authorities, authorizedClientRegistrationId) {

    val userSessionId: String
        get() {
           return "userSessionId"
        }

}