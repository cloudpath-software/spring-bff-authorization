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

package com.snapwise.security.bff.authorization.oauth2.core

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.user.DefaultOAuth2User

class BffOAuth2User(
    authorities: Collection<GrantedAuthority>,
    attributes: Map<String, Any>,
    nameAttributeKey: String): DefaultOAuth2User(authorities, attributes, nameAttributeKey) {

    var accessToken: OAuth2AccessToken? = null
        private set

    var userSessionId: String? = null
        private set

    fun withAccessToken(accessToken: OAuth2AccessToken): BffOAuth2User {
        this.accessToken = accessToken
        return this
    }

    fun withUserSessionId(userSessionId: String): BffOAuth2User {
        this.userSessionId = userSessionId
        return this
    }
}