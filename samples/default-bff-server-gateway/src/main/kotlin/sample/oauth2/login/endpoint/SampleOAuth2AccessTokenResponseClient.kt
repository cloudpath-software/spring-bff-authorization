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

package sample.oauth2.login.endpoint

import com.snapwise.security.bff.authorization.oauth2.client.endpoint.BffOAuth2AccessTokenResponseClient
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse
import org.springframework.stereotype.Component
import java.util.logging.Logger

@Component
class SampleOAuth2AccessTokenResponseClient: BffOAuth2AccessTokenResponseClient() {

    private val logger = Logger.getLogger(SampleOAuth2AccessTokenResponseClient::class.java.name)
    override fun getTokenResponse(authorizationCodeGrantRequest: OAuth2AuthorizationCodeGrantRequest): OAuth2AccessTokenResponse? {
        val tokenResponse = super.getTokenResponse(authorizationCodeGrantRequest)

        logger.info("tokenResponse: $tokenResponse")

        return tokenResponse
    }
}