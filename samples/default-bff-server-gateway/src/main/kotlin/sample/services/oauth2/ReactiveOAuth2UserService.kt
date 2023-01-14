/*
 *
 *  * Copyright 2023 the original author or authors.
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

package sample.services.oauth2

import com.snapwise.security.bff.authorization.UserSessionService
import com.snapwise.security.bff.authorization.oauth2.client.userinfo.BffOReactiveAuth2UserService
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono
import java.util.logging.Logger

@Service
class ReactiveOAuth2UserService(
    userSessionService: UserSessionService
): BffOReactiveAuth2UserService(userSessionService) {

    private val logger = Logger.getLogger(ReactiveOAuth2UserService::class.java.name)

    override fun loadUser(userRequest: OAuth2UserRequest): Mono<OAuth2User> {
        return super.loadUser(userRequest).map {
            logger.info("loaded oauth2 user -> $it")

            it
        }
    }
}