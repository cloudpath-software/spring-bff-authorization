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
package com.snapwise.security.bff.authorization.oauth2.services

import reactor.core.publisher.Mono

/**
 * Implementations of this interface are responsible for the management
 * of [bff user sessions][OAuth2TokenService].
 *
 * @since 0.0.1
 * @see OAuth2TokenService
 */
interface OAuth2TokenService {
    fun introspectToken(token: String): Mono<LinkedHashMap<*,*>>

    fun getAccessTokenWithRefresh(refreshToken: String): Mono<LinkedHashMap<*,*>>
}