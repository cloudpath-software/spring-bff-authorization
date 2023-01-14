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

package com.snapwise.security.bff.authorization.utils

import org.springframework.http.HttpCookie
import org.springframework.http.ResponseCookie
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.lang.Nullable

object ReactiveWebUtils {

    /**
     * Retrieve the first cookie with the given name. Note that multiple
     * cookies can have the same name but different paths or domains.
     * @param request current servlet request
     * @param name cookie name
     * @return the first cookie with the given name, or `null` if none is found
     */
    @Nullable
    fun getResponseCookie(request: ServerHttpRequest, name: String): ResponseCookie? {
        if(request.cookies.contains(name).not()) {
            return null
        }

        return request.cookies.getFirst(name) as ResponseCookie
    }

    /**
     * Retrieve the first cookie with the given name. Note that multiple
     * cookies can have the same name but different paths or domains.
     * @param request current servlet request
     * @param name cookie name
     * @return the first cookie with the given name, or `null` if none is found
     */
    @Nullable
    fun getHttpCookie(request: ServerHttpRequest, name: String): HttpCookie? {
        if(request.cookies.contains(name).not()) {
            return null
        }

        return request.cookies.getFirst(name) as HttpCookie
    }
}