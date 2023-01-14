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
package com.snapwise.security.bff.authorization.web.authentication

import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.AuthenticationConverter
import java.util.*

/**
 * Attempts to extract an Access Token Request from [HttpServletRequest] for the Bff user session
 * and then converts it to an [UserSessionAuthenticationConverter] used for authenticating the user.
 *
 * @see AuthenticationConverter
 *
 * @see SessionInfoEndpointFilter
 */
class UserSessionAuthenticationConverter : AuthenticationConverter {
    override fun convert(request: HttpServletRequest): Authentication? {
        // session_id (REQUIRED)
        val sessionId = request.getParameter(SESSION_ID)
        if (SESSION_ID != sessionId) {
            return null
        }
        val principal = SecurityContextHolder.getContext().authentication

        return UserSessionAuthentication(principal, sessionId)
    }

    companion object {
       private const val SESSION_ID = "session_id"
    }
}