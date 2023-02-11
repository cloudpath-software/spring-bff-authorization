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

package com.snapwise.bffauthorizationspa.annotation.reactive.configuration

import com.snapwise.bffauthorizationspa.annotation.reactive.specs.FormLoginSpec
import com.snapwise.security.bff.authorization.config.annotation.reactive.configurers.CoreServerHttpSecurityConfigurer
import com.snapwise.security.bff.authorization.config.annotation.reactive.specs.AbstractBffServerSpec
import com.snapwise.security.bff.authorization.config.annotation.reactive.specs.SessionInfoSpec
import org.springframework.security.config.Customizer
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.util.matcher.OrServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher

class SpaServerHttpSecurityConfigurer(private val httpSecurity: ServerHttpSecurity): CoreServerHttpSecurityConfigurer(httpSecurity) {

    private var formLogin: FormLoginSpec = FormLoginSpec(this)


    fun formLogin(): FormLoginSpec {
        return this.formLogin
    }

    /**
     * Configures the bff session info.
     * @param customizer the [Customizer] to provide more options for the
     * [SessionInfoSpec]
     * @return the [SpaServerHttpSecurityConfigurer] to customize
     */
    fun formLogin(customizer: Customizer<FormLoginSpec>): SpaServerHttpSecurityConfigurer {
        customizer.customize(this.formLogin)
        return this
    }

    /**
     * Creates a new instance.
     * @return the new [SpaServerHttpSecurityConfigurer] instance
     */
    override fun http(): SpaServerHttpSecurityConfigurer {
        return SpaServerHttpSecurityConfigurer(httpSecurity)
    }
}