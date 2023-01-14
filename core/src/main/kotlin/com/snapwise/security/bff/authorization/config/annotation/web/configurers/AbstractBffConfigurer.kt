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
package com.snapwise.security.bff.authorization.config.annotation.web.configurers

import org.springframework.security.config.annotation.ObjectPostProcessor
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.util.matcher.RequestMatcher

/**
 * Base configurer for a Bff authorization component (e.g. login endpoint).
 *
 * @since 0.0.1
 */
abstract class AbstractBffConfigurer(private val objectPostProcessor: ObjectPostProcessor<Any>) {

    abstract fun init(httpSecurity: HttpSecurity)
    abstract fun configure(httpSecurity: HttpSecurity)
    abstract val requestMatcher: RequestMatcher
    protected fun <T> postProcess(process: T): T {
        return objectPostProcessor.postProcess(process) as T
    }
}