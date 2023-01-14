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

package com.snapwise.security.bff.authorization.authentication

import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.server.authorization.context.Context
import java.util.function.Consumer

/**
 * A context that holds an [Authentication] and (optionally) additional information
 * and is used in an [AuthenticationProvider].
 *
 * @see Context
 */
interface BffAuthenticationContext : Context {
    /**
     * Returns the [Authentication] associated to the context.
     *
     * @param <T> the type of the `Authentication`
     * @return the [Authentication]
    </T> */
    fun <T : Authentication> getAuthentication(): T {
        return get(Authentication::class.java) as T
    }

    /**
     * A builder for subclasses of [BffAuthenticationContext].
     *
     * @param <T> the type of the authentication context
     * @param <B> the type of the builder
    </B></T> */
    abstract class AbstractBuilder<T : BffAuthenticationContext, B : AbstractBuilder<T, B>> protected constructor(
        authentication: Authentication
    ) {
        protected val context: MutableMap<Any, Any> = HashMap()

        init {
            put(Authentication::class.java, authentication)
        }

        /**
         * Associates an attribute.
         *
         * @param key the key for the attribute
         * @param value the value of the attribute
         * @return the [AbstractBuilder] for further configuration
         */
        fun put(key: Any, value: Any): B {
            context[key] = value
            return `this`
        }

        /**
         * A `Consumer` of the attributes `Map`
         * allowing the ability to add, replace, or remove.
         *
         * @param contextConsumer a [Consumer] of the attributes `Map`
         * @return the [AbstractBuilder] for further configuration
         */
        fun context(contextConsumer: Consumer<Map<Any, Any>>): B {
            contextConsumer.accept(context)
            return `this`
        }

        protected operator fun <V> get(key: Any): V? {
            return context[key] as V?
        }

        protected val `this`: B
            protected get() = this as B

        /**
         * Builds a new [BffAuthenticationContext].
         *
         * @return the [BffAuthenticationContext]
         */
        abstract fun build(): T
    }
}