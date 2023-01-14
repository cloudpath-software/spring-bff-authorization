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
package com.snapwise.security.bff.authorization.settings

import java.io.Serializable
import java.util.*
import java.util.function.Consumer

/**
 * Base implementation for configuration settings.
 *
 * @since 0.0.1
 */
abstract class AbstractSettings protected constructor(
    /**
     * Returns a `Map` of the configuration settings.
     *
     * @return a `Map` of the configuration settings
     */
    open val settings: Map<String, Any>
) : Serializable {

    /**
     * Returns a configuration setting.
     *
     * @param name the name of the setting
     * @param <T> the type of the setting
     * @return the value of the setting, or `null` if not available
    </T> */
    fun <T> getSetting(name: String): T {
        if(name.isEmpty()) { throw Exception("name cannot be empty") }
        return settings.getValue(name) as T
    }

    override fun equals(obj: Any?): Boolean {
        if (this === obj) {
            return true
        }
        if (obj == null || javaClass != obj.javaClass) {
            return false
        }
        val that = obj as AbstractSettings
        return settings == that.settings
    }

    override fun hashCode(): Int {
        return Objects.hash(settings)
    }

    override fun toString(): String {
        return "AbstractSettings {" +
                "settings=" + settings +
                '}'
    }

    /**
     * A builder for subclasses of [AbstractSettings].
     */
    abstract class AbstractBuilder<T : AbstractSettings?, B : AbstractBuilder<T, B>?> protected constructor() {
        protected val settings: MutableMap<String, Any> = HashMap()

        /**
         * Sets a configuration setting.
         *
         * @param name the name of the setting
         * @param value the value of the setting
         * @return the [AbstractBuilder] for further configuration
         */
        fun setting(name: String, value: Any): B {
            settings[name] = value
            return `this`
        }

        /**
         * A `Consumer` of the configuration settings `Map`
         * allowing the ability to add, replace, or remove.
         *
         * @param settingsConsumer a [Consumer] of the configuration settings `Map`
         * @return the [AbstractBuilder] for further configuration
         */
        fun settings(settingsConsumer: Consumer<Map<String, Any>>): B {
            settingsConsumer.accept(settings)
            return `this`
        }

        abstract fun build(): T
        protected val `this`: B
            protected get() = this as B
    }
}