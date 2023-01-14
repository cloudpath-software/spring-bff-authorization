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
package com.snapwise.security.bff.authorization

import org.springframework.lang.NonNull
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.util.CollectionUtils
import java.io.Serializable
import java.util.*
import java.util.function.Consumer

/**
 * A representation of an OAuth 2.0 "consent" to an Authorization request, which holds state related to the
 * set of [authorities][.getAuthorities] granted to a [client][.getRegisteredClientId] by the
 * [resource owner][.getPrincipalName].
 *
 *
 * When authorizing access for a given client, the resource owner may only grant a subset of the authorities
 * the client requested. The typical use-case is the `authorization_code` flow, in which the client
 * requests a set of `scope`s. The resource owner then selects which scopes they grant to the client.
 *
 * @author Daniel Garnier-Moiroux
 * @since 0.1.2
 */
class AuthorizationLogin private constructor(
    /**
     * Returns the identifier for the [registered client][RegisteredClient.getId].
     *
     * @return the [RegisteredClient.getId]
     */
    val registeredClientId: String,
    /**
     * Returns the `Principal` name of the resource owner (or client).
     *
     * @return the `Principal` name of the resource owner (or client)
     */
    val principalName: String, authorities: Set<GrantedAuthority>
) : Serializable {
    private val authorities: Set<GrantedAuthority>

    init {
        this.authorities = Collections.unmodifiableSet(authorities)
    }

    /**
     * Returns the [authorities][GrantedAuthority] granted to the client by the principal.
     *
     * @return the [authorities][GrantedAuthority] granted to the client by the principal.
     */
    fun getAuthorities(): Set<GrantedAuthority> {
        return authorities
    }

    val scopes: Set<String>
        /**
         * Convenience method for obtaining the `scope`s granted to the client by the principal,
         * extracted from the [authorities][.getAuthorities].
         *
         * @return the `scope`s granted to the client by the principal.
         */
        get() {
            val authorities: MutableSet<String> = HashSet()
            for (authority in getAuthorities()) {
                if (authority.getAuthority().startsWith(com.snapwise.security.bff.authorization.AuthorizationLogin.Companion.AUTHORITIES_SCOPE_PREFIX)) {
                    authorities.add(authority.getAuthority().replaceFirst(com.snapwise.security.bff.authorization.AuthorizationLogin.Companion.AUTHORITIES_SCOPE_PREFIX, ""))
                }
            }
            return authorities
        }

    override fun equals(obj: Any?): Boolean {
        if (this === obj) {
            return true
        }
        if (obj == null || javaClass != obj.javaClass) {
            return false
        }
        val that = obj as com.snapwise.security.bff.authorization.AuthorizationLogin
        return registeredClientId == that.registeredClientId && principalName == that.principalName && authorities == that.authorities
    }

    override fun hashCode(): Int {
        return Objects.hash(registeredClientId, principalName, authorities)
    }

    /**
     * A builder for [AuthorizationLogin].
     */
    class Builder(
        private val registeredClientId: String,
        private val principalName: String,
        authorities: Set<GrantedAuthority> = emptySet<GrantedAuthority>()
    ) : Serializable {
        private val authorities: MutableSet<GrantedAuthority> = HashSet<GrantedAuthority>()

        init {
            if (!CollectionUtils.isEmpty(authorities)) {
                this.authorities.addAll(authorities)
            }
        }

        /**
         * Adds a scope to the collection of `authorities` in the resulting [AuthorizationLogin],
         * wrapping it in a [SimpleGrantedAuthority], prefixed by `SCOPE_`. For example, a
         * `message.write` scope would be stored as `SCOPE_message.write`.
         *
         * @param scope the scope
         * @return the `Builder` for further configuration
         */
        fun scope(scope: String): com.snapwise.security.bff.authorization.AuthorizationLogin.Builder {
            authority(SimpleGrantedAuthority(com.snapwise.security.bff.authorization.AuthorizationLogin.Companion.AUTHORITIES_SCOPE_PREFIX + scope))
            return this
        }

        /**
         * Adds a [GrantedAuthority] to the collection of `authorities` in the
         * resulting [AuthorizationLogin].
         *
         * @param authority the [GrantedAuthority]
         * @return the `Builder` for further configuration
         */
        fun authority(authority: GrantedAuthority): com.snapwise.security.bff.authorization.AuthorizationLogin.Builder {
            authorities.add(authority)
            return this
        }

        /**
         * A `Consumer` of the `authorities`, allowing the ability to add, replace or remove.
         *
         * @param authoritiesConsumer a `Consumer` of the `authorities`
         * @return the `Builder` for further configuration
         */
        fun authorities(authoritiesConsumer: Consumer<Set<GrantedAuthority>?>): com.snapwise.security.bff.authorization.AuthorizationLogin.Builder {
            authoritiesConsumer.accept(authorities)
            return this
        }

        /**
         * Validate the authorities and build the [AuthorizationLogin].
         * There must be at least one [GrantedAuthority].
         *
         * @return the [AuthorizationLogin]
         */
        fun build(): com.snapwise.security.bff.authorization.AuthorizationLogin {
            return com.snapwise.security.bff.authorization.AuthorizationLogin(
                registeredClientId,
                principalName,
                authorities
            )
        }
    }

    companion object {
        private const val AUTHORITIES_SCOPE_PREFIX = "SCOPE_"

        /**
         * Returns a new [Builder], initialized with the values from the provided `OAuth2AuthorizationConsent`.
         *
         * @param authorizationConsent the `OAuth2AuthorizationConsent` used for initializing the [Builder]
         * @return the [Builder]
         */
        fun from(authorizationConsent: com.snapwise.security.bff.authorization.AuthorizationLogin): com.snapwise.security.bff.authorization.AuthorizationLogin.Builder {
            return com.snapwise.security.bff.authorization.AuthorizationLogin.Builder(
                authorizationConsent.registeredClientId,
                authorizationConsent.principalName,
                authorizationConsent.getAuthorities()
            )
        }

        /**
         * Returns a new [Builder], initialized with the given [registeredClientId][RegisteredClient.getClientId]
         * and `Principal` name.
         *
         * @param registeredClientId the [RegisteredClient.getId]
         * @param principalName the  `Principal` name
         * @return the [Builder]
         */
        fun withId(@NonNull registeredClientId: String, @NonNull principalName: String): com.snapwise.security.bff.authorization.AuthorizationLogin.Builder {
            if(registeredClientId.isEmpty()) throw Exception("registeredClientId cannot be empty")
            if(principalName.isEmpty()) throw Exception("principalName cannot be empty")
            return com.snapwise.security.bff.authorization.AuthorizationLogin.Builder(registeredClientId, principalName)
        }
    }
}