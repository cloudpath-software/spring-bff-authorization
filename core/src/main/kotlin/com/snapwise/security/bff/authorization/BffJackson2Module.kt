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
package com.snapwise.security.bff.authorization

import com.fasterxml.jackson.core.Version
import com.fasterxml.jackson.databind.module.SimpleModule
import org.springframework.security.jackson2.SecurityJackson2Modules
import org.springframework.security.oauth2.server.authorization.jackson2.*

/**
 * Jackson `Module` for `spring-authorization-server`, that registers the
 * following mix-in annotations:
 *
 *
 *  * [UnmodifiableMapMixin]
 *  * [HashSetMixin]
 *  * [OAuth2AuthorizationRequestMixin]
 *  * [DurationMixin]
 *  * [JwsAlgorithmMixin]
 *  * [OAuth2TokenFormatMixin]
 *
 *
 * If not already enabled, default typing will be automatically enabled as type info is
 * required to properly serialize/deserialize objects. In order to use this module just
 * add it to your `ObjectMapper` configuration.
 *
 * <pre>
 * ObjectMapper mapper = new ObjectMapper();
 * mapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
</pre> *
 *
 * **NOTE:** Use [SecurityJackson2Modules.getModules] to get a list
 * of all security modules.
 *
 * @since 0.0.1
 * @see SecurityJackson2Modules
 *
 * @see UnmodifiableMapMixin
 *
 * @see HashSetMixin
 *
 * @see OAuth2AuthorizationRequestMixin
 *
 * @see DurationMixin
 *
 * @see JwsAlgorithmMixin
 *
 * @see OAuth2TokenFormatMixin
 */
class BffJackson2Module : SimpleModule(
    BffJackson2Module::class.java.name, Version(0, 0, 1, null, null, null)
) {
    override fun setupModule(context: SetupContext) {
        SecurityJackson2Modules.enableDefaultTyping(context.getOwner())
//        context.setMixInAnnotations(
//            Collections.unmodifiableMap(emptyMap<Any, Any>()).javaClass,
//            UnmodifiableMapMixin::class.java
//        )
//        context.setMixInAnnotations(HashSet::class.java, HashSetMixin::class.java)
//        context.setMixInAnnotations(LinkedHashSet::class.java, HashSetMixin::class.java)
//        context.setMixInAnnotations(OAuth2AuthorizationRequest::class.java, OAuth2AuthorizationRequestMixin::class.java)
//        context.setMixInAnnotations(Duration::class.java, DurationMixin::class.java)
//        context.setMixInAnnotations(
//            SignatureAlgorithm::class.java,
//            JwsAlgorithmMixin::class.java
//        )
//        context.setMixInAnnotations(
//            MacAlgorithm::class.java,
//            JwsAlgorithmMixin::class.java
//        )
//        context.setMixInAnnotations(OAuth2TokenFormat::class.java, OAuth2TokenFormatMixin::class.java)
    }
}