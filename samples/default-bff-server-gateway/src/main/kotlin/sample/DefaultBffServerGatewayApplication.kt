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

package sample

import com.snapwise.security.gateway.filters.UserSessionGatewayFilterFactory
import com.snapwise.security.gateway.perdicates.UserSessionTokenValidatorPredicateFactory
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig
import io.github.resilience4j.timelimiter.TimeLimiterConfig
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.cloud.circuitbreaker.resilience4j.ReactiveResilience4JCircuitBreakerFactory
import org.springframework.cloud.circuitbreaker.resilience4j.Resilience4JConfigBuilder
import org.springframework.cloud.client.circuitbreaker.Customizer
import org.springframework.cloud.gateway.filter.factory.RetryGatewayFilterFactory
import org.springframework.cloud.gateway.handler.predicate.CookieRoutePredicateFactory
import org.springframework.cloud.gateway.handler.predicate.PathRoutePredicateFactory
import org.springframework.cloud.gateway.route.RouteLocator
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder
import org.springframework.context.annotation.Bean
import java.time.Duration

@SpringBootApplication
class DefaultBffServerGatewayApplication {

    @Bean
    fun routeLocator(
        builder: RouteLocatorBuilder,
        userSessionPredicateFactory: UserSessionTokenValidatorPredicateFactory,
        userSessionGatewayFilterFactory: UserSessionGatewayFilterFactory,
        cookieRoutePredicateFactory: CookieRoutePredicateFactory,
        pathRoutePredicateFactory: PathRoutePredicateFactory
    ): RouteLocator {
        return builder.routes()
            .route("sample-webflux-service") { r ->
                r.host("127.0.0.1:9002").and()
                    .predicate(
                        pathRoutePredicateFactory.apply(
                            PathRoutePredicateFactory.Config()
                                .setPatterns(listOf("/sample-webflux/**"))
                        )
                    ).filters { f ->
                        f.rewritePath("/sample-webflux/?(?<segment>.*)", "/\${segment}")
                        f.filter(
                            userSessionGatewayFilterFactory.apply(
                                UserSessionGatewayFilterFactory.Config()
                            )
                        )
                        f.retry { r ->
                            r.backoff = RetryGatewayFilterFactory.BackoffConfig(Duration.ofMillis(50), Duration.ofMillis(500), 2, true)
                        }
                        f.circuitBreaker { c ->
                            c.name = "sample-webflux-service"
                        }
                    }.uri("http://localhost:9001")
            }.build()
    }

    @Bean
    fun defaultCustomizer(): Customizer<ReactiveResilience4JCircuitBreakerFactory> {
        return Customizer<ReactiveResilience4JCircuitBreakerFactory> { factory ->
            factory.configureDefault { id ->
                Resilience4JConfigBuilder(id)
                    .circuitBreakerConfig(CircuitBreakerConfig.ofDefaults())
                    .timeLimiterConfig(TimeLimiterConfig.custom().timeoutDuration(Duration.ofSeconds(5)).build())
                    .build()
            }
        }
    }
}

fun main(args: Array<String>) {
    runApplication<DefaultBffServerGatewayApplication>(*args)
}
