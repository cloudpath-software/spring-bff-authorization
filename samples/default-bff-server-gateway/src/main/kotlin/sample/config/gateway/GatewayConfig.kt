package sample.config.gateway

import com.snapwise.security.bff.authorization.UserSessionService
import com.snapwise.security.gateway.filters.UserSessionGatewayFilterFactory
import com.snapwise.security.gateway.perdicates.UserSessionTokenValidatorPredicateFactory
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import sample.services.oauth2.OAuth2TokenRestService

@Configuration
class GatewayConfig {

    @Bean
    fun userSessionCookiePredicateFactory(
        oAuth2TokenRestService: OAuth2TokenRestService,
        userSessionService: UserSessionService
    ): UserSessionTokenValidatorPredicateFactory {
        return UserSessionTokenValidatorPredicateFactory(oAuth2TokenRestService, userSessionService)
    }

    @Bean
    fun userSessionHeaderFilterFactory(
        userSessionService: UserSessionService,
        oAuth2TokenRestService: OAuth2TokenRestService
    ): UserSessionGatewayFilterFactory {
        return UserSessionGatewayFilterFactory(oAuth2TokenRestService, userSessionService)
    }
}