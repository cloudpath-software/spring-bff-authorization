package sample.services.oauth2

import com.snapwise.security.bff.authorization.oauth2.services.OAuth2TokenService
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono
import sample.clients.AuthorizationServiceClient

@Service
class OAuth2TokenRestService(
    private val authorizationServiceClient: AuthorizationServiceClient
): OAuth2TokenService {
    override fun getAccessTokenWithRefresh(refreshToken: String): Mono<LinkedHashMap<*,*>> {
        return authorizationServiceClient
            .getAccessTokenWithRefresh(refreshToken)
            .cast(LinkedHashMap::class.java)
    }

    override fun introspectToken(token: String): Mono<LinkedHashMap<*,*>> {
        return authorizationServiceClient
            .introspectToken(token)
            .cast(LinkedHashMap::class.java)
    }
}