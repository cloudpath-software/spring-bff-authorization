package sample.services.oauth2

import com.snapwise.security.bff.authorization.oauth2.services.SessionOAuth2TokenService
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono
import sample.clients.AuthorizationServiceClient

@Service
class SessionOAuth2TokenRestService(
    private val authorizationServiceClient: AuthorizationServiceClient
): SessionOAuth2TokenService {
    override fun refreshSessionAccessToken(sessionId: String): Mono<String> {
        return authorizationServiceClient
            .getAccessTokenWithRefresh(sessionId)
            .cast(String::class.java)
    }

    override fun introspectToken(token: String): Mono<LinkedHashMap<*,*>> {
        return authorizationServiceClient
            .introspectToken(token)
            .cast(LinkedHashMap::class.java)
    }
}