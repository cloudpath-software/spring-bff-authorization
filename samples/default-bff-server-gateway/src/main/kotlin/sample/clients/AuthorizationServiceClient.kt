package sample.clients

import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.BodyInserters
import org.springframework.web.reactive.function.client.WebClient
import reactor.core.publisher.Mono

@Component
class AuthorizationServiceClient(
    webClientBuilder: WebClient.Builder,
) {

    private val webClient: WebClient

    init {
        this.webClient = webClientBuilder.build()
    }

    fun getOAuth2TokenByClientCredentials(): Mono<Any> {
        return webClient.post()
            .uri("/oauth2/token")
            .body(BodyInserters.fromFormData("grant_type", "client_credentials"))
            .retrieve().bodyToMono(Any::class.java)
    }

    fun introspectToken(token: String): Mono<LinkedHashMap<*, *>> {
        return webClient.post()
            .uri { uriBuilder ->
                uriBuilder.path("/oauth2/introspect")
                    .queryParam("token", token)
                    .build()
            }
            .retrieve().bodyToMono(LinkedHashMap::class.java)
    }

    fun getAccessTokenWithRefresh(token: String): Mono<Any> {
        return webClient.post()
            .uri("/oauth2/token")
            .body(
                BodyInserters
                .fromFormData("grant_type", "refresh_token")
                .with("refresh_token",token)
            )
            .retrieve().bodyToMono(Any::class.java)
    }
}