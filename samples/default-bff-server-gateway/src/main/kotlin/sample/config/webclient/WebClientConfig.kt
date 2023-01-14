package sample.config.webclient

import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties
import org.springframework.cloud.client.loadbalancer.LoadBalanced
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.reactive.function.client.WebClient

@Configuration
class WebClientConfig(
    private val oAuth2ClientProperties: OAuth2ClientProperties
) {
    @Bean
    @LoadBalanced
    fun webClientBuilder(): WebClient.Builder {

        val sampleProvider = oAuth2ClientProperties.registration.getValue("sample")

        return WebClient.builder()
            .defaultHeaders {
                it.setBasicAuth(sampleProvider.clientId, sampleProvider.clientSecret)
            }
    }
}