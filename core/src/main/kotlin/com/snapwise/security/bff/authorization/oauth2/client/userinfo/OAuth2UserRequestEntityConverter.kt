package com.snapwise.security.bff.authorization.oauth2.client.userinfo

import org.springframework.core.convert.converter.Converter
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.http.MediaType
import org.springframework.http.RequestEntity
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.core.AuthenticationMethod
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.web.util.UriComponentsBuilder


/**
 * A [Converter] that converts the provided [OAuth2UserRequest] to a
 * [RequestEntity] representation of a request for the UserInfo Endpoint.
 *
 * Resolves an issue with the OAuth2Introspect method execution.
 * The new authorization server implementation expects a Post request
 * with the token added as a request uri param.
 *
 * @see Converter
 * @see OAuth2UserRequest
 * @see RequestEntity
 *
 */
class OAuth2UserRequestEntityConverter : Converter<OAuth2UserRequest, RequestEntity<*>> {
    /**
     * Returns the [RequestEntity] used for the UserInfo Request.
     * @param userRequest the user request
     * @return the [RequestEntity] used for the UserInfo Request
     */
    override fun convert(userRequest: OAuth2UserRequest): RequestEntity<*> {
        val clientRegistration = userRequest.clientRegistration
        val httpMethod = getHttpMethod(clientRegistration)
        val headers = getHeaders(clientRegistration)
        val uri = UriComponentsBuilder.fromUriString(clientRegistration.providerDetails.userInfoEndpoint.uri)

        val request: RequestEntity<*>
        if (HttpMethod.POST.equals(httpMethod)) {
            uri.queryParam(OAuth2ParameterNames.TOKEN, userRequest.accessToken.tokenValue)

            request = RequestEntity<Any>(headers, httpMethod, uri.build().toUri())
        } else {
            headers.setBearerAuth(userRequest.accessToken.tokenValue)
            request = RequestEntity<Any>(headers, httpMethod, uri.build().toUri())
        }
        return request
    }

    private fun getHttpMethod(clientRegistration: ClientRegistration): HttpMethod {
        return if (AuthenticationMethod.FORM
            == clientRegistration.providerDetails.userInfoEndpoint.authenticationMethod
        ) {
            HttpMethod.POST
        } else HttpMethod.GET
    }

    private fun getHeaders(clientRegistration: ClientRegistration): HttpHeaders {
        val headers = HttpHeaders()
        headers.accept = listOf(MediaType.APPLICATION_JSON)

        return when(clientRegistration.clientAuthenticationMethod) {
            ClientAuthenticationMethod.CLIENT_SECRET_BASIC -> {
                val clientId = clientRegistration.clientId
                val clientSecret = clientRegistration.clientSecret

                headers.setBasicAuth(clientId, clientSecret)
                headers
            }
            ClientAuthenticationMethod.NONE -> {
                headers
            }
            else -> headers
        }
    }

    companion object {
        private val DEFAULT_CONTENT_TYPE = MediaType
            .valueOf(MediaType.APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8")
    }
}