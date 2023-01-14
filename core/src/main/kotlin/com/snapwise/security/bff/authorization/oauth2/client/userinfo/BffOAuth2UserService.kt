package com.snapwise.security.bff.authorization.oauth2.client.userinfo

import com.snapwise.security.bff.authorization.UserSession
import com.snapwise.security.bff.authorization.UserSessionService
import com.snapwise.security.bff.authorization.oauth2.client.endpoint.BffOAuth2AccessTokenResponseHttpMessageConverter
import com.snapwise.security.bff.authorization.oauth2.core.BffOAuth2User
import org.springframework.core.ParameterizedTypeReference
import org.springframework.core.convert.converter.Converter
import org.springframework.http.RequestEntity
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.InternalAuthenticationServiceException
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2AuthorizationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority
import org.springframework.util.StringUtils
import org.springframework.web.client.RestClientException
import org.springframework.web.client.RestTemplate
import org.springframework.web.client.UnknownContentTypeException
import java.util.*

open class BffOAuth2UserService(private val userSessionService: UserSessionService): OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private val restOperations = RestTemplate()

    private val PARAMETERIZED_RESPONSE_TYPE: ParameterizedTypeReference<Map<String, Any>> =
        object : ParameterizedTypeReference<Map<String, Any>>() {}

    private val requestEntityConverter: Converter<OAuth2UserRequest, RequestEntity<*>> =
        OAuth2UserRequestEntityConverter()

    override fun loadUser(userRequest: OAuth2UserRequest): OAuth2User {
        return try {
            if (!StringUtils.hasText(userRequest.clientRegistration.providerDetails.userInfoEndpoint.uri)) {
                val oauth2Error = OAuth2Error(
                    MISSING_USER_INFO_URI_ERROR_CODE,
                    "Missing required UserInfo Uri in UserInfoEndpoint for Client Registration: "
                            + userRequest.clientRegistration.registrationId,
                    null
                )
                throw OAuth2AuthenticationException(oauth2Error, oauth2Error.toString())
            }
            val userNameAttributeName = userRequest.clientRegistration.providerDetails.userInfoEndpoint.userNameAttributeName
            if (!StringUtils.hasText(userNameAttributeName)) {
                val oauth2Error = OAuth2Error(
                    MISSING_USER_NAME_ATTRIBUTE_ERROR_CODE, (
                            "Missing required \"user name\" attribute name in UserInfoEndpoint for Client Registration: "
                                    + userRequest.clientRegistration.registrationId),
                    null
                )
                throw OAuth2AuthenticationException(oauth2Error, oauth2Error.toString())
            }
            val request = (requestEntityConverter.convert(userRequest))!!
            val response = getResponse(userRequest, request)
            val userAttributes = response.body!!
            val authorities: MutableSet<GrantedAuthority> = LinkedHashSet()
            authorities.add(OAuth2UserAuthority(userAttributes))
            val token = userRequest.accessToken

            /**
             * Injected by the [BffOAuth2AccessTokenResponseHttpMessageConverter].
             *
             * see [BffOAuth2AccessTokenResponseHttpMessageConverter] for an explanation.
             */
            val refreshToken = userRequest.additionalParameters.getValue(OAuth2ParameterNames.REFRESH_TOKEN) as String

            for (authority: String in token.scopes) {
                authorities.add(SimpleGrantedAuthority("SCOPE_$authority"))
            }

            val userId = userAttributes.getValue("sub") as String
            val resourceIds = userAttributes.getValue("aud") as List<*>
            val resourceId = resourceIds.first() as String

            val existingUserSession = userSessionService.findBy(userId, resourceId, token.scopes)

            val sessionId = existingUserSession?.sessionId ?: UUID.randomUUID().toString()

            val userSession = UserSession.Builder()
                .sessionId(sessionId)
                .userId(userId)
                .withResource(resourceId)
                .withScopes(token.scopes)
                .accessToken(userRequest.accessToken.tokenValue)
                .refreshToken(refreshToken)
                .build()

            userSessionService.save(userSession)

            val bffOAuth2User = BffOAuth2User(authorities, userAttributes, userNameAttributeName)
                .withUserSessionId(sessionId)
                .withAccessToken(userRequest.accessToken)

            bffOAuth2User
        } catch (ex: AuthenticationException) {
            throw InternalAuthenticationServiceException(ex.message, ex.cause)
        }
    }

    private fun getResponse(
        userRequest: OAuth2UserRequest,
        request: RequestEntity<*>
    ): ResponseEntity<Map<String, Any>> {
        return try {
            restOperations.exchange(request, PARAMETERIZED_RESPONSE_TYPE)
        } catch (ex: OAuth2AuthorizationException) {
            var oauth2Error = ex.error
            val errorDetails = StringBuilder()
            errorDetails.append("Error details: [")
            errorDetails.append("UserInfo Uri: ")
                .append(userRequest.clientRegistration.providerDetails.userInfoEndpoint.uri)
            errorDetails.append(", Error Code: ").append(oauth2Error.errorCode)
            if (oauth2Error.description != null) {
                errorDetails.append(", Error Description: ").append(oauth2Error.description)
            }
            errorDetails.append("]")
            oauth2Error = OAuth2Error(
                INVALID_USER_INFO_RESPONSE_ERROR_CODE,
                "An error occurred while attempting to retrieve the UserInfo Resource: $errorDetails",
                null
            )
            throw OAuth2AuthenticationException(oauth2Error, oauth2Error.toString(), ex)
        } catch (ex: UnknownContentTypeException) {
            val errorMessage = ("An error occurred while attempting to retrieve the UserInfo Resource from '"
                    + userRequest.clientRegistration.providerDetails.userInfoEndpoint.uri
                    + "': response contains invalid content type '" + ex.contentType.toString() + "'. "
                    + "The UserInfo Response should return a JSON object (content type 'application/json') "
                    + "that contains a collection of name and value pairs of the claims about the authenticated End-User. "
                    + "Please ensure the UserInfo Uri in UserInfoEndpoint for Client Registration '"
                    + userRequest.clientRegistration.registrationId + "' conforms to the UserInfo Endpoint, "
                    + "as defined in OpenID Connect 1.0: 'https://openid.net/specs/openid-connect-core-1_0.html#UserInfo'")
            val oauth2Error = OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE, errorMessage, null)
            throw OAuth2AuthenticationException(oauth2Error, oauth2Error.toString(), ex)
        } catch (ex: RestClientException) {
            val oauth2Error = OAuth2Error(
                INVALID_USER_INFO_RESPONSE_ERROR_CODE,
                "An error occurred while attempting to retrieve the UserInfo Resource: " + ex.message, null
            )
            throw OAuth2AuthenticationException(oauth2Error, oauth2Error.toString(), ex)
        }
    }

    companion object {
        private const val MISSING_USER_INFO_URI_ERROR_CODE = "missing_user_info_uri"
        private const val MISSING_USER_NAME_ATTRIBUTE_ERROR_CODE = "missing_user_name_attribute"
        private const val INVALID_USER_INFO_RESPONSE_ERROR_CODE = "invalid_user_info_response"
    }
}