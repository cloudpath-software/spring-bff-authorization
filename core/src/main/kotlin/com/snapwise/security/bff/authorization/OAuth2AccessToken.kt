package com.snapwise.security.bff.authorization

import com.fasterxml.jackson.annotation.JsonProperty

data class OAuth2AccessToken(
    @JsonProperty("access_token")
    val accessToken: String,
    @JsonProperty("refresh_token")
    val refreshToken: String?,
    val scope: String?,
    @JsonProperty("token_type")
    val tokenType: String?,
    @JsonProperty("expires_in")
    val expiresIn: Int?)