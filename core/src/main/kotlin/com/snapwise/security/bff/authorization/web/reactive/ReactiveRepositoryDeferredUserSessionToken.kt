package com.snapwise.security.bff.authorization.web.reactive

import com.snapwise.security.bff.authorization.web.UserSessionAuthenticationToken
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.http.server.reactive.ServerHttpResponse
import reactor.core.publisher.Mono

class ReactiveRepositoryDeferredUserSessionToken(
    private val userSessionTokenRepository: ReactiveUserSessionTokenRepository,
    private val request: ServerHttpRequest,
    private val response: ServerHttpResponse
): ReactiveDeferredUserSessionToken {

    private var userSessionToken: UserSessionAuthenticationToken? = null
    private var missingToken = true

    private fun init() {
        this.userSessionToken = this.userSessionTokenRepository.loadToken(request).block()
        this.missingToken = this.userSessionToken == null
        if (this.missingToken) {
            this.userSessionToken = this.userSessionTokenRepository.generateToken(request).block()
            this.userSessionTokenRepository.saveToken(this.userSessionToken, request, response)
        }
    }

    override fun get(): Mono<UserSessionAuthenticationToken?> {
        init()
        return Mono.fromCallable { this.userSessionToken }
    }

    override fun isGenerated(): Boolean {
        init()
        return missingToken
    }
}