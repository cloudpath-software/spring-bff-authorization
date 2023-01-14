package com.snapwise.security.bff.authorization.web

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse

class RepositoryDeferredUserSessionToken(
    private val userSessionTokenRepository: UserSessionTokenRepository,
    private val request: HttpServletRequest,
    private val response: HttpServletResponse
): DeferredUserSessionToken {

    private var userSessionToken: UserSessionAuthenticationToken? = null
    private var missingToken = true

    private fun init() {
        this.userSessionToken = this.userSessionTokenRepository.loadToken(request)
        this.missingToken = this.userSessionToken == null
        if (this.missingToken) {
            this.userSessionToken = this.userSessionTokenRepository.generateToken(request)
            this.userSessionTokenRepository.saveToken(this.userSessionToken, request, response)
        }
    }

    override fun get(): UserSessionAuthenticationToken? {
        init()
        return this.userSessionToken
    }

    override fun isGenerated(): Boolean {
        init()
        return missingToken
    }
}