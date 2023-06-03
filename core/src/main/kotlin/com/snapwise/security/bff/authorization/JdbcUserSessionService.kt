/*
 *
 *  * Copyright 2022 the original author or authors.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *      https://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */
package com.snapwise.security.bff.authorization

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.Module
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.jdbc.core.*
import org.springframework.jdbc.support.lob.DefaultLobHandler
import org.springframework.jdbc.support.lob.LobCreator
import org.springframework.jdbc.support.lob.LobHandler
import org.springframework.security.jackson2.SecurityJackson2Modules
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.util.Assert
import org.springframework.util.StringUtils
import reactor.core.publisher.Mono
import java.nio.charset.StandardCharsets
import java.sql.*
import java.util.*
import java.util.function.Function

/**
 * A JDBC implementation of an [UserSessionService] that uses a
 * [JdbcOperations] for [OAuth2Authorization] persistence.
 *
 * **NOTE:** This `UserSessionService` depends on the table definition
 * described in
 * "classpath:com/shopwize/security/bff/authorization/session/bff-authorization-user-session-schema.sql" and
 * therefore MUST be defined in the database schema.
 *
 * @see UserSessionService
 *
 * @see UserSession
 *
 * @see JdbcOperations
 *
 * @see RowMapper
 */
class JdbcUserSessionService(
    /* the JDBC operations */
    private val jdbcOperations: JdbcOperations,

    /* the handler for large binary fields and large text fields */
    private val lobHandler: LobHandler = DefaultLobHandler()
) : UserSessionService {
    private var userSessionsRowMapper: RowMapper<UserSession>
    private var authorizationParametersMapper: Function<UserSession, List<SqlParameterValue>>

    init {
        val authorizationRowMapper = UserSessionRowMapper()
        authorizationRowMapper.setLobHandler(lobHandler)
        this.userSessionsRowMapper = authorizationRowMapper
        authorizationParametersMapper = UserSessionParametersMapper()
        initColumnMetadata(jdbcOperations)
    }

    override fun save(userSession: UserSession) {
        findById(userSession.sessionId).map { existingAuthorization ->
            if (existingAuthorization == null) {
                insertUserSession(userSession)
            } else {
                updateAuthorization(userSession)
            }
        }.subscribe()
    }

    private fun updateAuthorization(userSession: UserSession) {
        val parameters: MutableList<SqlParameterValue> = authorizationParametersMapper.apply(userSession).toMutableList()
        val id: SqlParameterValue = parameters.removeAt(0)
        parameters.add(id)
        lobHandler.lobCreator.use { lobCreator ->
            val pss: PreparedStatementSetter = LobCreatorArgumentPreparedStatementSetter(
                lobCreator,
                parameters.toTypedArray()
            )
            jdbcOperations.update(UPDATE_USER_SESSION_SQL, pss)
        }
    }

    private fun insertUserSession(userSession: UserSession) {
        val parameters: List<SqlParameterValue> = authorizationParametersMapper.apply(userSession)
        lobHandler.lobCreator.use { lobCreator ->
            val pss: PreparedStatementSetter = LobCreatorArgumentPreparedStatementSetter(
                lobCreator,
                parameters.toTypedArray()
            )
            jdbcOperations.update(SAVE_USER_SESSION_SQL, pss)
        }
    }

    override fun remove(userSession: UserSession) {
        val parameters: Array<SqlParameterValue> = arrayOf(
            SqlParameterValue(Types.VARCHAR, userSession.sessionId)
        )
        val pss: PreparedStatementSetter = ArgumentPreparedStatementSetter(parameters)
        jdbcOperations.update(REMOVE_USER_SESSION_SQL, pss)
    }

    override fun findById(id: String): Mono<UserSession?> {
        return Mono.fromCallable {
            val parameters: MutableList<SqlParameterValue> = mutableListOf()
            parameters.add(SqlParameterValue(Types.VARCHAR, id))
            findBy(PK_FILTER, parameters)
        }
    }

    override fun findBy(userId: String, resource: String, scopes: Set<String>): UserSession? {
        val parameters: MutableList<SqlParameterValue> = mutableListOf()
        parameters.add(SqlParameterValue(Types.VARCHAR, userId))
        parameters.add(SqlParameterValue(Types.VARCHAR, resource))

        val scopesParam = StringUtils.collectionToCommaDelimitedString(scopes)

        parameters.add(SqlParameterValue(Types.VARCHAR, scopesParam))
        return findBy(EXISTING_TOKEN_FILTER, parameters)
    }

    private fun findBy(filter: String, parameters: List<SqlParameterValue>): UserSession? {
        getLobHandler().lobCreator.use { lobCreator ->
            val pss: PreparedStatementSetter = LobCreatorArgumentPreparedStatementSetter(
                lobCreator,
                parameters.toTypedArray()
            )
            val result: List<UserSession> =
                getJdbcOperations().query(LOAD_USER_SESSION_SQL + filter, pss, getUserSessionRowMapper())
            return if (result.isNotEmpty()) result[0] else null
        }
    }

    /**
     * Sets the [RowMapper] used for mapping the current row in
     * `java.sql.ResultSet` to [UserSession]. The default is
     * [UserSessionRowMapper].
     *
     * @param userSessionRowMapper the [RowMapper] used for mapping the current
     * row in `ResultSet` to [UserSession]
     */
    fun setAuthorizationRowMapper(userSessionRowMapper: RowMapper<UserSession>) {
        this.userSessionsRowMapper = userSessionRowMapper
    }

    /**
     * Sets the `Function` used for mapping [OAuth2Authorization] to
     * a `List` of [SqlParameterValue]. The default is
     * [UserSessionParametersMapper].
     *
     * @param authorizationParametersMapper the `Function` used for mapping
     * [OAuth2Authorization] to a `List` of [SqlParameterValue]
     */
    fun setAuthorizationParametersMapper(
        authorizationParametersMapper: Function<UserSession, List<SqlParameterValue>>
    ) {
        this.authorizationParametersMapper = authorizationParametersMapper
    }

    protected fun getJdbcOperations(): JdbcOperations {
        return jdbcOperations
    }

    protected fun getLobHandler(): LobHandler {
        return lobHandler
    }

    protected fun getUserSessionRowMapper(): RowMapper<UserSession> {
        return userSessionsRowMapper
    }

    protected fun getAuthorizationParametersMapper(): Function<UserSession, List<SqlParameterValue>> {
        return authorizationParametersMapper
    }

    /**
     * The default [RowMapper] that maps the current row in
     * `java.sql.ResultSet` to [OAuth2Authorization].
     */
    class UserSessionRowMapper: RowMapper<UserSession> {
        private var lobHandler: LobHandler = DefaultLobHandler()
        private var objectMapper = ObjectMapper()

        init {
            val classLoader: ClassLoader = JdbcUserSessionService::class.java.classLoader
            val securityModules: List<Module> = SecurityJackson2Modules.getModules(classLoader)
            objectMapper.registerModules(securityModules)
            objectMapper.registerModule(BffJackson2Module())
        }

        @Throws(SQLException::class)
        override fun mapRow(rs: ResultSet, rowNum: Int): UserSession {
            val builder: UserSession.Builder = UserSession.Builder()
            val sessionId: String = rs.getString("session_id")
            val userId: String = rs.getString("user_id")
            val resource: String = rs.getString("resource")

            val scopesString: String = rs.getString("scopes")
            val scopes: Set<String> = StringUtils.commaDelimitedListToSet(scopesString)

            builder.sessionId(sessionId)
                .userId(userId)
                .withResource(resource)
                .withScopes(scopes)
            val accessTokenValue = rs.getString("access_token_value")
            builder.accessToken(accessTokenValue)
            val refreshTokenValue = rs.getString("refresh_token_value")
            builder.refreshToken(refreshTokenValue)
            return builder.build()
        }

        @Throws(SQLException::class)
        private fun getLobValue(rs: ResultSet, columnName: String): String? {
            var columnValue: String? = null
            val columnMetadata = columnMetadataMap.getValue(columnName)
            if (Types.BLOB == columnMetadata.dataType) {
                val columnValueBytes: ByteArray? = lobHandler.getBlobAsBytes(rs, columnName)
                if (columnValueBytes != null) {
                    columnValue = String(columnValueBytes, StandardCharsets.UTF_8)
                }
            } else if (Types.CLOB == columnMetadata.dataType) {
                columnValue = lobHandler.getClobAsString(rs, columnName)
            } else {
                columnValue = rs.getString(columnName)
            }
            return columnValue
        }

        fun setLobHandler(lobHandler: LobHandler) {
            Assert.notNull(lobHandler, "lobHandler cannot be null")
            this.lobHandler = lobHandler
        }

        fun setObjectMapper(objectMapper: ObjectMapper) {
            Assert.notNull(objectMapper, "objectMapper cannot be null")
            this.objectMapper = objectMapper
        }

        protected fun getLobHandler(): LobHandler {
            return lobHandler
        }

        protected fun getObjectMapper(): ObjectMapper {
            return objectMapper
        }

        private fun parseMap(data: String): Map<String, Any> {
            return try {
                objectMapper.readValue(data, object : TypeReference<Map<String, Any>>() {})
            } catch (ex: Exception) {
                throw IllegalArgumentException(ex.message, ex)
            }
        }
    }

    /**
     * The default `Function` that maps [UserSession] to a
     * `List` of [SqlParameterValue].
     */
    class UserSessionParametersMapper : Function<UserSession, List<SqlParameterValue>> {
        private var objectMapper = ObjectMapper()

        init {
            val classLoader: ClassLoader = JdbcUserSessionService::class.java.classLoader
            val securityModules: List<Module> = SecurityJackson2Modules.getModules(classLoader)
            objectMapper.registerModules(securityModules)
            objectMapper.registerModule(BffJackson2Module())
        }

        override fun apply(userSession: UserSession): List<SqlParameterValue> {
            val parameters: MutableList<SqlParameterValue> = mutableListOf()
            parameters.add(SqlParameterValue(Types.VARCHAR, userSession.sessionId))
            parameters.add(SqlParameterValue(Types.VARCHAR, userSession.userId))
            parameters.add(SqlParameterValue(Types.VARCHAR, userSession.resource))

            val scopes = StringUtils.collectionToCommaDelimitedString(userSession.scopes)

            parameters.add(SqlParameterValue(Types.VARCHAR, scopes))
            parameters.add(mapToSqlParameter("access_token_value", userSession.accessToken))
            parameters.add(mapToSqlParameter("refresh_token_value", userSession.refreshToken))

            return parameters
        }

        fun setObjectMapper(objectMapper: ObjectMapper) {
            this.objectMapper = objectMapper
        }

        protected fun getObjectMapper(): ObjectMapper {
            return objectMapper
        }

//        private fun <T : OAuth2Token?> toSqlParameterList(
//            tokenColumnName: String, tokenMetadataColumnName: String, token: OAuth2Authorization.Token<T>?
//        ): List<SqlParameterValue> {
//            val parameters: MutableList<SqlParameterValue> = ArrayList<SqlParameterValue>()
//            var tokenValue: String? = null
//            var tokenIssuedAt: Timestamp? = null
//            var tokenExpiresAt: Timestamp? = null
//            var metadata: String? = null
//            if (token != null) {
//                tokenValue = token.getToken().getTokenValue()
//                if (token.getToken().getIssuedAt() != null) {
//                    tokenIssuedAt = Timestamp.from(token.getToken().getIssuedAt())
//                }
//                if (token.getToken().getExpiresAt() != null) {
//                    tokenExpiresAt = Timestamp.from(token.getToken().getExpiresAt())
//                }
//                metadata = writeMap(token.getMetadata())
//            }
//            parameters.add(mapToSqlParameter(tokenColumnName, tokenValue))
//            parameters.add(SqlParameterValue(Types.TIMESTAMP, tokenIssuedAt))
//            parameters.add(SqlParameterValue(Types.TIMESTAMP, tokenExpiresAt))
//            parameters.add(mapToSqlParameter(tokenMetadataColumnName, metadata))
//            return parameters
//        }

        private fun writeMap(data: Map<String, Any>): String {
            return try {
                objectMapper.writeValueAsString(data)
            } catch (ex: Exception) {
                throw IllegalArgumentException(ex.message, ex)
            }
        }
    }

    class LobCreatorArgumentPreparedStatementSetter constructor(
        lobCreator: LobCreator,
        args: Array<Any>
    ) : ArgumentPreparedStatementSetter(args) {
        private val lobCreator: LobCreator

        init {
            this.lobCreator = lobCreator
        }

        @Throws(SQLException::class)
        override fun doSetValue(ps: PreparedStatement, parameterPosition: Int, argValue: Any) {
            if (argValue is SqlParameterValue) {
                val paramValue: SqlParameterValue = argValue as SqlParameterValue
                if (paramValue.sqlType == Types.BLOB) {
                    if (paramValue.value != null) {
                        Assert.isInstanceOf(
                            ByteArray::class.java, paramValue.value,
                            "Value of blob parameter must be byte[]"
                        )
                    }
                    val valueBytes = paramValue.getValue() as ByteArray
                    lobCreator.setBlobAsBytes(ps, parameterPosition, valueBytes)
                    return
                }
                if (paramValue.sqlType == Types.CLOB) {
                    if (paramValue.value != null) {
                        Assert.isInstanceOf(
                            String::class.java, paramValue.value,
                            "Value of clob parameter must be String"
                        )
                    }
                    val valueString = paramValue.getValue() as String
                    lobCreator.setClobAsString(ps, parameterPosition, valueString)
                    return
                }
            }
            super.doSetValue(ps, parameterPosition, argValue)
        }
    }

    private data class ColumnMetadata(val columnName: String, val dataType: Int)
    companion object {
        private const val COLUMN_NAMES = ("session_id, "
                + "user_id, "
                + "resource, "
                + "scopes, "
                + "access_token_value, "
                + "refresh_token_value")

        private const val TABLE_NAME = "bff_authorization_user_sessions"
        private const val PK_FILTER = "session_id = ?"
        private const val EXISTING_TOKEN_FILTER = "user_id = ? AND resource = ? AND scopes = ?"
        private const val RESOURCE_FILTER = "resource = ?"
        private const val SCOPES = "scopes = ?"
        private const val ACCESS_TOKEN_FILTER = "access_token_value = ?"
        private const val REFRESH_TOKEN_FILTER = "refresh_token_value = ?"

        private const val LOAD_USER_SESSION_SQL = ("SELECT " + COLUMN_NAMES
                + " FROM " + TABLE_NAME
                + " WHERE ")

        private const val SAVE_USER_SESSION_SQL = ("INSERT INTO " + TABLE_NAME
                + " (" + COLUMN_NAMES + ") VALUES (?, ?, ?, ?, ?, ?)")

        private const val UPDATE_USER_SESSION_SQL = ("UPDATE " + TABLE_NAME
                + " SET user_id = ?, resource = ?, scopes = ?, access_token_value = ?, refresh_token_value = ?"
                + " WHERE " + PK_FILTER)

        private const val REMOVE_USER_SESSION_SQL = "DELETE FROM $TABLE_NAME WHERE $PK_FILTER"
        private var columnMetadataMap: MutableMap<String, ColumnMetadata> = mutableMapOf()
        private fun initColumnMetadata(jdbcOperations: JdbcOperations) {
            columnMetadataMap = HashMap()
            var columnMetadata: ColumnMetadata
            columnMetadata = getColumnMetadata(jdbcOperations, "access_token_value", Types.BLOB)
            columnMetadataMap[columnMetadata.columnName] = columnMetadata
            columnMetadata = getColumnMetadata(jdbcOperations, "refresh_token_value", Types.BLOB)
            columnMetadataMap[columnMetadata.columnName] = columnMetadata
        }

        private fun getColumnMetadata(
            jdbcOperations: JdbcOperations,
            columnName: String,
            defaultDataType: Int
        ): ColumnMetadata {
            val dataType: Int? = jdbcOperations.execute(ConnectionCallback<Int> { conn ->
                val databaseMetaData: DatabaseMetaData = conn.metaData
                var rs: ResultSet = databaseMetaData.getColumns(null, null, TABLE_NAME, columnName)
                if (rs.next()) {
                    return@ConnectionCallback rs.getInt("DATA_TYPE")
                }
                // NOTE: (Applies to HSQL)
                // When a database object is created with one of the CREATE statements or renamed with the ALTER statement,
                // if the name is enclosed in double quotes, the exact name is used as the case-normal form.
                // But if it is not enclosed in double quotes,
                // the name is converted to uppercase and this uppercase version is stored in the database as the case-normal form.
                rs = databaseMetaData.getColumns(
                    null,
                    null,
                    TABLE_NAME.uppercase(Locale.getDefault()),
                    columnName.uppercase(Locale.getDefault())
                )
                if (rs.next()) {
                    return@ConnectionCallback rs.getInt("DATA_TYPE")
                }
                null
            } as ConnectionCallback<Int>)
            return ColumnMetadata(columnName, dataType ?: defaultDataType)
        }

        private fun mapToSqlParameter(columnName: String, value: String): SqlParameterValue {
            val columnMetadata = columnMetadataMap.getValue(columnName)
            return if (Types.BLOB == columnMetadata.dataType && StringUtils.hasText(value)) SqlParameterValue(
                Types.BLOB, value.toByteArray(
                    StandardCharsets.UTF_8
                )
            ) else SqlParameterValue(columnMetadata.dataType, value)
        }
    }
}