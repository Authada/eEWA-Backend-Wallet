/*
 * Copyright (c) 2024 AUTHADA GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.authada.eudi.wallet.web

import com.nimbusds.jose.jwk.JWKSet
import de.authada.eudi.wallet.WalletSigningKey
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.bodyValueAndAwait
import org.springframework.web.reactive.function.server.coRouter
import org.springframework.web.reactive.function.server.json

class MetaDataApi(
    private val walletSigningKey: WalletSigningKey
) {

    val route = coRouter {
        GET(WELL_KNOWN_JWKS, accept(MediaType.APPLICATION_JSON)) { _ ->
            handleGetJwkSet()
        }
        GET(PUBLIC_KEYS, accept(MediaType.APPLICATION_JSON)) {
            handleGetPublicKeys()
        }
    }


    private suspend fun handleGetJwkSet(): ServerResponse = ServerResponse.ok().json()
        .bodyValueAndAwait(Json.parseToJsonElement(JWKSet(walletSigningKey.key).toString(true)))

    private suspend fun handleGetPublicKeys(): ServerResponse =
        ServerResponse.ok()
            .json()
            .bodyValueAndAwait(JWKSet(walletSigningKey.key).toString(true))

    companion object {
        const val WELL_KNOWN_JWKS = "/.well-known/jwks.json"
        const val PUBLIC_KEYS = "/public_keys.jwks"
    }
}
