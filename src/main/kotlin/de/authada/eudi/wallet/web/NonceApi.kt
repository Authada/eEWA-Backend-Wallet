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

import de.authada.eudi.wallet.domain.CNonce
import de.authada.eudi.wallet.persistence.GenerateCNonce
import de.authada.eudi.wallet.persistence.UpsertCNonce
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.bodyValueAndAwait
import org.springframework.web.reactive.function.server.coRouter
import org.springframework.web.reactive.function.server.json
import java.time.Clock

class NonceApi(
    private val clock: Clock,
    private val generateCNonce: GenerateCNonce,
    private val upsertCNonce: UpsertCNonce
) {

    val route = coRouter {
        GET(CNONE, accept(MediaType.APPLICATION_JSON)) {
            getCNonce()
        }
    }


    private suspend fun getCNonce(): ServerResponse {
        val cNonce = generateCNonce(clock)
        upsertCNonce(cNonce)
        return ServerResponse.ok()
            .json()
            .bodyValueAndAwait(cNonce.toTO())
    }

    companion object {
        const val CNONE = "/cnonce"
    }
}

@Serializable
data class CNonceTO(
    @SerialName("c_nonce")
    val cnonce: String,
    @SerialName("c_nonce_expires_in")
    val expiresIn: Long
)

fun CNonce.toTO(): CNonceTO = CNonceTO(
    this.nonce,
    this.expiresIn.seconds
)
