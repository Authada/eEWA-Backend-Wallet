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

import arrow.core.getOrElse
import arrow.core.raise.either
import de.authada.eudi.wallet.domain.AppAttestation
import de.authada.eudi.wallet.domain.AppAttestation.AndroidAttestation
import de.authada.eudi.wallet.domain.AppAttestation.IOSAttestation
import de.authada.eudi.wallet.domain.AttestationIssuer
import de.authada.eudi.wallet.domain.AttestationRequest
import de.authada.eudi.wallet.domain.UnvalidatedProof
import de.authada.eudi.wallet.web.AppAttestationType.Android
import de.authada.eudi.wallet.web.AppAttestationType.iOS
import de.authada.eudi.wallet.web.ProofTypeTO.JWT
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.awaitBody
import org.springframework.web.reactive.function.server.bodyValueAndAwait
import org.springframework.web.reactive.function.server.buildAndAwait
import org.springframework.web.reactive.function.server.coRouter
import org.springframework.web.reactive.function.server.json

class AttestationApi(
    private val attestationIssuer: AttestationIssuer
) {

    val route = coRouter {
        POST(
            ATTESTATION,
            contentType(MediaType.APPLICATION_JSON) and accept(MediaType.APPLICATION_JSON),
            ::generateAppAttestation
        )
    }


    private suspend fun generateAppAttestation(request: ServerRequest): ServerResponse {
        val attestationRequest = request.awaitBody<AttestationRequestTO>()
        return either {
            ServerResponse.ok()
                .json()
                .bodyValueAndAwait(
                    AttestationTO(
                        attestation = attestationIssuer(
                            attestationRequest.toDomain()
                        ).serialize()
                    )
                )
        }.getOrElse { error ->
            log.error("error generating access token {}", error)
            ServerResponse.badRequest()
                .buildAndAwait()
        }
    }

    companion object {
        const val ATTESTATION = "/attestation"
        private val log = LoggerFactory.getLogger(AttestationApi::class.java)
    }
}


@Serializable
data class AttestationTO(
    @SerialName("attestation")
    val attestation: String
)

@Serializable
data class AttestationRequestTO(
    @SerialName("proof")
    val proof: ProofTO,
) {
    fun toDomain(): AttestationRequest = AttestationRequest(
        proof = when (proof.type) {
            JWT -> UnvalidatedProof.Jwt(proof.jwt!!)
        },
    )
}

enum class AppAttestationType {
    iOS,
    Android
}

@Serializable
data class AppAttestationTO(
    val type: AppAttestationType,
    val attestation: String
) {
    fun toDomain(): AppAttestation = when (type) {
        iOS -> IOSAttestation.fromCBOR(attestation)
        Android -> AndroidAttestation.of(attestation)
    }
}


@Serializable
data class ProofTO(
    @SerialName("proof_type") @Required val type: ProofTypeTO,
    val jwt: String? = null,
)

@Serializable
enum class ProofTypeTO {
    @SerialName("jwt")
    JWT,
}
