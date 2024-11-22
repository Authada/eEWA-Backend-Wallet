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
package de.authada.eudi.wallet.domain

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import de.authada.eudi.wallet.WalletSigningKey
import de.authada.eudi.wallet.domain.AttestationSecurityLevel.SECUREELEMENT
import de.authada.eudi.wallet.signingAlgorithm
import java.time.Clock
import java.time.Duration
import java.util.Date

enum class AttestationSecurityLevel(val value: String) {
    SOFTWARE("software"),
    HARDWARE("hardware"),
    TEE("tee"),
    STRONGBOX("strong_box"),
    SECUREENCLAVE("secure_enclave"),
    HSM("hsm"),
    SECUREELEMENT("secure_element"),
}

class WalletAttestationBuilder(
    private val issuerId: String,
    private val walletSigningKey: WalletSigningKey,
    private val expirationDuration: Duration,
    private val clock: Clock,
    private val walletProviderAttestationJwt: SignedJWT
) : BuildWalletAttestation {

    private val signer = ECDSASigner(walletSigningKey.key.toECPrivateKey())
    override operator fun invoke(
        clientId: String,
        clientKey: JWK,
        securityLevel: AttestationSecurityLevel
    ): SignedJWT {
        val now = clock.instant()
        return SignedJWT(
            JWSHeader.Builder(walletSigningKey.signingAlgorithm)
                .jwk(walletSigningKey.key.toPublicJWK())
                .type(JOSEObjectType("wallet-attestation+jwt"))
                .customParam("jwt", walletProviderAttestationJwt.serialize())
                .build(),
            JWTClaimsSet.Builder()
                .issuer(issuerId)
                .subject(clientId)
                .issueTime(
                    Date.from(now)
                )
                .expirationTime(Date.from(now + expirationDuration))
                .claim("aal", "https://trust-list.eu/aal/high")
                .claim(
                    "cnf", mapOf(
                        "jwk" to clientKey.toJSONObject(),
                        "key_type" to securityLevel.value,
                        "user_authentication" to if (securityLevel == SECUREELEMENT) "secure_element_pin" else "internal_pin"
                    )
                )
                .build()
        ).apply {
            sign(signer)
        }
    }
}
