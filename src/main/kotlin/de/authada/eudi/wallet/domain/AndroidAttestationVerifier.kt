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

import arrow.core.raise.ensure
import de.authada.eudi.wallet.domain.AppAttestation.AndroidAttestation
import de.authada.eudi.wallet.domain.SecurityLevel.SOFTWARE
import de.authada.eudi.wallet.domain.SecurityLevel.STRONGBOX
import de.authada.eudi.wallet.domain.SecurityLevel.TRUSTED_ENVIRONMENT
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.util.Base64

class AndroidAttestationVerifier(
    validPackages: Set<String>,
    validSignatureHashes: Set<String>,
    rootCertPublicKey: String
) {

    private val validPackages = validPackages.map { it.lowercase() }
    private val validSignatureHashes = validSignatureHashes.map { it.lowercase() }
    private val rootCertPublicKey: ByteArray = rootCertPublicKey.let {
        Base64.getDecoder().decode(it)
    }

    context(arrow.core.raise.Raise<AttestationRequestError>)
    fun verify(androidAttestation: AndroidAttestation, nonce: String): AttestationSecurityLevel {
        ensure(androidAttestation.attestationChallenge == nonce) {
            raise(AttestationRequestError.InvalidAppAttestation)
        }
        LOGGER.info("Android nonce checked")

        ensure(androidAttestation.hardwareAuthorizationList?.rootOfThrust?.verifierBootState == VerifierBootState.Verified) {
            raise(AttestationRequestError.InvalidAppAttestation)
        }
        LOGGER.info("Android root of trust checked")
        val signatureDigests =
            androidAttestation.softwareAuthorizationList?.attestationApplicationId?.signatureDigests?.map { it.lowercase() }
                ?: emptySet()
        ensure(signatureDigests.isNotEmpty() && validSignatureHashes.containsAll(signatureDigests)) {
            raise(AttestationRequestError.InvalidAppAttestation)
        }

        LOGGER.info("Android signature digests checked")
        val packageInfos =
            androidAttestation.softwareAuthorizationList?.attestationApplicationId?.packageInfos?.mapNotNull { it.packageName?.lowercase() }
                ?: emptySet()
        ensure(packageInfos.isNotEmpty() && validPackages.containsAll(packageInfos)) {
            raise(AttestationRequestError.InvalidAppAttestation)
        }
        LOGGER.info("Android packageInfos checked")

        val trustedRootCert = androidAttestation.chain.find { it.publicKey.encoded.contentEquals(rootCertPublicKey) }
        ensure(trustedRootCert != null) {
            raise(AttestationRequestError.InvalidAppAttestation)
        }
        LOGGER.info("Root cert is trusted")

        val validChain = kotlin.runCatching {
            trustManager(trustedRootCert).checkClientTrusted(
                androidAttestation.chain.toTypedArray(),
                trustedRootCert.publicKey.format
            )
        }.map {
            true
        }.getOrElse { false }

        ensure(validChain) {
            raise(AttestationRequestError.InvalidAppAttestation)
        }
        LOGGER.info("Chain is trusted")
        return when (androidAttestation.attestationSecurityLevel) {
            SOFTWARE -> AttestationSecurityLevel.SOFTWARE
            TRUSTED_ENVIRONMENT -> AttestationSecurityLevel.TEE
            STRONGBOX -> AttestationSecurityLevel.STRONGBOX
            null -> AttestationSecurityLevel.SOFTWARE
        }
    }

    companion object {
        val LOGGER: Logger = LoggerFactory.getLogger(AndroidAttestationVerifier::class.java)
    }

}
