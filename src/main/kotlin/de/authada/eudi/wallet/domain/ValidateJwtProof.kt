/*
 * Copyright (c) 2023 European Commission
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
 *
 * Modified by AUTHADA GmbH
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

import arrow.core.NonEmptySet
import arrow.core.nonEmptySetOf
import arrow.core.raise.Raise
import arrow.core.raise.result
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.AsymmetricJWK
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.proc.SingleKeyJWSKeySelector
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.nimbusds.jwt.proc.JWTProcessor
import de.authada.eudi.wallet.domain.AttestationRequestError.InvalidProof
import java.security.interfaces.ECPublicKey
import java.security.interfaces.EdECPublicKey
import java.security.interfaces.RSAPublicKey
import kotlin.time.Duration.Companion.seconds
import kotlin.time.DurationUnit


data class ProofData(
    val credentialKey: JWK,
    val nonce: String,
    val issuer: String,
    val appAttestation: Map<String, Any>,
    val seAttestation: String?,
    val seKey: String?
) {

    constructor(
        credentialKey: CredentialKey,
        nonce: String,
        issuer: String,
        appAttestation: Map<String, Any>,
        seAttestation: String?,
        seKey: String?
    ) : this(
        when (credentialKey) {
            is CredentialKey.Jwk -> credentialKey.value
            is CredentialKey.X5c -> JWK.parse(credentialKey.certificate)
            is CredentialKey.DIDUrl -> credentialKey.jwk
        },
        nonce,
        issuer,
        appAttestation,
        seAttestation,
        seKey
    )
}

context (Raise<InvalidProof>)
fun validateJwtProof(
    issuerId: String,
    unvalidatedProof: UnvalidatedProof.Jwt,
): ProofData = result {
    val signedJwt = SignedJWT.parse(unvalidatedProof.jwt)
    val (algorithm, credentialKey) = algorithmAndCredentialKey(signedJwt.header, nonEmptySetOf(JWSAlgorithm.ES256))
    val keySelector = keySelector(credentialKey, algorithm)
    val processor = processor(issuerId, keySelector)
    val jwtClaimsSet = processor.process(signedJwt, null)
    return ProofData(
        credentialKey,
        jwtClaimsSet.getStringClaim("nonce"),
        jwtClaimsSet.issuer,
        jwtClaimsSet.getJSONObjectClaim("app_attestation"),
        jwtClaimsSet.claims?.get("se_attestation") as String?,
        jwtClaimsSet.claims?.get("se_authentication_key") as String?
    )
}.getOrElse { raise(InvalidProof("Invalid proof JWT", it)) }


fun algorithmAndCredentialKey(
    header: JWSHeader,
    supported: NonEmptySet<JWSAlgorithm>,
): Pair<JWSAlgorithm, CredentialKey> {
    val algorithm = header.algorithm
        .takeIf(JWSAlgorithm.Family.SIGNATURE::contains)
        ?.takeIf(supported::contains)
        ?: error("signing algorithm '${header.algorithm.name}' is not supported")

    val kid = header.keyID
    val jwk = header.jwk
    val x5c = header.x509CertChain

    val key = when {
        kid != null && jwk == null && x5c.isNullOrEmpty() -> CredentialKey.DIDUrl(kid).getOrThrow()
        kid == null && jwk != null && x5c.isNullOrEmpty() -> CredentialKey.Jwk(jwk)
        kid == null && jwk == null && !x5c.isNullOrEmpty() -> CredentialKey.X5c.parseDer(x5c).getOrThrow()

        else -> error("a public key must be provided in one of 'kid', 'jwk', or 'x5c'")
    }.apply { ensureCompatibleWith(algorithm) }

    return (algorithm to key)
}

private fun CredentialKey.ensureCompatibleWith(algorithm: JWSAlgorithm) {
    fun JWK.ensureCompatibleWith(algorithm: JWSAlgorithm) {
        val supportedAlgorithms =
            when (this) {
                is RSAKey -> RSASSASigner.SUPPORTED_ALGORITHMS
                is ECKey -> ECDSASigner.SUPPORTED_ALGORITHMS
                is OctetKeyPair -> Ed25519Signer.SUPPORTED_ALGORITHMS
                else -> error("unsupported key type '${keyType.value}'")
            }
        require(algorithm in supportedAlgorithms) {
            "key type '${keyType.value}' is not compatible with signing algorithm '${algorithm.name}'"
        }
    }

    when (this) {
        is CredentialKey.DIDUrl -> jwk.ensureCompatibleWith(algorithm)
        is CredentialKey.Jwk -> value.ensureCompatibleWith(algorithm)

        is CredentialKey.X5c -> {
            val supportedAlgorithms =
                when (certificate.publicKey) {
                    is RSAPublicKey -> RSASSASigner.SUPPORTED_ALGORITHMS
                    is ECPublicKey -> ECDSASigner.SUPPORTED_ALGORITHMS
                    is EdECPublicKey -> Ed25519Signer.SUPPORTED_ALGORITHMS
                    else -> error("unsupported certificate algorithm '${certificate.publicKey.algorithm}'")
                }
            require(algorithm in supportedAlgorithms) {
                "certificate algorithm '${certificate.publicKey.algorithm}' is not compatible with signing algorithm '${algorithm.name}'"
            }
        }
    }
}

private fun keySelector(
    credentialKey: CredentialKey,
    algorithm: JWSAlgorithm,
): JWSKeySelector<SecurityContext> {
    fun <C : SecurityContext> JWK.keySelector(algorithm: JWSAlgorithm): SingleKeyJWSKeySelector<C> =
        when (this) {
            is AsymmetricJWK -> SingleKeyJWSKeySelector(algorithm, toPublicKey())
            else -> TODO("CredentialKey.Jwk with non AsymmetricJWK is not yet supported")
        }

    return when (credentialKey) {
        is CredentialKey.DIDUrl -> credentialKey.jwk.keySelector(algorithm)
        is CredentialKey.Jwk -> credentialKey.value.keySelector(algorithm)
        is CredentialKey.X5c -> SingleKeyJWSKeySelector(algorithm, credentialKey.certificate.publicKey)
    }
}

private val expectedType = JOSEObjectType("wallet-proof+jwt")
private val maxSkew = 30.seconds

private fun processor(
    issuerId: String,
    keySelector: JWSKeySelector<SecurityContext>,
): JWTProcessor<SecurityContext> =
    DefaultJWTProcessor<SecurityContext>()
        .apply {
            jwsTypeVerifier = DefaultJOSEObjectTypeVerifier(expectedType)
            jwsKeySelector = keySelector
            jwtClaimsSetVerifier =
                DefaultJWTClaimsVerifier<SecurityContext?>(
                    issuerId, // aud
                    JWTClaimsSet.Builder()
                        .build(),
                    setOf("iat", "nonce", "app_attestation"),
                ).apply {
                    maxClockSkew = maxSkew.toInt(DurationUnit.SECONDS)
                }
        }
