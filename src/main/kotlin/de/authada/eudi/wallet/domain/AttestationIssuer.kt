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

import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jose.util.X509CertUtils
import com.upokecenter.cbor.CBORObject
import de.authada.eudi.wallet.domain.AttestationRequestError.InvalidNonce
import de.authada.eudi.wallet.domain.AttestationRequestError.InvalidSeAttestation
import de.authada.eudi.wallet.web.AppAttestationTO
import de.authada.eudi.wallet.persistence.GetCNonce
import kotlinx.serialization.json.Json
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.cert.X509Certificate
import java.time.Clock
import java.util.Base64

sealed interface AttestationRequestError {
    data class InvalidRequest(val error: String) : AttestationRequestError
    data class InvalidProof(val msg: String, val cause: Throwable? = null) : AttestationRequestError
    data object InvalidNonce : AttestationRequestError
    data object InvalidAppAttestation : AttestationRequestError
    data object InvalidSeAttestation : AttestationRequestError
}


class AttestationIssuer(
    private val clock: Clock,
    private val validateProof: ValidateProof,
    private val verifyAppAttestation: VerifyAppAttestation,
    private val verifySeAttestation: VerifySeAttestation,
    private val getCNonce: GetCNonce,
    private val buildAppAttestation: BuildWalletAttestation
) {
    context(arrow.core.raise.Raise<AttestationRequestError>)
    suspend operator fun invoke(attestationRequest: AttestationRequest): JWSObject {
        val (holderKey, nonce, issuer, appAttestationTo, seAttestation, seKey) = validateProof(attestationRequest.proof)
        val cnonce = getCNonce(nonce) ?: raise(InvalidNonce)
        if (cnonce.isExpired(clock.instant())) {
            raise(InvalidNonce)
        }

        val appAttestation =
            Json.Default.decodeFromString<AppAttestationTO>(JSONObjectUtils.toJSONString(appAttestationTo)).toDomain()
        val appSecurityLevel = verifyAppAttestation.invoke(appAttestation, cnonce.nonce)
        val seVerified: Boolean = seAttestation?.let {
            if (seKey == null) {
                raise(InvalidSeAttestation)
            }
            verifySeAttestation(it, seKey, holderKey)
            true
        } ?: false

        val securityLevel = if (seVerified) {
            AttestationSecurityLevel.SECUREELEMENT
        } else appSecurityLevel

        return buildAppAttestation(issuer, holderKey, securityLevel)
    }
}

sealed interface AppAttestation {
    data class IOSAttestation(
        val fmt: String,
        val attStmt: AttestationStatement,
        val authData: ByteArray,
        val authDataObject: AuthenticatorData
    ) : AppAttestation {
        data class AttestationStatement(
            val x5c: List<ByteArray>,
            val receipt: ByteArray
        )

        companion object {
            fun fromCBOR(byteString: String): IOSAttestation {
                val cbor = CBORObject.DecodeFromBytes(Base64URL.from(byteString).decode())
                val fmt = cbor.get("fmt").AsString()
                val attStmt = cbor.get("attStmt")
                val authData = cbor.get("authData").GetByteString()
                val authDataObject = AuthenticatorData.fromByteArray(cbor.get("authData").GetByteString())
                val x5c: List<ByteArray> = attStmt.get("x5c")!!.values.map { element ->
                    element.GetByteString()!!
                }
                val receipt = attStmt.get("receipt").GetByteString()

                return IOSAttestation(fmt, AttestationStatement(x5c, receipt), authData, authDataObject)
            }
        }

        data class AuthenticatorData(
            val rpid: ByteArray,
            val counter: UInt,
            val aaguid: ByteArray,
            val credentialId: ByteArray,
        ) {
            companion object {
                fun fromByteArray(byteArray: ByteArray): AuthenticatorData = AuthenticatorData(
                    rpid = byteArray.sliceArray(0..31),
                    counter = ByteBuffer.wrap(byteArray.sliceArray(33..36)).order(ByteOrder.BIG_ENDIAN).getInt()
                        .toUInt(),
                    aaguid = byteArray.sliceArray(37..52),
                    credentialId = byteArray.sliceArray(55..86)
                )
            }
        }
    }

    data class AndroidAttestation(
        val chain: List<X509Certificate>,
        val attestationSecurityLevel: SecurityLevel?,
        val attestationChallenge: String?,
        val softwareAuthorizationList: AuthorizationList?,
        val hardwareAuthorizationList: AuthorizationList?
    ) : AppAttestation {
        companion object {
            fun of(attestationString: String): AndroidAttestation {
                val keyCertChain = attestationString.split(",").map {
                    Base64.getUrlDecoder().decode(it)
                }.map {
                    X509CertUtils.parse(it)
                }

                return keyCertChain.firstOrNull()?.getExtensionValue("1.3.6.1.4.1.11129.2.1.17")?.let {
                    ASN1Sequence.getInstance(ASN1OctetString.getInstance(it).octets)
                }?.let { keyAttestationExtension ->
                    val attestationSecurityLevel = SecurityLevel.of(keyAttestationExtension.getObjectAt(1))
                    val attestationChallenge = keyAttestationExtension.getObjectAt(4)?.let {
                        (it as ASN1OctetString).octets?.toString(Charsets.UTF_8)
                    }
                    val softwareEncodedAuthorizationList = keyAttestationExtension.getObjectAt(6)
                    val hardwareEncodedAuthorizationList = keyAttestationExtension.getObjectAt(7)

                    AndroidAttestation(
                        chain = keyCertChain,
                        attestationSecurityLevel = attestationSecurityLevel,
                        attestationChallenge = attestationChallenge,
                        softwareAuthorizationList = AuthorizationList.of(softwareEncodedAuthorizationList),
                        hardwareAuthorizationList = AuthorizationList.of(hardwareEncodedAuthorizationList),
                    )
                }!!
            }
        }
    }
}

data class AttestationRequest(
    val proof: UnvalidatedProof,
)


