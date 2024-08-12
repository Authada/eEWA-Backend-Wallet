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

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.ASN1TaggedObject


enum class SecurityLevel(val value: Int) {
    SOFTWARE(0),
    TRUSTED_ENVIRONMENT(1),
    STRONGBOX(2);

    companion object {
        fun of(asN1Encodable: ASN1Encodable?): SecurityLevel? =
            (asN1Encodable as? ASN1Enumerated)?.intValueExact()?.let { value ->
                SecurityLevel.entries.find { it.value == value }
            }
    }
}

enum class VerifierBootState(val value: Int) {
    Verified(0),
    SelfSigned(1),
    Unverified(2),
    Failed(3);

    companion object {
        fun of(asN1Encodable: ASN1Encodable?): VerifierBootState? =
            (asN1Encodable as? ASN1Enumerated)?.intValueExact()?.let { value ->
                VerifierBootState.entries.find { it.value == value }
            }
    }
}

data class RootOfThrust(
    val verifierBootState: VerifierBootState?
) {
    companion object {
        fun of(asN1Encodable: ASN1Encodable?): RootOfThrust? = asN1Encodable?.let {
            val sequence = ASN1Sequence.getInstance(it)
            RootOfThrust(VerifierBootState.of(sequence.getObjectAt(2)))
        }
    }
}

data class AttestationApplicationPackageInfos(
    val packageName: String?,
    val version: Int?
) {

    companion object {
        fun of(asN1Encodable: ASN1Encodable?): AttestationApplicationPackageInfos? =
            (asN1Encodable as? ASN1Sequence)?.let {
                AttestationApplicationPackageInfos(
                    packageName = (it.getObjectAt(0) as? ASN1OctetString)?.octets?.toString(Charsets.UTF_8),
                    version = (it.getObjectAt(0) as? ASN1Integer)?.intValueExact()

                )
            }
    }
}

data class AttestationApplicationId(
    val signatureDigests: Set<String>?,
    val packageInfos: Set<AttestationApplicationPackageInfos>?
) {
    companion object {
        @OptIn(ExperimentalStdlibApi::class)
        fun of(asN1Encodable: ASN1Encodable?): AttestationApplicationId? =
            (asN1Encodable as? ASN1OctetString)?.octets?.let {
                val seq = ASN1Sequence.getInstance(it)
                AttestationApplicationId(
                    packageInfos = (seq.getObjectAt(0) as? ASN1Set)?.objects?.asSequence()?.mapNotNull {
                        AttestationApplicationPackageInfos.of(it as ASN1Encodable)
                    }?.toSet(),
                    signatureDigests = (seq.getObjectAt(1) as? ASN1Set)?.objects?.asSequence()?.map {
                        (it as ASN1OctetString).octets.toHexString()
                    }?.toSet()
                )
            }
    }
}

data class AuthorizationList(
    val rootOfThrust: RootOfThrust?,
    val attestationApplicationId: AttestationApplicationId?
) {
    companion object {
        fun of(asN1Encodable: ASN1Encodable?): AuthorizationList? {
            return asN1Encodable?.let {
                (it as ASN1Sequence).objects.asSequence().map {
                    it as ASN1TaggedObject
                }
            }?.toList()?.let {
                AuthorizationList(
                    rootOfThrust = it.findWithTag(TAG_ROOTOFTRUST)?.let { RootOfThrust.of(it) },
                    attestationApplicationId = AttestationApplicationId.of(
                        it.findWithTag(
                            TAG_ATTESTATION_APPLICATIONID
                        )
                    ),
                )
            }
        }

        const val TAG_ROOTOFTRUST: Int = 704
        const val TAG_ATTESTATION_APPLICATIONID: Int = 709
    }
}

fun List<ASN1TaggedObject>.findWithTag(value: Int): ASN1Encodable? =
    this.find { it.tagNo == value }?.parseExplicitBaseObject()
