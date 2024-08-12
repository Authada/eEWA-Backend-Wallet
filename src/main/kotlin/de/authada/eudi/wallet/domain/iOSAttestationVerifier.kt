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
import com.nimbusds.jose.util.Base64
import com.nimbusds.jose.util.X509CertChainUtils
import com.nimbusds.jose.util.X509CertUtils
import de.authada.eudi.wallet.domain.AppAttestation.IOSAttestation
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.crypto.digests.SHA256Digest
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

class iOSAttestationVerifier(
    rootCert: X509Certificate,
    private val allowDev: Boolean,
    validAppIds: Set<String>
) {
    private val validAppIdHashes: Set<ByteArray> = validAppIds.map { hash(it) }.toSet()
    private val trustManager = trustManager(rootCert)
    private val authType = rootCert.publicKey.format

    context(arrow.core.raise.Raise<AttestationRequestError>)
    fun verify(iOSAttestation: IOSAttestation, nonce: String): AttestationSecurityLevel {

        ensure(iOSAttestation.fmt == "apple-appattest") {
            raise(AttestationRequestError.InvalidAppAttestation)
        }
        ensure(iOSAttestation.attStmt.x5c.size == 2) {
            raise(AttestationRequestError.InvalidAppAttestation)
        }

        ensure(trustManager.validateChain(iOSAttestation.attStmt.x5c, authType)) {
            raise(AttestationRequestError.InvalidAppAttestation)
        }

        val credCert = X509CertUtils.parse(iOSAttestation.attStmt.x5c.first())
        ensure(validateNonce(nonce, iOSAttestation, credCert)) {
            raise(AttestationRequestError.InvalidAppAttestation)
        }

        ensure(validatePublicKey(credCert, iOSAttestation.authDataObject.credentialId)) {
            raise(AttestationRequestError.InvalidAppAttestation)
        }

        ensure(validateAppIds(iOSAttestation.authDataObject.rpid)) {
            raise(AttestationRequestError.InvalidAppAttestation)
        }

        ensure(iOSAttestation.authDataObject.counter == 0u) {
            raise(AttestationRequestError.InvalidAppAttestation)
        }

        ensure(validateAAGUID(iOSAttestation.authDataObject.aaguid)) {
            raise(AttestationRequestError.InvalidAppAttestation)
        }
        return AttestationSecurityLevel.SECUREENCLAVE
    }

    private fun validateAAGUID(aaguid: ByteArray): Boolean = if (allowDev) {
        aaguid.contentEquals(aaguid_dev) || aaguid.contentEquals(aaguid_prod)
    } else {
        aaguid.contentEquals(aaguid_prod)
    }

    private fun validateAppIds(rpid: ByteArray): Boolean = validAppIdHashes.any { it.contentEquals(rpid) }

    private fun validatePublicKey(credCert: X509Certificate, credentialId: ByteArray): Boolean {
        val ecPublicKey = credCert.publicKey as ECPublicKey
        val encodedPublicKey = publicKeyData(ecPublicKey)
        val keyHash = hash(encodedPublicKey)
        return keyHash.contentEquals(credentialId)
    }

    private fun publicKeyData(ecPublicKey: ECPublicKey): ByteArray =
        SubjectPublicKeyInfo.getInstance(ecPublicKey.encoded).publicKeyData.octets

    context(arrow.core.raise.Raise<AttestationRequestError>)
    private fun iOSAttestationVerifier.validateNonce(
        nonce: String,
        iOSAttestation: IOSAttestation,
        credCert: X509Certificate
    ): Boolean {
        val clientDataHash = hash(nonce)
        val calculatedAttestationNonce = hash(iOSAttestation.authData + clientDataHash)

        val attestationNonce = kotlin.runCatching {
            val extensionBytes =
                ASN1OctetString.getInstance(credCert.getExtensionValue("1.2.840.113635.100.8.2")).octets
            val octetString =
                ASN1TaggedObject.getInstance((ASN1Sequence.fromByteArray(extensionBytes) as ASN1Sequence).getObjectAt(0)).baseObject as ASN1OctetString
            octetString.octets
        }.getOrElse {
            raise(AttestationRequestError.InvalidAppAttestation)
        }
        return calculatedAttestationNonce.contentEquals(attestationNonce)
    }

    companion object {
        private val aaguid_dev = "appattestdevelop".toByteArray(Charsets.UTF_8)
        private val aaguid_prod = "appattest".toByteArray(Charsets.UTF_8) + ByteArray(7).apply {
            fill(0x00)
        }

        private val shA256Digest = SHA256Digest()

        private fun hash(tbh: String): ByteArray {
            val tbhBytes = tbh.toByteArray(Charsets.UTF_8)
            val output = hash(tbhBytes)
            return output
        }

        private fun hash(tbhBytes: ByteArray): ByteArray {
            val output = ByteArray(shA256Digest.digestSize)
            shA256Digest.update(tbhBytes, 0, tbhBytes.size)
            shA256Digest.doFinal(output, 0)
            return output
        }

    }
}


fun X509TrustManager.validateChain(x5c: List<ByteArray>, authType: String): Boolean {
    val chain = X509CertChainUtils.parse(x5c.map { Base64.encode(it) })
    return kotlin.runCatching { checkClientTrusted(chain.toTypedArray(), authType) }.map { true }
        .getOrElse { false }
}

fun trustManager(rootCert: X509Certificate): X509TrustManager {
    val instance = TrustManagerFactory.getInstance("X509")
    val keyStore = KeyStore.getInstance("JKS")
    keyStore.load(null)
    keyStore.setCertificateEntry("root", rootCert)
    instance.init(keyStore)
    return instance.trustManagers.first() as X509TrustManager
}
