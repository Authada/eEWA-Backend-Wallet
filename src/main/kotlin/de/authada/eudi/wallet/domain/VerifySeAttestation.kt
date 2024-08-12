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
import com.nimbusds.jose.jwk.JWK
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

class VerifySeAttestation(
    private val authenticationPublicKeys: Set<String>
) {

    context(arrow.core.raise.Raise<AttestationRequestError>)
    operator fun invoke(seAttestation: String, seKey: String, bindingKey: JWK) {
        ensure(seKey in authenticationPublicKeys) {
            raise(AttestationRequestError.InvalidSeAttestation)
        }
        val signature = Signature.getInstance(SE_SIGNATURE_ALG)
        signature.initVerify(decodeKey(seKey))
        val spki = SubjectPublicKeyInfo.getInstance(bindingKey.toECKey().toECPublicKey().getEncoded())
        signature.update(spki.publicKeyData.bytes)
        val attestationBytes = Base64.getDecoder().decode(seAttestation)
        val validSignature = signature.verify(attestationBytes)
        ensure(validSignature) {
            raise(AttestationRequestError.InvalidSeAttestation)
        }
    }

    private fun decodeKey(key: String): PublicKey {
        val bytes = Base64.getDecoder().decode(key)
        val keySpec = X509EncodedKeySpec(bytes)
        val keyFactory = java.security.KeyFactory.getInstance("EC")
        return keyFactory.generatePublic(keySpec)
    }

    companion object {
        const val SE_SIGNATURE_ALG = "SHA256withECDSA"
    }
}
