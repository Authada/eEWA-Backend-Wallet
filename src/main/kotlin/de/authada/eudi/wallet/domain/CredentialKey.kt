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

import arrow.core.NonEmptyList
import arrow.core.raise.result
import com.nimbusds.jose.jwk.AsymmetricJWK
import com.nimbusds.jose.jwk.JWK
import foundation.identity.did.DIDURL
import java.security.cert.X509Certificate

/**
 * This is the public key or reference to it
 * that is provided by the wallet, via [UnvalidatedProof], to be included
 * inside the issued credential
 */
sealed interface CredentialKey {

    /**
     * If the Credential shall be bound to a DID, the kid refers to a DID URL
     * which identifies a particular key in the DID Document that the Credential shall be bound to
     */
    data class DIDUrl(val url: DIDURL, val jwk: JWK) : CredentialKey {
        init {
            require(!jwk.isPrivate) { "jwk must not contain a private key" }
            require(jwk is AsymmetricJWK) { "'jwk' must be asymmetric" }
        }

        companion object {

            /**
             * Resolves the provided DID url. Currently supports 'key' and 'jwk' methods.
             */
            operator fun invoke(value: String): Result<DIDUrl> = result {
                val url = DIDURL.fromString(value)
                val method = url.did.methodName
                require(method == "key" || method == "jwk") { "Unsupported DID method '$method'" }

                val jwk = resolveDidUrl(url).bind()
                DIDUrl(url, jwk)
            }
        }
    }

    @JvmInline
    value class Jwk(val value: JWK) : CredentialKey {
        init {
            require(!value.isPrivate) { "jwk must not contain a private key" }
            require(value is AsymmetricJWK) { "'jwk' must be asymmetric" }
        }
    }

    @JvmInline
    value class X5c(val chain: NonEmptyList<X509Certificate>) : CredentialKey {
        val certificate: X509Certificate
            get() = chain.head

        companion object
    }
}
