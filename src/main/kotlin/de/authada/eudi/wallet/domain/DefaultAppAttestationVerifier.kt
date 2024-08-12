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

import de.authada.eudi.wallet.domain.AppAttestation.AndroidAttestation
import de.authada.eudi.wallet.domain.AppAttestation.IOSAttestation

class DefaultAppAttestationVerifier(
    private val iOSAttestationVerifier: iOSAttestationVerifier,
    private val androidAttestationVerifier: AndroidAttestationVerifier
) : VerifyAppAttestation {

    context(arrow.core.raise.Raise<AttestationRequestError>)
    override suspend fun invoke(appAttestation: AppAttestation, nonce: String): AttestationSecurityLevel =
        when (appAttestation) {
            is AndroidAttestation -> androidAttestationVerifier.verify(appAttestation, nonce)
            is IOSAttestation -> iOSAttestationVerifier.verify(appAttestation, nonce)
        }

}
