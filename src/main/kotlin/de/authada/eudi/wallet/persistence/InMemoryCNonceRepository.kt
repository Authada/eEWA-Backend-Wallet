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
package de.authada.eudi.wallet.persistence

import de.authada.eudi.wallet.domain.CNonce
import de.authada.eudi.wallet.domain.isExpired
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

class InMemoryCNonceRepository(
    private val data: MutableMap<String, CNonce> = mutableMapOf(),
) {

    private val mutex = Mutex()

    val deleteExpiredCNonce: DeleteExpiredCNonce = DeleteExpiredCNonce { at ->

        fun <K, V> MutableMap<K, V>.removeIfValue(predicate: (V) -> Boolean) =
            filterValues(predicate).forEach { (k, _) -> remove(k) }

        mutex.withLock(this) {
            data.removeIfValue { it.isExpired(at) }
        }
    }

    val upsertCNonce: UpsertCNonce = UpsertCNonce { cNonce ->
        mutex.withLock(this) {
            data[cNonce.nonce] = cNonce
        }
    }
    val getCNonce: GetCNonce = GetCNonce { nonce ->
        mutex.withLock(this) {
            data[nonce]
        }
    }

    internal suspend fun clear(): Unit =
        mutex.withLock(this) {
            data.clear()
        }
}
