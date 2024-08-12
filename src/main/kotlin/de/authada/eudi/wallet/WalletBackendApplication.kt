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
package de.authada.eudi.wallet

import arrow.core.recover
import arrow.core.some
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.OctetSequenceKey
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.Base64
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.oauth2.sdk.id.Issuer
import com.nimbusds.oauth2.sdk.util.X509CertificateUtils
import de.authada.eudi.wallet.KeyOption.GenerateRandom
import de.authada.eudi.wallet.KeyOption.LoadFromKeystore
import de.authada.eudi.wallet.domain.AndroidAttestationVerifier
import de.authada.eudi.wallet.domain.AttestationIssuer
import de.authada.eudi.wallet.domain.DefaultAppAttestationVerifier
import de.authada.eudi.wallet.domain.HttpsUrl
import de.authada.eudi.wallet.domain.TrustAllAppAttestationVerifier
import de.authada.eudi.wallet.domain.ValidateProof
import de.authada.eudi.wallet.domain.VerifySeAttestation
import de.authada.eudi.wallet.domain.WalletAttestationBuilder
import de.authada.eudi.wallet.domain.iOSAttestationVerifier
import de.authada.eudi.wallet.persistence.InMemoryCNonceRepository
import de.authada.eudi.wallet.web.AttestationApi
import de.authada.eudi.wallet.web.MetaDataApi
import de.authada.eudi.wallet.web.NonceApi
import de.authada.eudi.wallet.persistence.GenerateCNonce
import io.netty.handler.ssl.SslContextBuilder
import io.netty.handler.ssl.util.InsecureTrustManagerFactory
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.boot.web.codec.CodecCustomizer
import org.springframework.context.ApplicationContextInitializer
import org.springframework.context.support.BeanDefinitionDsl
import org.springframework.context.support.GenericApplicationContext
import org.springframework.context.support.beans
import org.springframework.core.env.Environment
import org.springframework.core.env.getProperty
import org.springframework.core.env.getRequiredProperty
import org.springframework.core.io.DefaultResourceLoader
import org.springframework.core.io.FileSystemResource
import org.springframework.http.HttpStatus
import org.springframework.http.client.reactive.ReactorClientHttpConnector
import org.springframework.http.codec.json.KotlinSerializationJsonDecoder
import org.springframework.http.codec.json.KotlinSerializationJsonEncoder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.config.web.server.invoke
import org.springframework.security.web.server.authorization.HttpStatusServerAccessDeniedHandler
import org.springframework.web.reactive.function.client.WebClient
import reactor.netty.http.client.HttpClient
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Duration
import java.util.Date
import kotlin.time.Duration.Companion.days
import kotlin.time.toJavaDuration

private val log = LoggerFactory.getLogger(WalletBackendApplication::class.java)

/**
 * [WebClient] instances for usage within the application.
 */
internal object WebClients {

    /**
     * A [WebClient] with [Json] serialization enabled.
     */
    val Default: WebClient by lazy {
        val json = Json { ignoreUnknownKeys = true }
        WebClient
            .builder()
            .codecs {
                it.defaultCodecs().kotlinSerializationJsonDecoder(KotlinSerializationJsonDecoder(json))
                it.defaultCodecs().kotlinSerializationJsonEncoder(KotlinSerializationJsonEncoder(json))
                it.defaultCodecs().enableLoggingRequestDetails(true)
            }
            .build()
    }

    /**
     * A [WebClient] with [Json] serialization enabled that trusts *all* certificates.
     */
    val Insecure: WebClient by lazy {
        log.warn("Using insecure WebClient trusting all certificates")
        val sslContext = SslContextBuilder.forClient()
            .trustManager(InsecureTrustManagerFactory.INSTANCE)
            .build()
        val httpClient = HttpClient.create().secure { it.sslContext(sslContext) }
        Default.mutate()
            .clientConnector(ReactorClientHttpConnector(httpClient))
            .build()
    }
}


@OptIn(ExperimentalSerializationApi::class)
fun beans(clock: Clock) = beans {
    val walletPublicUrl = env.readRequiredUrl("wallet.publicUrl", removeTrailingSlash = true)
    val issuerId = walletPublicUrl
    //
    // Signing key
    //

    bean(isLazyInit = true) {
        val signingKey = when (env.getProperty<KeyOption>("wallet.signing-key")) {
            null, GenerateRandom -> {
                log.info("Generating random signing key and self-signed certificate for issuance")
                val key = ECKeyGenerator(Curve.P_256).keyID("wallet-backend-kid-0").generate()
                val certificate = X509CertificateUtils.generateSelfSigned(
                    Issuer(walletPublicUrl.value.host),
                    Date.from(clock.instant()),
                    Date.from(clock.instant() + 365.days.toJavaDuration()),
                    key.toECPublicKey(),
                    key.toECPrivateKey(),
                )
                ECKey.Builder(key)
                    .x509CertChain(listOf(Base64.encode(certificate.encoded)))
                    .build()
            }

            LoadFromKeystore -> {
                log.info("Loading signing key and certificate for issuance from keystore")
                loadJwkFromKeystore(env, "wallet.signing-key")
            }
        }
        require(signingKey is ECKey) { "Only ECKeys are supported for signing" }
        WalletSigningKey(signingKey)
    }

    //
    // Adapters (out ports)
    //
    bean { clock }
    bean {
        if ("insecure" in env.activeProfiles) {
            WebClients.Insecure
        } else {
            WebClients.Default
        }
    }

    //
    // Encryption of credential response
    //

    with(InMemoryCNonceRepository()) {
        bean { deleteExpiredCNonce }
        bean { upsertCNonce }
        bean { getCNonce }
        bean { GenerateCNonce.random(Duration.ofMinutes(5L)) }
        bean { this@with }
    }

    bean {
        ValidateProof(issuerId)
    }

    bean {
        iOSAttestationVerifier(
            X509CertUtils.parse(env.getRequiredProperty("attestation.ios.x509rootcert")),
            env.getRequiredProperty<Boolean>("attestation.ios.allow-dev"),
            env.getRequiredProperty<Set<String>>("attestation.ios.appids"),
        )
    }
    bean {
        AndroidAttestationVerifier(
            env.getRequiredProperty<Set<String>>("attestation.android.valid-packages"),
            env.getRequiredProperty<Set<String>>("attestation.android.valid-digests"),
            env.getRequiredProperty<String>("attestation.android.root-cert-public-key"),
        )
    }
    bean {
        VerifySeAttestation(
            env.getRequiredProperty<Set<String>>("attestation.secure-element.authentication-keys"),
        )
    }
    bean {
        if (env.getProperty<Boolean>("attestation.mock", false)) {
            TrustAllAppAttestationVerifier()
        } else {
            DefaultAppAttestationVerifier(
                ref(),
                ref()
            )
        }
    }

    bean {
        WalletAttestationBuilder(
            issuerId,
            ref(),
            Duration.ofDays(365),
            clock
        )
    }


    bean {
        AttestationIssuer(clock, ref(), ref(), ref(), ref(), ref())
    }

    bean {
        val metaDataApi = MetaDataApi(ref())
        val nonceApi = NonceApi(clock, ref(), ref())
        val attestationApi = AttestationApi(ref())
        metaDataApi.route.and(nonceApi.route).and(attestationApi.route)
    }

    bean {
        val http = ref<ServerHttpSecurity>()
        http {
            authorizeExchange {
                authorize(MetaDataApi.WELL_KNOWN_JWKS, permitAll)
                authorize(MetaDataApi.PUBLIC_KEYS, permitAll)
                authorize(NonceApi.CNONE, permitAll)
                authorize(AttestationApi.ATTESTATION, permitAll)
                authorize(anyExchange, denyAll)
            }

            csrf {
                disable()
            }

            cors {
                disable()
            }

            exceptionHandling {
                accessDeniedHandler = HttpStatusServerAccessDeniedHandler(HttpStatus.FORBIDDEN)
            }
        }
    }

    bean {
        CodecCustomizer {
            val json = Json {
                explicitNulls = false
                ignoreUnknownKeys = true
            }
            it.defaultCodecs().kotlinSerializationJsonDecoder(KotlinSerializationJsonDecoder(json))
            it.defaultCodecs().kotlinSerializationJsonEncoder(KotlinSerializationJsonEncoder(json))
            it.defaultCodecs().enableLoggingRequestDetails(true)
        }
    }
}


private fun Environment.readRequiredUrl(key: String, removeTrailingSlash: Boolean = false): HttpsUrl =
    getRequiredProperty(key)
        .let { url ->
            fun String.normalize() =
                if (removeTrailingSlash) {
                    this.removeSuffix("/")
                } else {
                    this
                }

            fun String.toHttpsUrl(): HttpsUrl = HttpsUrl.of(this) ?: HttpsUrl.unsafe(this)

            url.normalize().toHttpsUrl()
        }

private const val keystoreDefaultLocation = "/keystore.jks"

@Suppress("SameParameterValue")
private fun loadJwkFromKeystore(environment: Environment, prefix: String): JWK {
    fun property(property: String): String =
        when {
            prefix.isBlank() -> property
            prefix.endsWith(".") -> "$prefix$property"
            else -> "$prefix.$property"
        }

    fun JWK.withCertificateChain(chain: List<X509Certificate>): JWK {
        require(this.parsedX509CertChain.isNotEmpty()) { "jwk must have a leaf certificate" }
        require(chain.isNotEmpty()) { "chain cannot be empty" }
        require(this.parsedX509CertChain.first() == chain.first()) {
            "leaf certificate of provided chain does not match leaf certificate of jwk"
        }

        val encodedChain = chain.map { Base64.encode(it.encoded) }
        return when (this) {
            is RSAKey -> RSAKey.Builder(this).x509CertChain(encodedChain).build()
            is ECKey -> ECKey.Builder(this).x509CertChain(encodedChain).build()
            is OctetKeyPair -> OctetKeyPair.Builder(this).x509CertChain(encodedChain).build()
            is OctetSequenceKey -> OctetSequenceKey.Builder(this).x509CertChain(encodedChain).build()
            else -> error("Unexpected JWK type '${this.keyType.value}'/'${this.javaClass}'")
        }
    }

    val keystoreResource = run {
        val keystoreLocation = environment.getRequiredProperty(property("keystore"))
        log.info("Will try to load Keystore from: '{}'", keystoreLocation)
        val keystoreResource = DefaultResourceLoader().getResource(keystoreLocation).some()
            .filter { it.exists() }
            .recover {
                log.warn(
                    "Could not find Keystore at '{}'. Fallback to '{}'",
                    keystoreLocation,
                    keystoreDefaultLocation,
                )
                FileSystemResource(keystoreDefaultLocation).some()
                    .filter { it.exists() }
                    .bind()
            }
            .getOrNull()
        checkNotNull(keystoreResource) { "Could not load Keystore either from '$keystoreLocation' or '$keystoreDefaultLocation'" }
    }

    val keystoreType = environment.getProperty(property("keystore.type"), KeyStore.getDefaultType())
    val keystorePassword = environment.getProperty(property("keystore.password"))?.takeIf { it.isNotBlank() }
    val keyAlias = environment.getRequiredProperty(property("alias"))
    val keyPassword = environment.getProperty(property("password"))?.takeIf { it.isNotBlank() }

    return keystoreResource.inputStream.use { inputStream ->
        val keystore = KeyStore.getInstance(keystoreType)
        keystore.load(inputStream, keystorePassword?.toCharArray())

        val jwk = JWK.load(keystore, keyAlias, keyPassword?.toCharArray())
        val chain = keystore.getCertificateChain(keyAlias).orEmpty()
            .map { certificate -> certificate as X509Certificate }
            .toList()

        when {
            chain.isNotEmpty() -> jwk.withCertificateChain(chain)
            else -> jwk
        }
    }
}

private enum class KeyOption {
    GenerateRandom,
    LoadFromKeystore,
}

fun BeanDefinitionDsl.initializer(): ApplicationContextInitializer<GenericApplicationContext> =
    ApplicationContextInitializer<GenericApplicationContext> { initialize(it) }

@SpringBootApplication
class WalletBackendApplication

fun main(args: Array<String>) {
    runApplication<WalletBackendApplication>(*args) {
        addInitializers(beans(Clock.systemDefaultZone()).initializer())
    }
}
