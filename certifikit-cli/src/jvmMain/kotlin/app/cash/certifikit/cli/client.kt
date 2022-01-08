/*
 * Copyright (C) 2020 Square, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package app.cash.certifikit.cli

import java.util.concurrent.TimeUnit
import okhttp3.ConnectionSpec
import okhttp3.OkHttpClient
import okhttp3.tls.HandshakeCertificates

fun Main.buildClient(): OkHttpClient {
  return OkHttpClient.Builder()
      .connectTimeout(2, TimeUnit.SECONDS)
      .followRedirects(followRedirects)
      .eventListener(VerboseEventListener(verbose))
      .connectionSpecs(listOf(ConnectionSpec.MODERN_TLS,
          ConnectionSpec.CLEARTEXT)) // The specs may be overridden later.
      .apply {
        if (insecure) {
          hostnameVerifier { _, _ -> true }

          val handshakeCertificates = HandshakeCertificates.Builder()
              .addTrustedCertificates(trustManager)
              .addInsecureHost(host!!)
              .build()
          sslSocketFactory(handshakeCertificates.sslSocketFactory(),
              handshakeCertificates.trustManager)

          val spec = ConnectionSpec.Builder(ConnectionSpec.COMPATIBLE_TLS)
              .allEnabledCipherSuites()
              .allEnabledTlsVersions()
              .build()

          connectionSpecs(listOf(spec, ConnectionSpec.CLEARTEXT))
        } else if (keyStoreFile != null) {
          val handshakeCertificates = HandshakeCertificates.Builder()
              .addTrustedCertificates(trustManager)
              .build()
          sslSocketFactory(handshakeCertificates.sslSocketFactory(),
              handshakeCertificates.trustManager)
        }
      }
      .build()
}
