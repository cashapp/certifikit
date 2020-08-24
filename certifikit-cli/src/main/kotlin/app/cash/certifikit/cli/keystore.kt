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

import java.io.File
import java.security.KeyStore
import javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

fun File.trustManager(): X509TrustManager {
    val factory = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm())

    val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
    this.inputStream().use {
        keyStore.load(it, null)
    }
    factory.init(keyStore)

    val trustManagers = factory.trustManagers!!
    check(trustManagers.size == 1 && trustManagers[0] is X509TrustManager) {
        "Unexpected default trust managers: ${trustManagers.contentToString()}"
    }
    return trustManagers[0] as X509TrustManager
}
