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
package app.cash.certifikit.cli.oscp

import app.cash.certifikit.cli.SiteResponse
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import okhttp3.OkHttpClient

fun CoroutineScope.ocsp(
  client: OkHttpClient,
  siteResponse: SiteResponse
): Deferred<OcspResponse?> {
  val oscpClient = OcspClient(client)

  val peerCertificate = siteResponse.peerCertificates.getOrNull(0)
  val signingCertificate = siteResponse.peerCertificates.getOrNull(1)

  val ocspResponse = async {
    if (peerCertificate != null && signingCertificate != null) {
      oscpClient.submit(peerCertificate, signingCertificate)
    } else {
      OcspResponse.failure("no trusted certificates")
    }
  }
  return ocspResponse
}
