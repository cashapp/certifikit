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

import app.cash.certifikit.Certificate
import app.cash.certifikit.cli.errors.ClientException
import app.cash.certifikit.cli.errors.UsageException
import app.cash.certifikit.cli.oscp.toCertificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import okhttp3.MediaType.Companion.toMediaType

val Certificate.caIssuers: String?
  get() = authorityInfoAccess?.find { it.accessMethod == app.cash.certifikit.ObjectIdentifiers.caIssuers }?.accessLocation?.second?.toString()

suspend fun Main.fetchCertificates(url: String, fullChain: Boolean = false): List<Certificate> {
  try {
    client.execute(url.request()).use {
      val body = it.body ?: return listOf()

      val certs = when {
        body.contentType() == "application/pkix-cert".toMediaType() || body.contentType() == "application/pkcs7-mime".toMediaType() -> {
          val cf = CertificateFactory.getInstance("X.509")
          val certs = cf.generateCertificates(body.byteStream())
          certs.map { cert -> (cert as X509Certificate).toCertificate() }
        }
        body.contentType() == "application/x-pem-file".toMediaType() -> {
          listOf(it.bodyString().parsePemCertificate())
        }
        else -> {
          throw UsageException(
            "Response returned: " + body.contentType() + " expecting application/x-pem-file."
          )
        }
      }

      if (!fullChain) {
        return certs
      }

      val rest = certs.singleOrNull()?.caIssuers?.let { certificate ->
        fetchCertificates(certificate, fullChain = true)
      }.orEmpty()

      return certs + rest
    }
  } catch (ce: ClientException) {
    throw UsageException("Request Failed: " + ce.message)
  }
}
