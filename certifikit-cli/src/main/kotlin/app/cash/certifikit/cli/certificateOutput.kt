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
import app.cash.certifikit.ObjectIdentifiers
import app.cash.certifikit.decodeKeyUsage
import java.security.cert.X509Certificate
import java.time.Instant.ofEpochMilli
import javax.net.ssl.X509TrustManager
import okhttp3.internal.platform.Platform
import okio.ByteString
import okio.ByteString.Companion.toByteString
import picocli.CommandLine.Help.Ansi

fun X509Certificate.publicKeySha256(): ByteString =
  publicKey.encoded.toByteString()
      .sha256()

fun Certificate.prettyPrintCertificate(
  trustManager: X509TrustManager = Platform.get()
      .platformTrustManager()
): String {
  val sha256 = this.publicKeySha256()

  return buildString {
    val trustedRoot = trustManager.acceptedIssuers.find {
      it.publicKeySha256() == sha256
    } != null
    val trusted = if (trustedRoot) {
      Ansi.AUTO.string(" @|green (signed by locally-trusted root)|@")
    } else {
      ""
    }

    append("CN: \t$commonName$trusted\n")
    append("SHA256:\t${sha256.hex()}\n")
    append("SAN: \t${subjectAlternativeNameValue()?.joinToString(", ") ?: "<N/A>"}\n")
    if (organizationalUnitName != null) {
      append("OU: \t$organizationalUnitName\n")
    }

    keyUsage?.let {
      append("Key Usage: ${it.decodeKeyUsage().joinToString(", ")}\n")
    }

    append(
        "Valid: \t${
          ofEpochMilli(tbsCertificate.validity.notBefore)
        }..${
          ofEpochMilli(tbsCertificate.validity.notAfter)
        }"
    )

    basicConstraints?.apply {
      append("\nCA: $ca")
      if (maxIntermediateCas != null) append(" Max Intermediate: $maxIntermediateCas")
    }
  }
}

private fun Certificate.subjectAlternativeNameValue() =
  tbsCertificate.extensions.firstOrNull {
    it.id == ObjectIdentifiers.subjectAlternativeName
  }
      ?.let {
        @Suppress("UNCHECKED_CAST")
        it.value as List<Pair<Any, Any>>
      }
      ?.map {
        it.second.toString()
      }

/**
 * Returns the certificate encoded in [PEM format][rfc_7468].
 *
 * [rfc_7468]: https://tools.ietf.org/html/rfc7468
 */
fun X509Certificate.certificatePem(): String {
  return buildString {
    append("-----BEGIN CERTIFICATE-----\n")
    encodeBase64Lines(encoded.toByteString())
    append("-----END CERTIFICATE-----\n")
  }
}

fun StringBuilder.encodeBase64Lines(data: ByteString) {
  val base64 = data.base64()
  for (i in 0 until base64.length step 64) {
    append(base64, i, minOf(i + 64, base64.length)).append('\n')
  }
}
