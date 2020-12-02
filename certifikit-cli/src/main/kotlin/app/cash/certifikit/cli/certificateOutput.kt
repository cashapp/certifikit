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

import app.cash.certifikit.BasicDerAdapter
import app.cash.certifikit.Certificate
import app.cash.certifikit.ObjectIdentifiers
import app.cash.certifikit.decodeKeyUsage
import java.net.InetAddress
import java.security.cert.X509Certificate
import java.time.Instant.ofEpochMilli
import javax.net.ssl.X509TrustManager
import okio.ByteString
import okio.ByteString.Companion.toByteString
import picocli.CommandLine.Help.Ansi

fun X509Certificate.publicKeySha256(): ByteString =
  publicKey.encoded.toByteString()
      .sha256()

fun Certificate.prettyPrintCertificate(
  trustManager: X509TrustManager
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
    append("Serial:\t${serialNumberString}\n")
    append("Pin:\tsha256/${sha256.hex()}\n")
    append("SAN: \t${subjectAlternativeNameValue()?.joinToString(", ") ?: "<N/A>"}\n")
    if (organizationalUnitName != null) {
      append("OU: \t$organizationalUnitName\n")
    }

    keyUsage?.let {
      append("Key Usage: ${it.decodeKeyUsage().joinToString(", ")}\n")
    }
    extKeyUsage?.let {
      append("Ext Key Usage: ${it.joinToString(", ")}\n")
    }

    authorityInfoAccess?.let {
      append("Authority Info Access:\n")
      it.forEach { accessDescription ->
        append("\t${accessDescription.name}: ${accessDescription.accessLocation.second}\n")
      }
    }

    val periodLeft = tbsCertificate.validity.periodLeft
    val periodLeftString = when {
      periodLeft == null -> Ansi.AUTO.string(" (@|red Not valid|@)")
      periodLeft.years >= 1 -> " (${periodLeft.years} years)"
      periodLeft.months >= 1 -> " (${periodLeft.months} months)"
      periodLeft.days < 20 -> Ansi.AUTO.string(" (@|yellow $periodLeft days|@)")
      else -> " (${periodLeft.days})"
    }
    append(
        "Valid: \t${
          ofEpochMilli(tbsCertificate.validity.notBefore)
        }..${
          ofEpochMilli(tbsCertificate.validity.notAfter)
        }$periodLeftString"
    )

    basicConstraints?.apply {
      append("\nCA: $ca")
      if (maxIntermediateCas != null) append(" Max Intermediate: $maxIntermediateCas")
    }
  }
}

private fun Certificate.subjectAlternativeNameValue(): List<String>? {
  return tbsCertificate.extensions.firstOrNull {
    it.id == ObjectIdentifiers.subjectAlternativeName
  }
      ?.let {
        @Suppress("UNCHECKED_CAST")
        it.value as List<Pair<Any, Any>>
      }
      ?.map { (adapter, value) ->
        if (adapter is BasicDerAdapter<*> && adapter.tag == 7L) {
          val bytes = (value as ByteString).toByteArray()
          InetAddress.getByAddress(bytes).toString()
        } else {
          value.toString()
        }
      }
}
