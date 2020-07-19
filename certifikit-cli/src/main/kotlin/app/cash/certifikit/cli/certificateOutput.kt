package app.cash.certifikit.cli

import app.cash.certifikit.Certificate
import app.cash.certifikit.ObjectIdentifiers
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.security.cert.X509Certificate
import java.time.Instant

fun Certificate.prettyPrintCertificate(): String {
  return buildString {
    append("CN: \t$commonName\n")
    append("SN: \t${tbsCertificate.serialNumber.toString(16)}\n")
    append("SAN: \t${subjectAltNames()?.joinToString(", ") ?: "<N/A>"}\n")
    if (organizationalUnitName != null) {
      append("OU: \t$organizationalUnitName\n")
    }

    append(
        "Valid: \t${
          Instant.ofEpochMilli(tbsCertificate.validity.notBefore)
        }..${
          Instant.ofEpochMilli(tbsCertificate.validity.notAfter)
        }"
    )
  }
}

private fun Certificate.subjectAltNames(): List<String>? {
  return tbsCertificate.extensions.firstOrNull {
    it.id == ObjectIdentifiers.subjectAlternativeName
  }
      ?.let {
        @Suppress("UNCHECKED_CAST")
        it.value as List<Pair<Any, Any>>
      }
      ?.map {
        it.second.toString()
      }
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
