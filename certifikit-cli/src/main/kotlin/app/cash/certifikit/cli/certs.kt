package app.cash.certifikit.cli

import app.cash.certifikit.Certificate
import app.cash.certifikit.CertificateAdapters
import app.cash.certifikit.cli.errors.UsageException
import okio.ByteString.Companion.decodeBase64

internal fun String.parsePemCertificate(fileName: String? = null): Certificate {
    val regex = """-----BEGIN CERTIFICATE-----(.*)-----END CERTIFICATE-----""".toRegex(RegexOption.DOT_MATCHES_ALL)
    val matchResult = regex.find(this) ?: throw UsageException("Invalid format" +
            if (fileName != null) ": $fileName" else "")
    val (pemBody) = matchResult.destructured

    val data = pemBody.decodeBase64()!!

    return CertificateAdapters.certificate.fromDer(data)
}