package app.cash.certifikit.cli.ct

import app.cash.certifikit.Certificate
import app.cash.certifikit.CertificateAdapters
import app.cash.certifikit.cli.Main
import io.r2dbc.postgresql.PostgresqlConnectionConfiguration
import io.r2dbc.postgresql.PostgresqlConnectionFactory
import io.r2dbc.postgresql.api.PostgresqlConnection
import kotlinx.coroutines.reactive.awaitSingle
import okio.ByteString
import okio.ByteString.Companion.toByteString

@Suppress("unused")
suspend fun Main.crt(host: String): List<Certificate> {
  return connectToCrtShDb().queryHostCertificates(host)
}

suspend fun PostgresqlConnection.queryHostCertificates(host: String): List<Certificate> {
  val query = """
    SELECT min(CERTIFICATE_ID) ID,
           min(ISSUER_CA_ID) ISSUER_CA_ID,
           min(NAME_VALUE) NAME_VALUE,
           array_agg(DISTINCT NAME_VALUE) NAME_VALUES,
           x509_commonName(CERTIFICATE) COMMON_NAME,
           x509_notBefore(CERTIFICATE) NOT_BEFORE,
           x509_notAfter(CERTIFICATE) NOT_AFTER,
           CERTIFICATE certificate,
           encode(x509_serialNumber(CERTIFICATE), 'hex') SERIAL_NUMBER
    FROM certificate_and_identities cai
    WHERE plainto_tsquery('certwatch', $2) @@ identities(cai.CERTIFICATE)
        AND (NAME_VALUE = $1 OR NAME_VALUE = $3)
        AND NAME_TYPE = 'san:dNSName'
        AND x509_notAfter(CERTIFICATE) >= now() AT TIME ZONE 'UTC'
    GROUP BY CERTIFICATE
  """.trimIndent()

  val shortHost = host.replace("^[^.]+.".toRegex(), "")
  val wildcard = "*.$shortHost"

  val certificates = createStatement(query)
    .bind("$1", host)
    .bind("$2", shortHost)
    .bind("$3", wildcard)
    .execute().flatMap {
      it.map { t, u ->
        (t.get("certificate", ByteArray::class.java) as ByteArray).toByteString()
      }
    }.map { it.decodeCertificatePem() }.collectList().awaitSingle()

  return certificates.filter { it.matches(host) }
}

fun Certificate.matches(host: String): Boolean {
  // TODO check exact hostname match here
  return true
}

fun ByteString.decodeCertificatePem(): Certificate {
  return CertificateAdapters.certificate.fromDer(this)
}

suspend fun connectToCrtShDb(): PostgresqlConnection {
  val conf = PostgresqlConnectionConfiguration.builder()
    // Failing on IPv6
    // .host("crt.sh")
    .host("91.199.212.73")
    .port(5432)
    .username("guest")
    .database("certwatch")
    .preparedStatementCacheQueries(0)
    .build()

  val connFactory = PostgresqlConnectionFactory(conf)

  return connFactory.create().awaitSingle().apply {
    isAutoCommit = true
  }
}
