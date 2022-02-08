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
package app.cash.certifikit.cli.ct

import app.cash.certifikit.Certificate
import app.cash.certifikit.CertificateAdapters
import app.cash.certifikit.cli.Main
import app.cash.certifikit.cli.prettyPrint
import io.r2dbc.postgresql.PostgresqlConnectionConfiguration
import io.r2dbc.postgresql.PostgresqlConnectionFactory
import io.r2dbc.postgresql.api.PostgresqlConnection
import java.net.Inet4Address
import java.time.Duration.ofSeconds
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.reactive.awaitSingle
import kotlinx.coroutines.time.withTimeout
import kotlinx.coroutines.withContext
import okhttp3.Dns
import okio.ByteString
import okio.ByteString.Companion.toByteString
import picocli.CommandLine

@Suppress("unused")
suspend fun Main.crt(host: String): List<Pair<String, Certificate>> {
  return connectToCrtShDb().queryHostCertificates(host)
}

suspend fun PostgresqlConnection.queryHostCertificates(host: String): List<Pair<String, Certificate>> {
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
      it.map { t, _ ->
        val id = t.get("id")!!.toString()
        val cert = (t.get("certificate", ByteArray::class.java) as ByteArray).toByteString()
        Pair(id, cert)
      }
    }.collectList().awaitSingle()

  return certificates.map { (id, certBytes) ->
    Pair(id, certBytes.decodeCertificatePem())
  }.filter { it.second.matches(host) }
}

fun Certificate.matches(host: String): Boolean {
  this.subjectAlternativeNames?.forEach { (_, value) ->
    if (value == host) {
      return true
    } else if (value is String && value.startsWith("*.")) {
      val regex = ("[^.]+\\." + value.substring(2).replace(".", "\\.")).toRegex()
      return regex.matches(host)
    }
  }

  return false
}

fun ByteString.decodeCertificatePem(): Certificate {
  return CertificateAdapters.certificate.fromDer(this)
}

fun Inet4Address.ipAddress(): String {
  val src = this.address
  return "${(src[0] and 0xff)}.${src[1] and 0xff}.${src[2] and 0xff}.${src[3] and 0xff}"
}

// https://groups.google.com/g/crtsh/c/sUmV0mBz8bQ/m/K-6Vymd_AAAJ
suspend fun connectToCrtShDb(): PostgresqlConnection {
  // Avoid IPv6, since it is problematic.
  val hostname = "crt.sh"

  val ipv4host = withContext(Dispatchers.IO) { Dns.SYSTEM.lookup(hostname) }.firstOrNull {
    it is Inet4Address
  } as Inet4Address?

  val conf = PostgresqlConnectionConfiguration.builder()
    .host(ipv4host?.ipAddress() ?: hostname)
    .port(5432)
    .username("guest")
    .database("certwatch")
    .preparedStatementCacheQueries(0)
    .build()

  val connFactory = PostgresqlConnectionFactory(conf)

  return connFactory.create().awaitSingle()
}

suspend fun showCrtResponse(crtResponse: Deferred<List<Pair<String, Certificate>>>?) {
  if (crtResponse != null) {
    println()
    println("CT Logs:")

    try {
      // TODO(yschimke): Show from root CA with trusted CA highlighted, unsafe currently.
      val response =
        withTimeout(ofSeconds(5)) { crtResponse.await() }.groupBy { it.second.issuerCommonName }

      for ((issuer, certificates) in response) {
        println(issuer)
        certificates.forEach { (id, c) ->
          val validity = c.tbsCertificate.validity.prettyPrint()
          val link = "https://crt.sh/?id=$id"
          println("\t${c.commonName}\t$validity\t$link")
        }
      }
    } catch (e: TimeoutCancellationException) {
      System.err.println(
        CommandLine.Help.Ansi.AUTO.string(
          "@|yellow Timeout querying CT logs (${e.message})|@"
        )
      )
    } catch (e: Exception) {
      System.err.println(
        CommandLine.Help.Ansi.AUTO.string(
          "@|yellow Failed checking CT logs (${e.message})|@"
        )
      )
    }
  }
}

infix fun Byte.and(mask: Int): Int = toInt() and mask
