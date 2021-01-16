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
import app.cash.certifikit.cli.Main
import app.cash.certifikit.cli.await
import app.cash.certifikit.cli.moshi.parseList
import app.cash.certifikit.cli.parsePemCertificate
import app.cash.certifikit.cli.readString
import com.squareup.moshi.JsonClass
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.datetime.Instant
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.Request
import okhttp3.Response
import java.util.concurrent.TimeUnit
import kotlin.time.ExperimentalTime

@JsonClass(generateAdapter = true)
data class CTCertificate(
  val issuer_ca_id: Long,
  val issuer_name: String,
  val common_name: String,
  val name_value: String,
  val id: Long,
  val entry_timestamp: String,
  val not_before: Instant,
  val not_after: Instant,
  val serial_number: String,
) {
  val pemUrl = "https://crt.sh/?d=$id".toHttpUrl()
}

@OptIn(ExperimentalTime::class)
suspend fun Main.crt(host: String): List<Certificate> {
  val url = "https://crt.sh/?dnsname=$host&match=LIKE&output=json&exclude=expired".toHttpUrl()

  val request = url.request().newBuilder().header("User-Agent", "curl/7.64.1").build()

  val response = this.baseClient.newCall(request).await()

  val certificates = response.use<Response, List<CTCertificate>> { it.parseList() }

  val client = baseClient.newBuilder()
    .writeTimeout(20, TimeUnit.SECONDS)
    .readTimeout(20, TimeUnit.SECONDS)
    .callTimeout(20, TimeUnit.SECONDS)
    .build()

  return coroutineScope {
    certificates.map {
      async {
        client.newCall(it.pemUrl.request()).await().readString()
      }
    }.awaitAll().map {
      it.parsePemCertificate()
    }
  }
}

private fun HttpUrl.request() = Request.Builder()
  .url(this)
  .build()