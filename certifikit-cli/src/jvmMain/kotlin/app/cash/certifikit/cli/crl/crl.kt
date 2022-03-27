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
package app.cash.certifikit.cli.crl

import app.cash.certifikit.AnyValue
import app.cash.certifikit.AttributeTypeAndValue
import app.cash.certifikit.DistributionPoint
import app.cash.certifikit.cli.SiteResponse
import app.cash.certifikit.cli.execute
import app.cash.certifikit.cli.request
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import java.io.IOException

suspend fun crl(
  client: OkHttpClient,
  siteResponse: SiteResponse
): List<CrlResponse>? {
  val peerCertificate = siteResponse.peerCertificates.getOrNull(0)

  val crls = peerCertificate?.crlDistributionPoints

  if (crls.isNullOrEmpty()) {
    return null
  }

  return withContext(Dispatchers.Default) {
    crls.map {
      async {
        fetchCrl(it, client)
      }
    }.awaitAll()
  }
}

private suspend fun fetchCrl(
  it: DistributionPoint,
  client: OkHttpClient
): CrlResponse {
  val distributionPoint = it.distributionPoint

  return when (distributionPoint) {
    is Pair<*, *> -> {
      val url = ((distributionPoint.second as Pair<*, *>).second as AnyValue).bytes.utf8()
      fetchCrl(url, client)
    }
    is List<*> -> {
      val cRLIssuer = distributionPoint.map { it as AttributeTypeAndValue }
      CrlResponse(cRLIssuer = cRLIssuer)
    }
    else -> CrlResponse(failure = IllegalStateException("CRL format not understood $distributionPoint"))
  }
}

private suspend fun fetchCrl(url : String, client: OkHttpClient): CrlResponse {
  val request = url.request { head() }
  val response = client.execute(request)

  return try {
    CrlResponse(url = request.url, response = response.also {
      response.body?.close()
    })
  } catch (e: IOException) {
    CrlResponse(url = request.url, failure = e)
  }
}
