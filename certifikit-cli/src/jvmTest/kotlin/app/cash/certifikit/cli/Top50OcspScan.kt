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

import app.cash.certifikit.cli.oscp.OcspClient
import app.cash.certifikit.cli.oscp.OcspResponse
import java.util.concurrent.TimeUnit
import kotlin.system.exitProcess
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import okhttp3.OkHttpClient
import okio.FileSystem
import okio.Path.Companion.toPath

suspend fun main() {
  val fileSystem = FileSystem.SYSTEM

  coroutineScope {
    // https://en.wikipedia.org/wiki/List_of_most_popular_websites
    val hosts = fileSystem.read("certifikit-cli/src/test/resources/top50.csv".toPath()) {
      readUtf8().lines()
    }

    val client = OkHttpClient.Builder().callTimeout(2, TimeUnit.SECONDS).build()
    val ocspClient = OcspClient(client, secure = false)

    val requests = hosts.map { host ->
      Pair(host, async { ocspClient.submit(host) })
    }

    requests.forEach { (host, pendingResponse) ->
      val response = pendingResponse.await()

      if (response.status != OcspResponse.Status.GOOD) {
        println("$host: ${response.prettyPrint()}")
      } else {
        println("$host: GOOD from ${response.url?.host}")
      }
    }
  }

  exitProcess(1)
}
