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

import java.io.File
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.Test
import picocli.CommandLine

class MainTest {
  @Test fun version() {
    CommandLine(Main()).execute("-V")
  }

  @Test fun certificate() {
    fromArgs("src/test/resources/cert.pem").call()
  }

  @Test fun https() {
    fromArgs("--host", "www.google.com").call()
  }

  @Test fun testFetch() {
    MockWebServer().use { server ->
      server.enqueue(MockResponse().setBody(File("src/test/resources/cert.pem").readText()))
      server.start()

      fromArgs(server.url("/cert.pem").toString()).call()
    }
  }

  @Test fun testFetch404() {
    MockWebServer().use { server ->
      server.enqueue(MockResponse().setResponseCode(404))
      server.start()

      fromArgs(server.url("/cert.pem").toString()).call()
    }
  }

  companion object {
    fun fromArgs(vararg args: String?): Main {
      return CommandLine.populateCommand(Main(), *args)
    }
  }
}
