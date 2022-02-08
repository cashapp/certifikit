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

import okio.FileSystem
import okio.Path.Companion.toPath
import org.assertj.core.api.Assertions.assertThat
import kotlin.test.Test

class TestCerts {
  val fileSystem = FileSystem.SYSTEM

  @Test
  fun parseCert() {
    val cert = fileSystem.read("src/jvmTest/resources/cert.pem".toPath()) {
      readUtf8().parsePemCertificate()
    }
    assertThat(cert.signatureAlgorithm.algorithm).isEqualTo("1.2.840.113549.1.1.11")
  }
}
