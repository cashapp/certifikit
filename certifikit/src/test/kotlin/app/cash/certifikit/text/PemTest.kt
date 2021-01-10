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
package app.cash.certifikit.text

import java.security.KeyPair
import java.security.cert.X509Certificate
import okio.ExperimentalFileSystem
import okio.FileSystem
import okio.Path
import okio.Path.Companion.toPath
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

@OptIn(ExperimentalFileSystem::class)
class PemTest {
  val fileSystem = FileSystem.SYSTEM

  @Test
  fun parseHeldCertificate() {
    val (pkcs8pair, cert1) = decode("src/test/resources/pkcs8pair.pem".toPath())
    val (pkcs1pair, cert2) = decode("src/test/resources/pkcs1pair.pem".toPath())

    assertThat(cert1).isEqualTo(cert2)
    assertThat(pkcs1pair.private).isEqualTo(pkcs8pair.private)
    assertThat(pkcs1pair.public).isEqualTo(pkcs8pair.public)
  }

  private fun decode(file: Path): Pair<KeyPair, X509Certificate> {
    return fileSystem.read(file) {
      decode(readUtf8())
    }
  }
}
