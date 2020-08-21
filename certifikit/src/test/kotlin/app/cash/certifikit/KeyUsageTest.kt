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
package app.cash.certifikit

import app.cash.certifikit.KeyUsage.CRLSign
import app.cash.certifikit.KeyUsage.DigitalSignature
import app.cash.certifikit.KeyUsage.KeyCertSign
import okio.ByteString.Companion.decodeHex
import org.assertj.core.api.Assertions.assertThat
import org.junit.Test

class KeyUsageTest {
  @Test
  fun testKnownValues() {
    assertThat(BitString("80".decodeHex(), unusedBitsCount = 7).decodeKeyUsage()).containsExactly(
        DigitalSignature)
    assertThat(BitString("06".decodeHex(), unusedBitsCount = 1).decodeKeyUsage()).containsExactly(
        KeyCertSign, CRLSign)
    assertThat(BitString("86".decodeHex(), unusedBitsCount = 1).decodeKeyUsage()).containsExactly(
        DigitalSignature, KeyCertSign, CRLSign)
  }

  @Test
  fun testEdgeValues() {
    assertThat(BitString("".decodeHex(), unusedBitsCount = 0).decodeKeyUsage()).isEmpty()
    assertThat(BitString("FF80".decodeHex(), unusedBitsCount = 7).decodeKeyUsage()).containsExactly(
        *KeyUsage.values())
  }
}
