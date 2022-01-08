/*
 * Copyright (C) 2022 Square, Inc.
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
import kotlin.test.Test
import kotlin.test.assertEquals

class KeyUsageTest {
  @Test
  fun testKnownValues() {
    assertEquals(
      BitString("80".decodeHex(), unusedBitsCount = 7).decodeKeyUsage(),
      listOf(DigitalSignature))
    assertEquals(
      BitString("06".decodeHex(), unusedBitsCount = 1).decodeKeyUsage(), listOf(
        KeyCertSign, CRLSign))
    assertEquals(
      BitString("86".decodeHex(), unusedBitsCount = 1).decodeKeyUsage(), listOf(
        DigitalSignature, KeyCertSign, CRLSign))
  }

  @Test
  fun testEdgeValues() {
    assertEquals(BitString("".decodeHex(), unusedBitsCount = 0).decodeKeyUsage(), listOf())
    assertEquals(
      BitString("FF80".decodeHex(), unusedBitsCount = 7).decodeKeyUsage(), listOf(*KeyUsage.values()))
  }
}
