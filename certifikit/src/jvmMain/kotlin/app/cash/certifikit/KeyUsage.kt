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

enum class KeyUsage(val bit: Int) {
  DigitalSignature(0),
  NonRepudiation(1),
  KeyEncipherment(2),
  DataEncipherment(3),
  KeyAgreement(4),
  KeyCertSign(5),
  CRLSign(6),
  EncipherOnly(7),
  DecipherOnly(8)
}

fun BitString.decodeKeyUsage(): List<KeyUsage> = bitSet.map { KeyUsage.values()[it] }
