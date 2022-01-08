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

import okio.ByteString
import okio.IOException

internal expect fun ByteString.toBitList(unusedBitsCount: Int): List<Int>

expect class ProtocolException(message: String? = null) : IOException

expect class BigInteger

internal expect fun BigInteger.toByteArray(): ByteArray

internal expect fun BigInteger.testBit(bit: Int): Boolean

internal expect fun BigInteger.bitLength(): Int

internal expect fun BigInteger.toHexString(): String

internal expect fun ByteArray.toBigInteger(): BigInteger

internal expect fun String.parseUtcTime(): Long

internal expect fun Long.formatUtcTime(): String

internal expect fun Long.formatGeneralizedTime(): String

internal expect fun String.parseGeneralizedTime(): Long
