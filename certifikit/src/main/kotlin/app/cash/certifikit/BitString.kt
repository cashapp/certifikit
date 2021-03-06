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

import java.math.BigInteger
import okio.ByteString

/**
 * Like a [ByteString], but whose bits are not necessarily a strict multiple of 8.
 */
data class BitString(
  val byteString: ByteString,

  /** 0-7 unused bits in the last byte. */
  val unusedBitsCount: Int = 0
) {
  // Avoid Long.hashCode(long) which isn't available on Android 5.
  override fun hashCode(): Int {
    var result = 0
    result = 31 * result + byteString.hashCode()
    result = 31 * result + unusedBitsCount
    return result
  }

  val bitSet: List<Int>
  get() {
    if (byteString.size == 0)
      return listOf()

    // Bits are encoded from the front, with lowest value bits possibly ignored.
    val maxResultBit = byteString.size * 8 - 1 - this.unusedBitsCount
    val bitField = BigInteger(byteString.toByteArray())

    return (0..maxResultBit).mapNotNull {
      val offset = (maxResultBit - it) + unusedBitsCount
      if (bitField.testBit(offset)) it else null
    }
  }
}
