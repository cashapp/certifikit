/*
 * Copyright (C) 2022 Square, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *      http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package app.cash.certifikit

import okio.Buffer
import okio.ByteString
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.ParseException
import java.text.SimpleDateFormat
import java.util.Date
import java.util.TimeZone

fun BitString.decodeKeyUsage(): List<KeyUsage> = bitSet.map { KeyUsage.values()[it] }

internal actual fun ByteString.toBitList(unusedBitsCount: Int): List<Int> {
  if (this.size == 0)
    return listOf()

  // Bits are encoded from the front, with lowest value bits possibly ignored.
  val maxResultBit = this.size * 8 - 1 - unusedBitsCount
  val bitField = BigInteger(this.toByteArray())

  return (0..maxResultBit).mapNotNull {
    val offset = (maxResultBit - it) + unusedBitsCount
    if (bitField.testBit(offset)) it else null
  }
}

actual typealias ProtocolException = java.net.ProtocolException

actual typealias BigInteger = BigInteger

internal actual fun BigInteger.toByteArray(): ByteArray = this.toByteArray()

internal actual fun BigInteger.toHexString(): String = this.toString(16)

internal actual fun ByteArray.toBigInteger(): BigInteger = BigInteger(this)

internal actual fun String.parseUtcTime(): Long {
  val utc = TimeZone.getTimeZone("GMT")
  val dateFormat = SimpleDateFormat("yyMMddHHmmss'Z'").apply {
    timeZone = utc
    set2DigitYearStart(Date(-631152000000L)) // 1950-01-01T00:00:00Z.
  }

  try {
    val parsed = dateFormat.parse(this)
    return parsed.time
  } catch (e: ParseException) {
    throw ProtocolException("Failed to parse UTCTime $this")
  }
}

internal actual fun Long.formatUtcTime(): String {
  val utc = TimeZone.getTimeZone("GMT")
  val dateFormat = SimpleDateFormat("yyMMddHHmmss'Z'").apply {
    timeZone = utc
    set2DigitYearStart(Date(-631152000000L)) // 1950-01-01T00:00:00Z.
  }

  return dateFormat.format(this)
}

internal actual fun String.parseGeneralizedTime(): Long {
  val utc = TimeZone.getTimeZone("GMT")
  val dateFormat = SimpleDateFormat("yyyyMMddHHmmss'Z'").apply {
    timeZone = utc
  }

  try {
    val parsed = dateFormat.parse(this)
    return parsed.time
  } catch (e: ParseException) {
    throw ProtocolException("Failed to parse GeneralizedTime $this")
  }
}

internal actual fun Long.formatGeneralizedTime(): String {
  val utc = TimeZone.getTimeZone("GMT")
  val dateFormat = SimpleDateFormat("yyyyMMddHHmmss'Z'").apply {
    timeZone = utc
  }

  return dateFormat.format(this)
}

fun Certificate.toX509Certificate(): X509Certificate {
  val data = CertificateAdapters.certificate.toDer(this)
  try {
    val certificateFactory = CertificateFactory.getInstance("X.509")
    val certificates = certificateFactory.generateCertificates(Buffer().write(data).inputStream())
    return certificates.single() as X509Certificate
  } catch (e: NoSuchElementException) {
    throw IllegalArgumentException("failed to decode certificate", e)
  } catch (e: IllegalArgumentException) {
    throw IllegalArgumentException("failed to decode certificate", e)
  } catch (e: GeneralSecurityException) {
    throw IllegalArgumentException("failed to decode certificate", e)
  }
}

/** Returns true if the certificate was signed by [issuer]. */
fun Certificate.checkSignature(issuer: PublicKey): Boolean {
  val signedData = CertificateAdapters.tbsCertificate.toDer(tbsCertificate)

  return Signature.getInstance(tbsCertificate.signatureAlgorithmName).run {
    initVerify(issuer)
    update(signedData.toByteArray())
    verify(signatureValue.byteString.toByteArray())
  }
}

internal actual fun BigInteger.testBit(bit: Int): Boolean = testBit(bit)

internal actual fun BigInteger.bitLength(): Int = bitLength()

actual typealias X509Certificate = X509Certificate

actual typealias PrivateKey = PrivateKey

actual typealias KeyPair = KeyPair
