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

import kotlinx.datetime.Clock
import kotlinx.datetime.DateTimePeriod
import kotlinx.datetime.Instant
import kotlinx.datetime.TimeZone
import kotlinx.datetime.periodUntil
import okio.ByteString

data class Certificate(
  val tbsCertificate: TbsCertificate,
  val signatureAlgorithm: AlgorithmIdentifier,
  val signatureValue: BitString
) {
  /**
   * Certificate hash as used in HTTP Public Key Pinning.
   */
  fun publicKeySha256(): ByteString =
    CertificateAdapters.subjectPublicKeyInfo.toDer(tbsCertificate.subjectPublicKeyInfo).sha256()

  val serialNumberString: String
    get() {
      return tbsCertificate.serialNumber.run {
        "${if (testBit(bitLength() - 1)) "00" else ""}${toHexString()}"
      }
    }

  val commonName: String?
    get() {
      return tbsCertificate.subject
        .flatten()
        .firstOrNull { it.type == ObjectIdentifiers.commonName }
        ?.value?.toString() // This allows for legacy encodings like Teletex but left fugly.
    }

  val issuerCommonName: String?
    get() {
      return tbsCertificate.issuer
        .flatten()
        .firstOrNull { it.type == ObjectIdentifiers.commonName }
        ?.value?.toString() // This allows for legacy encodings like Teletex but left fugly.
    }

  val organizationalUnitName: String?
    get() {
      return tbsCertificate.subject
        .flatten()
        .firstOrNull { it.type == ObjectIdentifiers.organizationalUnitName }
        ?.value as String?
    }

  val keyUsage: BitString?
    get() {
      return tbsCertificate.extensions
        .firstOrNull { it.id == ObjectIdentifiers.keyUsage }
        ?.value as BitString?
    }

  val authorityInfoAccess: List<AccessDescription>?
    get() {
      val value = tbsCertificate.extensions
        .firstOrNull { it.id == ObjectIdentifiers.authorityInfoAccess }
        ?.value
      return value as List<AccessDescription>?
    }

  @Suppress("UNCHECKED_CAST")
  val extKeyUsage: List<ExtKeyUsage>?
    get() {
      val list = tbsCertificate.extensions
        .firstOrNull { it.id == ObjectIdentifiers.extKeyUsage }
        ?.value as List<String>?
      return list?.map { ExtKeyUsage(it) }
    }

  @Suppress("UNCHECKED_CAST")
  val subjectAlternativeNames: List<Pair<Any, Any>>?
    get() = tbsCertificate.extensions.firstOrNull {
      it.id == ObjectIdentifiers.subjectAlternativeName
    }?.value as List<Pair<Any, Any>>?

  val basicConstraints: BasicConstraints?
    get() = tbsCertificate.extensions.firstOrNull {
      it.id == ObjectIdentifiers.basicConstraints
    }?.value as? BasicConstraints
}

data class TbsCertificate(
  /** This is a integer enum. Use 0L for v1, 1L for v2, and 2L for v3. */
  val version: Long,
  val serialNumber: BigInteger,
  val signature: AlgorithmIdentifier,
  val issuer: List<List<AttributeTypeAndValue>>,
  val validity: Validity,
  val subject: List<List<AttributeTypeAndValue>>,
  val subjectPublicKeyInfo: SubjectPublicKeyInfo,
  val issuerUniqueID: BitString?,
  val subjectUniqueID: BitString?,
  val extensions: List<Extension>
) {
  /**
   * Returns the standard name of this certificate's signature algorithm as specified by
   * [Signature.getInstance]. Typical values are like "SHA256WithRSA".
   */
  val signatureAlgorithmName: String
    get() {
      return when (signature.algorithm) {
        ObjectIdentifiers.sha256WithRSAEncryption -> "SHA256WithRSA"
        ObjectIdentifiers.sha256withEcdsa -> "SHA256withECDSA"
        else -> error("unexpected signature algorithm: ${signature.algorithm}")
      }
    }

  // Avoid Long.hashCode(long) which isn't available on Android 5.
  override fun hashCode(): Int {
    var result = 0
    result = 31 * result + version.toInt()
    result = 31 * result + serialNumber.hashCode()
    result = 31 * result + signature.hashCode()
    result = 31 * result + issuer.hashCode()
    result = 31 * result + validity.hashCode()
    result = 31 * result + subject.hashCode()
    result = 31 * result + subjectPublicKeyInfo.hashCode()
    result = 31 * result + (issuerUniqueID?.hashCode() ?: 0)
    result = 31 * result + (subjectUniqueID?.hashCode() ?: 0)
    result = 31 * result + extensions.hashCode()
    return result
  }
}

data class AlgorithmIdentifier(
  /** An OID string like "1.2.840.113549.1.1.11" for sha256WithRSAEncryption. */
  val algorithm: String,
  /** Parameters of a type implied by [algorithm]. */
  val parameters: Any?
)

data class AttributeTypeAndValue(
  /** An OID string like "2.5.4.11" for organizationalUnitName. */
  val type: String,
  val value: Any?
)

data class Validity(
  val notBefore: Long,
  val notAfter: Long
) {
  /**
   * Returns the remaining Period, or null if the certificate is not within the valid period.
   */
  val periodLeft: DateTimePeriod?
    get() {
      val now = Clock.System.now()
      val notBeforeInstant = Instant.fromEpochMilliseconds(notBefore)
      val notAfterInstant = Instant.fromEpochMilliseconds(notAfter)

      return when {
        now < notBeforeInstant -> null
        now > notAfterInstant -> null
        else -> now.periodUntil(notAfterInstant, TimeZone.currentSystemDefault())
      }
    }

  // Avoid Long.hashCode(long) which isn't available on Android 5.
  override fun hashCode(): Int {
    var result = 0
    result = 31 * result + notBefore.toInt()
    result = 31 * result + notAfter.toInt()
    return result
  }
}

data class SubjectPublicKeyInfo(
  val algorithm: AlgorithmIdentifier,
  val subjectPublicKey: BitString
)

data class Extension(
  val id: String,
  val critical: Boolean,
  val value: Any?
)

data class BasicConstraints(
  /** True if this certificate can be used as a Certificate Authority (CA). */
  val ca: Boolean,
  /** The maximum number of intermediate CAs between this and leaf certificates. */
  val maxIntermediateCas: Long?
)

/** A private key. Note that this class doesn't support attributes or an embedded public key. */
data class PrivateKeyInfo(
  val version: Long, // v1(0), v2(1)
  val algorithmIdentifier: AlgorithmIdentifier, // v1(0), v2(1)
  val privateKey: ByteString
) {
  // Avoid Long.hashCode(long) which isn't available on Android 5.
  override fun hashCode(): Int {
    var result = 0
    result = 31 * result + version.toInt()
    result = 31 * result + algorithmIdentifier.hashCode()
    result = 31 * result + privateKey.hashCode()
    return result
  }
}

data class AccessDescription(
  val accessMethod: String,
  val accessLocation: Pair<Any, Any>
) {
  val name: String
    get() = when (accessMethod) {
      ObjectIdentifiers.ocsp -> "ocsp"
      ObjectIdentifiers.caIssuers -> "caIssuers"
      else -> accessMethod
    }
}
