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

@file:JvmName("Pem")

package app.cash.certifikit.text

import app.cash.certifikit.AlgorithmIdentifier
import app.cash.certifikit.CertificateAdapters
import app.cash.certifikit.PrivateKeyInfo
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import okio.Buffer
import okio.ByteString
import okio.ByteString.Companion.decodeBase64
import okio.ByteString.Companion.toByteString

/**
 * Decodes a multiline string that contains a [certificate][certificatePem] which is
 * [PEM-encoded][rfc_7468]. A typical input string looks like this:
 *
 * ```
 * -----BEGIN CERTIFICATE-----
 * MIIBYTCCAQegAwIBAgIBKjAKBggqhkjOPQQDAjApMRQwEgYDVQQLEwtlbmdpbmVl
 * cmluZzERMA8GA1UEAxMIY2FzaC5hcHAwHhcNNzAwMTAxMDAwMDA1WhcNNzAwMTAx
 * MDAwMDEwWjApMRQwEgYDVQQLEwtlbmdpbmVlcmluZzERMA8GA1UEAxMIY2FzaC5h
 * cHAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASda8ChkQXxGELnrV/oBnIAx3dD
 * ocUOJfdz4pOJTP6dVQB9U3UBiW5uSX/MoOD0LL5zG3bVyL3Y6pDwKuYvfLNhoyAw
 * HjAcBgNVHREBAf8EEjAQhwQBAQEBgghjYXNoLmFwcDAKBggqhkjOPQQDAgNIADBF
 * AiAyHHg1N6YDDQiY920+cnI5XSZwEGhAtb9PYWO8bLmkcQIhAI2CfEZf3V/obmdT
 * yyaoEufLKVXhrTQhRfodTeigi4RX
 * -----END CERTIFICATE-----
 * ```
 */
actual fun String.decodeCertificatePem(): X509Certificate {
  try {
    val certificateFactory = CertificateFactory.getInstance("X.509")
    val certificates = certificateFactory
        .generateCertificates(
            Buffer().writeUtf8(this).inputStream())

    return certificates.single() as X509Certificate
  } catch (nsee: NoSuchElementException) {
    throw IllegalArgumentException("failed to decode certificate", nsee)
  } catch (iae: IllegalArgumentException) {
    throw IllegalArgumentException("failed to decode certificate", iae)
  } catch (e: GeneralSecurityException) {
    throw IllegalArgumentException("failed to decode certificate", e)
  }
}

/**
 * Returns the certificate encoded in [PEM format][rfc_7468].
 *
 * [rfc_7468]: https://tools.ietf.org/html/rfc7468
 */
actual fun X509Certificate.certificatePem(): String {
  return buildString {
    append("-----BEGIN CERTIFICATE-----\n")
    encodeBase64Lines(encoded.toByteString())
    append("-----END CERTIFICATE-----\n")
  }
}

/**
 * Returns the RSA private key encoded in [PKCS #8][rfc_5208] [PEM format][rfc_7468].
 *
 * [rfc_5208]: https://tools.ietf.org/html/rfc5208
 * [rfc_7468]: https://tools.ietf.org/html/rfc7468
 */
actual fun PrivateKey.privateKeyPkcs8Pem(): String {
  return buildString {
    append("-----BEGIN PRIVATE KEY-----\n")
    encodeBase64Lines(encoded.toByteString())
    append("-----END PRIVATE KEY-----\n")
  }
}

/**
 * Returns the RSA private key encoded in [PKCS #1][rfc_8017] [PEM format][rfc_7468].
 *
 * [rfc_8017]: https://tools.ietf.org/html/rfc8017
 * [rfc_7468]: https://tools.ietf.org/html/rfc7468
 */
actual fun PrivateKey.privateKeyPkcs1Pem(): String {
  check(this is RSAPrivateKey) { "PKCS1 only supports RSA keys" }
  return buildString {
    append("-----BEGIN RSA PRIVATE KEY-----\n")
    encodeBase64Lines(pkcs1Bytes())
    append("-----END RSA PRIVATE KEY-----\n")
  }
}

internal actual fun PrivateKey.pkcs1Bytes(): ByteString {
  val decoded = CertificateAdapters.privateKeyInfo.fromDer(this.encoded.toByteString())
  return decoded.privateKey
}

/**
 * Decodes a multiline string that contains both a [certificate][certificatePem] and a
 * [private key][privateKeyPkcs8Pem], both [PEM-encoded][rfc_7468]. A typical input string looks
 * like this:
 *
 * ```
 * -----BEGIN CERTIFICATE-----
 * MIIBYTCCAQegAwIBAgIBKjAKBggqhkjOPQQDAjApMRQwEgYDVQQLEwtlbmdpbmVl
 * cmluZzERMA8GA1UEAxMIY2FzaC5hcHAwHhcNNzAwMTAxMDAwMDA1WhcNNzAwMTAx
 * MDAwMDEwWjApMRQwEgYDVQQLEwtlbmdpbmVlcmluZzERMA8GA1UEAxMIY2FzaC5h
 * cHAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASda8ChkQXxGELnrV/oBnIAx3dD
 * ocUOJfdz4pOJTP6dVQB9U3UBiW5uSX/MoOD0LL5zG3bVyL3Y6pDwKuYvfLNhoyAw
 * HjAcBgNVHREBAf8EEjAQhwQBAQEBgghjYXNoLmFwcDAKBggqhkjOPQQDAgNIADBF
 * AiAyHHg1N6YDDQiY920+cnI5XSZwEGhAtb9PYWO8bLmkcQIhAI2CfEZf3V/obmdT
 * yyaoEufLKVXhrTQhRfodTeigi4RX
 * -----END CERTIFICATE-----
 * -----BEGIN PRIVATE KEY-----
 * MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCA7ODT0xhGSNn4ESj6J
 * lu/GJQZoU9lDrCPeUcQ28tzOWw==
 * -----END PRIVATE KEY-----
 * ```
 *
 * The string should contain exactly one certificate and one private key in [PKCS #8][rfc_5208]
 * format. It should not contain any other PEM-encoded blocks, but it may contain other text
 * which will be ignored.
 *
 * Encode a held certificate into this format by concatenating the results of
 * [certificatePem()][certificatePem] and [privateKeyPkcs8Pem()][privateKeyPkcs8Pem].
 *
 * [rfc_7468]: https://tools.ietf.org/html/rfc7468
 * [rfc_5208]: https://tools.ietf.org/html/rfc5208
 */
actual fun decode(certificateAndPrivateKeyPem: String): Pair<KeyPair, X509Certificate> {
  var certificatePem: String? = null
  var pkcs8Base64: String? = null
  var pkcs1Base64: String? = null
  for (match in PEM_REGEX.findAll(certificateAndPrivateKeyPem)) {
    when (val label = match.groups[1]!!.value) {
      "CERTIFICATE" -> {
        require(certificatePem == null) { "string includes multiple certificates" }
        certificatePem = match.groups[0]!!.value // Keep --BEGIN-- and --END-- for certificates.
      }
      "PRIVATE KEY" -> {
        require(pkcs8Base64 == null && pkcs1Base64 == null) { "string includes multiple private keys" }
        pkcs8Base64 = match.groups[2]!!.value // Include the contents only for PKCS8.
      }
      "RSA PRIVATE KEY" -> {
        require(pkcs8Base64 == null && pkcs1Base64 == null) { "string includes multiple private keys" }
        pkcs1Base64 = match.groups[2]!!.value // Include the contents only for PKCS1.
      }
      else -> {
        throw IllegalArgumentException("unexpected type: $label")
      }
    }
  }
  require(certificatePem != null) { "string does not include a certificate" }

  val certificate = certificatePem.decodeCertificatePem()
  when {
    pkcs8Base64 != null -> {
      val keyType = when (certificate.publicKey) {
        is ECPublicKey -> "EC"
        is RSAPublicKey -> "RSA"
        else -> throw IllegalArgumentException("unexpected key type: ${certificate.publicKey}")
      }

      val pkcs8Bytes = pkcs8Base64.decodeBase64()
          ?: throw IllegalArgumentException("failed to decode private key")
      val privateKey = decodePkcs8(pkcs8Bytes, keyType)
      val keyPair = KeyPair(certificate.publicKey, privateKey)
      return Pair(keyPair, certificate)
    }
    pkcs1Base64 != null -> {
      require(certificate.publicKey is RSAPublicKey) { "unexpected key type: ${certificate.publicKey}" }

      val pkcs1Bytes = pkcs1Base64.decodeBase64()
          ?: throw IllegalArgumentException("failed to decode private key")
      val privateKey = decodePkcs1(pkcs1Bytes)
      val keyPair = KeyPair(certificate.publicKey, privateKey)
      return Pair(keyPair, certificate)
    }
    else -> {
      throw IllegalArgumentException("string does not include a private key")
    }
  }
}

internal actual fun decodePkcs8(data: ByteString, keyAlgorithm: String): PrivateKey {
  try {
    val keyFactory = KeyFactory.getInstance(keyAlgorithm)
    val x = CertificateAdapters.privateKeyInfo.fromDer(data)
    return keyFactory.generatePrivate(PKCS8EncodedKeySpec(data.toByteArray()))
  } catch (e: GeneralSecurityException) {
    throw IllegalArgumentException("failed to decode private key", e)
  }
}

internal actual fun decodePkcs1(data: ByteString): PrivateKey {
  try {
    val privateKeyInfo = PrivateKeyInfo(0L, AlgorithmIdentifier("1.2.840.113549.1.1.1", null), data)
    val pkcs8data = CertificateAdapters.privateKeyInfo.toDer(privateKeyInfo)
    return decodePkcs8(pkcs8data, "RSA")
  } catch (e: GeneralSecurityException) {
    throw IllegalArgumentException("failed to decode private key", e)
  }
}
