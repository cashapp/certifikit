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

package app.cash.certifikit.text

import app.cash.certifikit.KeyPair
import app.cash.certifikit.PrivateKey
import app.cash.certifikit.X509Certificate
import okio.ByteString

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
expect fun String.decodeCertificatePem(): X509Certificate

/**
 * Returns the certificate encoded in [PEM format][rfc_7468].
 *
 * [rfc_7468]: https://tools.ietf.org/html/rfc7468
 */
expect fun X509Certificate.certificatePem(): String

/**
 * Returns the RSA private key encoded in [PKCS #8][rfc_5208] [PEM format][rfc_7468].
 *
 * [rfc_5208]: https://tools.ietf.org/html/rfc5208
 * [rfc_7468]: https://tools.ietf.org/html/rfc7468
 */
expect fun PrivateKey.privateKeyPkcs8Pem(): String

/**
 * Returns the RSA private key encoded in [PKCS #1][rfc_8017] [PEM format][rfc_7468].
 *
 * [rfc_8017]: https://tools.ietf.org/html/rfc8017
 * [rfc_7468]: https://tools.ietf.org/html/rfc7468
 */
expect fun PrivateKey.privateKeyPkcs1Pem(): String

internal expect fun PrivateKey.pkcs1Bytes(): ByteString

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
expect fun decode(certificateAndPrivateKeyPem: String): Pair<KeyPair, X509Certificate>

internal expect fun decodePkcs8(data: ByteString, keyAlgorithm: String): PrivateKey

internal expect fun decodePkcs1(data: ByteString): PrivateKey

internal val PEM_REGEX = Regex("""-----BEGIN ([!-,.-~ ]*)-----([^-]*)-----END \1-----""")

internal fun StringBuilder.encodeBase64Lines(data: ByteString) {
  val base64 = data.base64()
  for (i in base64.indices step 64) {
    append(base64, i, minOf(i + 64, base64.length)).append('\n')
  }
}
