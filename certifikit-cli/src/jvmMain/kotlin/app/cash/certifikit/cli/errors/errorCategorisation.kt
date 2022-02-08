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
package app.cash.certifikit.cli.errors

import app.cash.certifikit.cli.Main
import java.io.IOException
import java.net.ConnectException
import java.security.InvalidAlgorithmParameterException
import java.security.cert.CertificateExpiredException
import javax.net.ssl.SSLHandshakeException

fun Exception.findMatchingCause(matcher: (Throwable) -> Boolean): Throwable? =
  generateSequence<Throwable>(this) { it.cause }.find { matcher(it) }

fun Main.classify(
  e: IOException
): IOException {
  return when {
    // java.security.cert.CertificateExpiredException: NotAfter: Mon Apr 13 00:59:59 BST 2015
    e.findMatchingCause { it is CertificateExpiredException } != null -> CertificationException(
      "Certificate for $host is expired", e
    )
    // javax.net.ssl.SSLHandshakeException: PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target
    e.findMatchingCause { it.javaClass.simpleName == "SunCertPathBuilderException" } != null -> CertificationException(
      "Certificate for $host is untrusted", e
    )
    // SSLPeerUnverifiedException: Hostname wrong.host.badssl.com not verified:
    e is javax.net.ssl.SSLPeerUnverifiedException -> CertificationException(e.message!!, e)
    // java.net.UnknownHostException: x.google.com: nodename nor servname provided, or not known
    e is java.net.UnknownHostException -> CertificationException("DNS Lookup Failed: $host", e)
    // java.net.SocketTimeoutException: Connect timed out
    e is java.net.SocketTimeoutException -> CertificationException(
      "No response from server: $host", e
    )
    // javax.net.ssl.SSLException: java.lang.RuntimeException: Unexpected error: java.security.InvalidAlgorithmParameterException: the trustAnchors parameter must be non-empty
    e.findMatchingCause { it is InvalidAlgorithmParameterException } != null ->
      CertificationException("No trusted CA certificates in keystore", e)
    // javax.net.ssl.SSLHandshakeException: Received fatal alert: handshake_failure
    e is SSLHandshakeException -> CertificationException(
      "SSL Handshake Failure: ${e.message} ${if (insecure) "" else ", try with --insecure"}", e
    )
    // java.net.ConnectException: Failed to connect to localhost/[0:0:0:0:0:0:0:1]:443
    e is ConnectException -> CertificationException(e.message ?: "Unable to connect to host", e)
    else -> e
  }
}
