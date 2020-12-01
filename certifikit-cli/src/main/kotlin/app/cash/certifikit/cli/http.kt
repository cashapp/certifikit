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
package app.cash.certifikit.cli

import app.cash.certifikit.Certifikit
import app.cash.certifikit.cli.errors.ClientException
import app.cash.certifikit.cli.errors.UsageException
import app.cash.certifikit.cli.errors.classify
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.security.cert.X509Certificate
import javax.net.ssl.X509TrustManager
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import okhttp3.Call
import okhttp3.Callback
import okhttp3.CipherSuite
import okhttp3.ConnectionSpec.Companion.MODERN_TLS
import okhttp3.ConnectionSpec.Companion.RESTRICTED_TLS
import okhttp3.Dns
import okhttp3.EventListener
import okhttp3.Handshake
import okhttp3.Headers
import okhttp3.OkHttp
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody
import okhttp3.TlsVersion
import okhttp3.TlsVersion.TLS_1_1
import okhttp3.TlsVersion.TLS_1_2
import okhttp3.TlsVersion.TLS_1_3
import okhttp3.tls.HandshakeCertificates
import picocli.CommandLine.Help.Ansi

enum class Strength(val color: String) {
  Good("green"),
  Weak("yellow"),
  Bad("red")
}

private val TlsVersion.strength: Strength
  get() {
    return when (this) {
      TLS_1_3 -> Strength.Good
      TLS_1_2 -> Strength.Good
      TLS_1_1 -> Strength.Weak
      else -> Strength.Bad
    }
  }

private val CipherSuite.strength: Strength
  get() {
    return when {
      RESTRICTED_TLS.cipherSuites!!.contains(this) -> Strength.Good
      MODERN_TLS.cipherSuites!!.contains(this) -> Strength.Weak
      else -> Strength.Bad
    }
  }

const val userAgent = "Certifikit/${Certifikit.VERSION} OkHttp/${OkHttp.VERSION}"

data class SiteResponse(val peerCertificates: List<X509Certificate>, val headers: Headers) {
  val strictTransportSecurity: String?
    get() = headers["strict-transport-security"]
}

suspend fun Main.fromHttps(host: String, inetAddress: InetAddress? = null): SiteResponse {
  val response = try {
    val client = if (inetAddress != null) {
      client.newBuilder().dns(FixedDns(client.dns, host, inetAddress)).build()
    } else {
      client
    }
    client.newCall(
        Request.Builder()
            .url("https://$host/")
            .header("User-Agent", userAgent)
            .head()
            .build())
        .await()
  } catch (ioe: IOException) {
    throw this.classify(ioe)
  }

  return response.use {
    val peerCertificates = response.handshake!!.peerCertificates.map { it as X509Certificate }
    SiteResponse(peerCertificates = peerCertificates, headers = response.headers)
  }
}

class FixedDns(
  private val delegate: Dns,
  private val host: String,
  private val inetAddress: InetAddress
) : Dns {
  override fun lookup(hostname: String): List<InetAddress> {
    return if (hostname == host) {
      listOf(inetAddress)
    } else {
      delegate.lookup(hostname)
    }
  }
}

fun HandshakeCertificates.Builder.addTrustedCertificates(
  trustManager: X509TrustManager
): HandshakeCertificates.Builder {
  return apply {
    for (issuer in trustManager.acceptedIssuers) {
      addTrustedCertificate(issuer)
    }
  }
}

class VerboseEventListener(private val verbose: Boolean) : EventListener() {
  override fun dnsEnd(
    call: Call,
    domainName: String,
    inetAddressList: List<InetAddress>
  ) {
    if (verbose) {
      println("DNS: \t" + inetAddressList.joinToString(", "))
    }
  }

  override fun connectEnd(
    call: Call,
    inetSocketAddress: InetSocketAddress,
    proxy: Proxy,
    protocol: Protocol?
  ) {
    if (verbose) {
      println("addr: \t$inetSocketAddress")
      println()
    }
  }

  override fun secureConnectEnd(
    call: Call,
    handshake: Handshake?
  ) {
    if (handshake != null) {
      val out = if (verbose) System.out else System.err

      val cipherStrength = handshake.cipherSuite.strength
      if (verbose || cipherStrength != Strength.Good) {
        out.print("Cipher:\t${handshake.cipherSuite}")
        if (cipherStrength != Strength.Good) {
          out.print(" ${Ansi.AUTO.string(" @|${cipherStrength.color} ($cipherStrength)|@")}")
        }
        out.println()
      }

      val tlsStrength = handshake.tlsVersion.strength
      if (verbose || tlsStrength != Strength.Good) {
        out.print("TLS: \t${handshake.tlsVersion}")
        if (tlsStrength != Strength.Good) {
          out.print(" ${Ansi.AUTO.string(" @|${tlsStrength.color} ($tlsStrength)|@")}")
        }
        out.println()
      }
    }
  }
}

@OptIn(ExperimentalCoroutinesApi::class)
suspend fun Call.await(): Response {
  return suspendCancellableCoroutine { cont ->
    cont.invokeOnCancellation {
      cancel()
    }
    enqueue(object : Callback {
      override fun onFailure(call: Call, e: IOException) {
        if (!cont.isCompleted) {
          cont.resumeWithException(e)
        }
      }

      override fun onResponse(call: Call, response: Response) {
        if (!cont.isCompleted) {
          cont.resume(response, onCancellation = { response.close() })
        }
      }
    })
  }
}

suspend fun ResponseBody.readString() = withContext(Dispatchers.IO) { string() }

suspend fun OkHttpClient.execute(request: Request): Response {
  val call = this.newCall(request)

  val response = call.await()

  if (!response.isSuccessful) {
    val msg: String = response.message
    response.close()

    throw ClientException(msg, response.code)
  }

  return response
}

fun String.request(): Request = Request.Builder().url(this).build()

@Suppress("BlockingMethodInNonBlockingContext")
suspend fun Response.bodyString(): String {
  return withContext(Dispatchers.IO) {
    body?.string() ?: throw UsageException("No response body")
  }
}

fun Response.statusMessage(): String = this.code.toString() + " " + this.message
