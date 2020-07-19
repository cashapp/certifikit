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

import app.cash.certifikit.Certificate
import app.cash.certifikit.CertificateAdapters
import app.cash.certifikit.cli.Main.Companion.NAME
import app.cash.certifikit.cli.Main.VersionProvider
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.security.cert.X509Certificate
import java.util.Properties
import kotlin.system.exitProcess
import okhttp3.Call
import okhttp3.EventListener
import okhttp3.Handshake
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okio.ByteString.Companion.decodeBase64
import okio.ByteString.Companion.toByteString
import picocli.CommandLine
import picocli.CommandLine.Command
import picocli.CommandLine.IVersionProvider
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters

@Command(
    name = NAME, description = ["An ergonomic CLI for understanding certificates."],
    mixinStandardHelpOptions = true, versionProvider = VersionProvider::class
)
class Main : Runnable {
  @Option(names = ["--host"], description = ["From HTTPS Handshake"])
  var host: String? = null

  @Option(names = ["--verbose"], description = ["Verbose Output"])
  var verbose: Boolean = false

  @Option(names = ["--insecure"], description = ["Insecure HTTPS"])
  var insecure: Boolean = false

  @Option(names = ["--no-redirect"], description = ["Avoid redirect"])
  var avoidRedirect: Boolean = false

  @Option(names = ["--output"], description = ["Output file or directory"])
  var output: File? = null

  @Parameters(paramLabel = "file", description = ["Input File"], arity = "0..1")
  var file: String? = null

  override fun run() {
    if (host != null) {
      queryHost()
    } else if (file != null) {
      showPemFile()
    }
  }

  private fun showPemFile() {
    val certificate = parsePemCertificate(File(file!!))
    println(certificate.prettyPrintCertificate())
  }

  private fun queryHost() {
    val x509certificates = fromHttps("https://$host/")
    val certificates = x509certificates
        .map {
          CertificateAdapters.certificate.fromDer(it.encoded.toByteString())
        }
    prettyPrintChain(certificates)

    if (output != null) {
      outputCertificates(output!!, x509certificates)
    }
  }

  private fun outputCertificates(
    output: File,
    certificates: List<X509Certificate>
  ) {
    when {
      output.isDirectory -> certificates.forEach {
        val serialNumber = it.serialNumber.toString(16)
        outputCertificate(File(output, "$serialNumber.pem"), it)
      }
      else -> outputCertificate(output, certificates.first())
    }
  }

  private fun outputCertificate(
    output: File,
    certificate: X509Certificate
  ) {
    output.writeText(certificate.certificatePem())
  }

  private fun prettyPrintChain(certificates: List<Certificate>) {
    certificates.forEachIndexed { i, certificate ->
      if (i > 0) {
        println()
      }

      println(certificate.prettyPrintCertificate())
    }
  }

  private fun fromHttps(url: String): List<X509Certificate> {
    val client = OkHttpClient.Builder()
        .followRedirects(!avoidRedirect)
        .eventListener(object : EventListener() {
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
              println("Connected: \t $inetSocketAddress")
              println()
            }
          }

          override fun secureConnectEnd(
            call: Call,
            handshake: Handshake?
          ) {
            if (verbose && handshake != null) {
              println("Cipher: \t${handshake.cipherSuite}")
              println("TLS: \t${handshake.tlsVersion}")
            }
          }
        })
        .build()

    val call = client.newCall(
        Request.Builder()
            .url(url)
            .build()
    )

    return call.execute()
        .use {
          it.handshake!!.peerCertificates
        }
        .map { it as X509Certificate }
  }

  private fun parsePemCertificate(file: File): Certificate {
    val data = file.readText()
        .replace("-----BEGIN CERTIFICATE-----\n", "")
        .replace("-----END CERTIFICATE-----\n", "")
        .decodeBase64()!!
    val certificate = CertificateAdapters.certificate.fromDer(data)
    return certificate
  }

  class VersionProvider : IVersionProvider {
    override fun getVersion(): Array<String> {
      return arrayOf("$NAME ${versionString()}")
    }
  }

  companion object {
    internal const val NAME = "cft"

    @JvmStatic
    fun main(args: Array<String>) {
      exitProcess(CommandLine(Main()).execute(*args))
    }

    private fun versionString(): String? {
      val prop = Properties()
      Main::class.java.getResourceAsStream("/certifikit-version.properties")
          ?.use {
            prop.load(it)
          }
      return prop.getProperty("version", "dev")
    }
  }
}
