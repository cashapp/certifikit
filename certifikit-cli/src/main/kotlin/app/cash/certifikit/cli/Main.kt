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
import java.util.Properties
import kotlin.system.exitProcess
import okhttp3.OkHttpClient
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

  @Parameters(paramLabel = "file", description = ["Input File"], arity = "0..1")
  var file: String? = null

  override fun run() {
    if (host != null) {
      val certificates = fromHttps("https://$host/")
      prettyPrintChain(certificates)
    } else if (file != null) {
      val certificate = parsePemCertificate(File(file!!))
      prettyPrintCertificate(certificate)
    }
  }

  private fun prettyPrintChain(certificates: List<Certificate>) {
    for (certificate in certificates) {
      prettyPrintCertificate(certificate)
      println()
    }
  }

  private fun fromHttps(url: String): List<Certificate> {
    val client = OkHttpClient()

    val call = client.newCall(
        Request.Builder()
            .url(url)
            .build()
    )

    return call.execute()
        .use {
          it.handshake!!.peerCertificates
        }
        .map {
          CertificateAdapters.certificate.fromDer(it.encoded.toByteString())
        }
  }

  private fun prettyPrintCertificate(certificate: Certificate) {
    println(certificate.commonName)
    // Needs nullability
//        println("SAN:" + certificate.subjectAlternativeNames)
    println(certificate.tbsCertificate.serialNumber)
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
          .use {
            prop.load(it)
          }
      return prop.getProperty("version", "dev")
    }
  }
}
