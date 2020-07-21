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
import app.cash.certifikit.cli.errors.CertificationException
import app.cash.certifikit.cli.errors.UsageException
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.security.cert.X509Certificate
import java.util.Properties
import java.util.concurrent.Callable
import kotlin.system.exitProcess
import okio.ByteString.Companion.decodeBase64
import okio.ByteString.Companion.toByteString
import picocli.CommandLine
import picocli.CommandLine.Command
import picocli.CommandLine.Help.Ansi
import picocli.CommandLine.IVersionProvider
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters

@Command(
    name = NAME, description = ["An ergonomic CLI for understanding certificates."],
    mixinStandardHelpOptions = true, versionProvider = VersionProvider::class
)
class Main : Callable<Int> {
  @Option(names = ["--host"], description = ["From HTTPS Handshake"])
  var host: String? = null

  @Option(names = ["--verbose"], description = ["Verbose Output"])
  var verbose: Boolean = false

  @Option(names = ["--insecure"], description = ["Insecure HTTPS"])
  var insecure: Boolean = false

  @Option(names = ["--redirect"], description = ["Follow redirect"])
  var followRedirect: Boolean = false

  @Option(names = ["--output"], description = ["Output file or directory"])
  var output: File? = null

  @Parameters(paramLabel = "file", description = ["Input File"], arity = "0..1")
  var file: String? = null

  override fun call(): Int = try {
    if (host != null) {
      queryHost()
    } else if (file != null) {
      showPemFile()
    }
    0
  } catch (ce: CertificationException) {
    System.err.println("Error: ${Ansi.AUTO.string(" @|yellow ${ce.message}|@")}")
    if (verbose) {
      ce.cause?.printStackTrace()
    }
    -2
  } catch (ue: UsageException) {
    System.err.println("Error: ${Ansi.AUTO.string(" @|red ${ue.message}|@")}")
    if (verbose) {
      ue.cause?.printStackTrace()
    }
    -1
  }

  private fun showPemFile() {
    val certificate = parsePemCertificate(File(file!!))
    println(certificate.prettyPrintCertificate())
  }

  private fun queryHost() {
    val x509certificates = fromHttps(host!!)
    prettyPrintChain(x509certificates)

    if (output != null) {
      try {
        outputCertificates(output!!, x509certificates)
      } catch (ioe: IOException) {
        throw UsageException("Unable to write to $output", ioe)
      }
    }
  }

  private fun outputCertificates(
    output: File,
    certificates: List<X509Certificate>
  ) {
    when {
      output.isDirectory -> certificates.forEach {
        outputCertificate(File(output, "${it.sha256Hash().hex()}.pem"), it)
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

  private fun prettyPrintChain(certificates: List<X509Certificate>) {
    certificates.forEachIndexed { i, certificate ->
      if (i > 0) {
        println()
      }

      val sha256 = certificate.sha256Hash()
      val certifikit = CertificateAdapters.certificate.fromDer(certificate.encoded.toByteString())

      println(certifikit.prettyPrintCertificate(sha256))
    }
  }

  private fun parsePemCertificate(file: File): Certificate {
    try {
      val data = file.readText()
          .replace("-----BEGIN CERTIFICATE-----\n", "")
          .replace("-----END CERTIFICATE-----\n", "")
          .decodeBase64()!!
      val certificate = CertificateAdapters.certificate.fromDer(data)
      return certificate
    } catch (fnfe: FileNotFoundException) {
      throw UsageException("No such file: $file", fnfe)
    }
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
